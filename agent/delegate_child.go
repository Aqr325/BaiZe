package agent

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/Autumn-27/baize/agent/delegation"
	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/intercept"
	"github.com/Autumn-27/norma/agentcore"
	"github.com/Autumn-27/norma/harness"
	"github.com/Autumn-27/norma/llm"
	"github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// 子代理运行时依赖，由 server 层在启动时 wire 一次。
//   - ChildProviderFor 按 child 路由解析 llm.Provider（模型/后端来自 ChildConfig）。
//   - ChildStore 返回子 turn 可用的领域 store（nil = 不注入领域工具，只跑 SDK 通用工具）。
//   - ChildWorkDir 是 data 根目录，子会话写到 <root>/subagents/<id>/。
//   - ChildProxy 返回 (代理地址, CA 证书)，供 WebFetch/Bash 留痕。
var (
	ChildProviderFor func(cfg delegation.ChildConfig) (llm.Provider, error)
	ChildStore       func() *db.ExplorationStore
	ChildWorkDir     string
	ChildProxy       func() (addr, caCert string)
)

// BuildDelegateTool, if set, returns a delegate_task tool for every agent's
// base tool list. The server wires it to the lifecycle service + provider +
// broker singleton. nil = no delegate_task (feature off).
var BuildDelegateTool func() actool.CoreTool

// AugmentDelegateTool appends the delegate_task tool (when wired) to a base tool
// list. Called from AugmentTools so every agent gets it uniformly.
func AugmentDelegateTool(base []actool.CoreTool) []actool.CoreTool {
	if BuildDelegateTool == nil {
		return base
	}
	return append(base, BuildDelegateTool())
}

// subWorkDirSpec appends a working-directory notice for a subagent session.
func subWorkDirSpec(workDir string) string {
	return "\n\n**子代理工作目录**：写文件一律落到 " + workDir + "（本子代理专属目录），不要写 /tmp 或其他绝对路径。"
}

// RunSubagentTurn is the real TurnFn. It runs ONE agentcore session for a child
// goal with the route-resolved provider and a restricted toolset, publishing
// lifecycle events through emit. It mirrors ChatAgent.Chat's session wiring.
func RunSubagentTurn(ctx context.Context, cfg delegation.ChildConfig, emit delegation.Emit) (delegation.ChildOutcome, error) {
	if ChildProviderFor == nil {
		return delegation.ChildOutcome{Status: "error", Error: "no subagent provider factory wired"}, errors.New("no provider factory")
	}
	prov, err := ChildProviderFor(cfg)
	if err != nil {
		return delegation.ChildOutcome{Status: "error", Error: err.Error()}, err
	}

	// Restricted toolset: domain tools from the allowed toolset names (subset of
	// the parent), always plus the SDK generic tools.
	var domain []actool.CoreTool
	if ChildStore != nil {
		if st := ChildStore(); st != nil {
			ts := NewToolSet(st, "subagent")
			if len(cfg.AllowedToolsets) == 0 {
				domain = ts.AllDomainTools()
			} else {
				for _, name := range cfg.AllowedToolsets {
					switch name {
					case "worker":
						domain = append(domain, ts.WorkerTools()...)
					case "mainagent":
						domain = append(domain, ts.MainAgentTools()...)
					case "planner":
						domain = append(domain, ts.PlannerTools()...)
					case "goals":
						domain = append(domain, ts.setGoals(), ts.setConstraints())
					case "pentest":
						domain = append(domain, ts.listAssets(), ts.insertAssets(), ts.addFinding(), ts.listFindings(), ts.listCompanies())
					}
				}
			}
		}
	}
	base := append(domain, actool.DefaultTools()...)

	subDir := filepath.Join(ChildWorkDir, "subagents", cfg.SubagentID)
	_ = os.MkdirAll(subDir, 0o755)
	ctx = intercept.WithReviewWorkingDirectory(ctx, subDir)
	ctx = WithRunInfo(ctx, RunInfo{SessionID: cfg.SubagentID})

	tools, def, cleanup := AugmentTools(ctx, "subagent", base)
	defer cleanup()

	role := cfg.Role
	if role == "" {
		role = "leaf"
	}
	system, boundary := deferredSystem(
		renderSystem("subagent", DefaultAssistantPrompt, chatVars{DataDir: ChildWorkDir, Now: nowStr()})+
			"\n\n**你的角色**："+role+" 子代理。专注完成给定目标，不要越界做父代理职责；结果要具体、可验证。"+
			subWorkDirSpec(subDir),
		def,
	)
	proxyAddr, caCert := "", ""
	if ChildProxy != nil {
		proxyAddr, caCert = ChildProxy()
	}
	opts := agentcore.Options{
		Provider:        prov,
		SystemPrompt:    system,
		DynamicBoundary: boundary,
		Tools:           tools,
		DeferredTools:   def.Deferred,
		UnlockSet:       def.Unlock,
		PermissionMode:  permission.ModeBypass,
		EnableWebFetch:  true,
		WebFetchProxy:   proxyAddr,
		WebFetchCACert:  caCert,
		BashEnv:         proxyEnv(proxyAddr, caCert),
		WorkingDir:      subDir,
		MaxTurns:        defaultSubagentTurns,
		MaxDuration:     defaultSubagentDuration,
		Compaction:      compactionConfig(0),
		Todos:           actool.NewTodoStore(),
		ToolOutputDir:   filepath.Join(subDir, "cmd-output"),
		Settlement:      wrapupSettlement("subagent", nil),
	}
	ctx = attachSideCapture(ctx, &opts)
	s := newAgentSession(opts)
	defer s.Close()

	text, reason, err := captureRunSession(ctx, s, cfg.Goal, func(r db.Activity) {
		if emit == nil {
			return
		}
		switch r.Kind {
		case "tool_use":
			emit(delegation.EventToolStart, map[string]any{"tool": r.Tool, "tool_use_id": r.ToolUseID})
		case "tool_result":
			emit(delegation.EventToolComplete, map[string]any{"tool": r.Tool, "tool_use_id": r.ToolUseID, "is_error": r.IsError})
		case "text":
			emit(delegation.EventDelta, map[string]any{"text": r.Detail})
		}
	})

	out := delegation.ChildOutcome{
		Status:        "completed",
		Summary:       text,
		UsageMetadata: map[string]any{"api_calls": 1},
	}
	if reason == harness.ReasonAbortedStreaming || reason == harness.ReasonAbortedTools {
		out.Status = "interrupted"
	}
	if err != nil {
		out.Status = "error"
		out.Error = err.Error()
	}
	return out, nil
}

// defaultSubagentTurns bounds each child's agent loop steps.
const defaultSubagentTurns = 12

// defaultSubagentDuration bounds each child's wall-clock run.
var defaultSubagentDuration = 15 * time.Minute
