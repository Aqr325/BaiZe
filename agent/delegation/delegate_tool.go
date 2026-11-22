package delegation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	acperm "github.com/Autumn-27/norma/permission"
	actool "github.com/Autumn-27/norma/tool"
)

// DelegateTask is one task in a delegate_task call. It mirrors the
// tasks.items schema hermes builds.
type DelegateTask struct {
	Goal     string         `json:"goal"`
	Context  string         `json:"context,omitempty"`
	Index    int            `json:"index,omitempty"`
	Group    string         `json:"group,omitempty"`
	Role     string         `json:"role,omitempty"`
	Toolsets []string       `json:"toolsets,omitempty"`
	Label    string         `json:"label,omitempty"`
	Params   map[string]any `json:"params,omitempty"`
}

// TaskResult is one child's aggregated outcome within a delegate_task call.
type TaskResult struct {
	Index               int            `json:"index"`
	Group               string         `json:"group,omitempty"`
	SubagentID          string         `json:"subagent_id,omitempty"`
	State               State          `json:"state"`
	Summary             string         `json:"summary,omitempty"`
	ErrorClassification string         `json:"error_classification,omitempty"`
	ErrorMessage        string         `json:"error_message,omitempty"`
	ResultHash          string         `json:"result_hash,omitempty"`
	Label               string         `json:"label,omitempty"`
	UsageMetadata       map[string]any `json:"usage_metadata,omitempty"`
	ToolExecution       map[string]any `json:"tool_execution_summary,omitempty"`
	StructuredPayload   map[string]any `json:"structured_payload,omitempty"`
}

// DelegateResult is the aggregate returned to the model. It summarizes the
// decomposition outcome: how many tasks were launched and how each resolved.
type DelegateResult struct {
	TaskCount   int          `json:"task_count"`
	Succeeded   int          `json:"succeeded"`
	Failed      int          `json:"failed"`
	Interrupted int          `json:"interrupted"`
	Results     []TaskResult `json:"results"`
}

// DelegateToolOptions wires the delegate_task tool to a lifecycle service,
// provider, broker and the parent scope. CheckToolsets, if set, verifies a
// child's requested toolsets are a subset of the parent's enabled set (never
// broaden). ResolveConfig, if set, supplies the live delegation config; else an
// empty config (default backend) is used.
type DelegateToolOptions struct {
	Service         *LifecycleService
	Provider        Provider
	Broker          *Broker
	MaxConcurrency  int
	MaxDepth        int
	ParentSessionID string
	ParentTaskID    int64
	ExecutionID     string
	CheckToolsets   func([]string) error
	ResolveConfig   func() (Config, error)
}

// DefaultMaxConcurrency bounds parallel children when options leave it zero.
const DefaultMaxConcurrency = 4

// NewDelegateTool builds the delegate_task tool. If Service is nil the tool
// reports itself unavailable (the wiring never offers it without a lifecycle).
func NewDelegateTool(o DelegateToolOptions) actool.CoreTool {
	maxConc := o.MaxConcurrency
	if maxConc <= 0 {
		maxConc = DefaultMaxConcurrency
	}
	run := func(ctx context.Context, in json.RawMessage) (actool.Result, error) {
		if o.Service == nil {
			return errTool("delegate_task is unavailable: no subagent lifecycle is configured for this session."), nil
		}
		return runDelegate(ctx, o, in, maxConc)
	}
	return actool.Build(actool.Spec{
		Name:        "delegate_task",
		Description: "Spawn isolated subagents to run parallel workstreams. Decompose a large task into N smaller goals, each executed by its own subagent (a fresh agent turn with its own model route and restricted toolset), then aggregate the results. Use for fan-out/recon-analyze-report splits and independent probes.",
		Prompt:      "Prefer a few focused subagents over one giant turn. Keep each goal self-contained; pass context for background. Never delegate a goal that depends on another task's result unless you pass that result in context.",
		Schema:      delegateTaskSchema(o),
		Permissions: func(context.Context, json.RawMessage, acperm.Context) acperm.Decision { return acperm.Allowed() },
		Run: func(ctx context.Context, in json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
			return run(ctx, in)
		},
	})
}

func delegateTaskSchema(o DelegateToolOptions) map[string]any {
	props := map[string]any{
		"tasks": map[string]any{
			"type": "array",
			"items": map[string]any{
				"type": "object",
				"properties": map[string]any{
					"goal":     strSchema("The concrete goal for this subagent. Self-contained; no cross-task dependency unless passed in context."),
					"context":  strSchema("Optional background context passed to the subagent (up to 32000 chars)."),
					"index":    intSchema("Zero-based index, preserved in results."),
					"group":    strSchema("Optional grouping label."),
					"role":     map[string]any{"type": "string", "enum": []string{"leaf", "orchestrator"}, "description": "leaf = one focused workstream; orchestrator = may itself delegate."},
					"toolsets": map[string]any{"type": "array", "items": map[string]any{"type": "string"}, "description": "Optional toolset restriction, must be a subset of the parent's enabled toolsets."},
					"label":    strSchema("Short label shown with the child's progress and result."),
				},
				"required": []string{"goal"},
			},
		},
	}
	// Merge provider-declared per-task parameters (deterministic for a config).
	cfg := Config{Backend: DefaultBackend}
	if o.ResolveConfig != nil {
		if c, err := o.ResolveConfig(); err == nil {
			cfg = c
		}
	}
	if o.Provider != nil {
		items := props["tasks"].(map[string]any)["items"].(map[string]any)
		p := items["properties"].(map[string]any)
		for name, schema := range o.Provider.TaskParameters(cfg) {
			if ReservedTaskParameters[name] {
				continue // core owns these
			}
			p[name] = schema
		}
		items["properties"] = p
		props["tasks"].(map[string]any)["items"] = items
	}
	return map[string]any{"type": "object", "properties": props, "required": []string{"tasks"}}
}

func strSchema(desc string) map[string]any {
	return map[string]any{"type": "string", "description": desc}
}

func intSchema(desc string) map[string]any {
	return map[string]any{"type": "integer", "description": desc}
}

// errTool builds an error result with a formatted message.
func errTool(format string, args ...any) actool.Result {
	return actool.Errorf(fmt.Sprintf(format, args...))
}

// runDelegate validates, spawns (bounded concurrency), waits and aggregates.
func runDelegate(ctx context.Context, o DelegateToolOptions, in json.RawMessage, maxConc int) (actool.Result, error) {
	var input struct {
		Tasks []DelegateTask `json:"tasks"`
	}
	if err := json.Unmarshal(in, &input); err != nil {
		return errTool("delegate_task: invalid arguments: %v", err), nil
	}
	if len(input.Tasks) == 0 {
		return errTool("delegate_task: tasks must be a non-empty array."), nil
	}
	for i := range input.Tasks {
		t := &input.Tasks[i]
		if strings.TrimSpace(t.Goal) == "" || len(t.Goal) > MaxGoalChars {
			return errTool("delegate_task: task %d goal must be a non-empty string of at most %d characters.", i, MaxGoalChars), nil
		}
		if len(t.Context) > MaxContextChars {
			return errTool("delegate_task: task %d context must be at most %d characters.", i, MaxContextChars), nil
		}
		if t.Role != "" && t.Role != "leaf" && t.Role != "orchestrator" {
			return errTool("delegate_task: task %d role must be 'leaf' or 'orchestrator'.", i), nil
		}
		if len(t.Toolsets) > 0 && o.CheckToolsets != nil {
			if err := o.CheckToolsets(t.Toolsets); err != nil {
				return errTool("delegate_task: task %d: %v", i, err), nil
			}
		}
	}
	cfg := Config{Backend: DefaultBackend, MaxConcurrency: maxConc}
	if o.ResolveConfig != nil {
		if c, err := o.ResolveConfig(); err == nil {
			cfg = c
		}
	}
	// Fail-closed: pick the active provider; an unknown/unavailable backend
	// refuses the whole call, never silently reroutes.
	provider := o.Provider
	if provider == nil {
		p, err := ActiveProvider(cfg)
		if err != nil {
			return errTool("delegate_task: %v", err), nil
		}
		provider = p
	}
	type resolvedRoute struct {
		label, role, model, prov string
	}
	// Resolve every route up front (fail-closed): a single refused task fails the call.
	// Before this point no child has been launched, so nothing needs cleanup.
	resolved := make([]resolvedRoute, len(input.Tasks))
	for i := range input.Tasks {
		t := &input.Tasks[i]
		route, err := provider.RouteTask(TaskSpec{
			Goal: t.Goal, Context: t.Context, Index: t.Index,
			Group: t.Group, Role: t.Role, Params: t.Params,
		}, cfg)
		if err != nil {
			return errTool("delegate_task: task %d: %v", i, err), nil
		}
		label := route.Label
		if label == "" {
			label = t.Label
		}
		role := route.Profile
		if role == "" {
			role = t.Role
			if role == "" {
				role = "leaf"
			}
		}
		resolved[i] = resolvedRoute{label: label, role: role, model: route.Model, prov: route.Provider}
	}

	// Launch + Wait in one bounded worker pool: maxConc workers => at most
	// maxConc children are ever in flight. Previously every child was launched
	// synchronously first and the semaphore only guarded Wait, so the limit
	// never actually capped concurrency.
	results := make([]TaskResult, len(input.Tasks))
	handles := make([]Handle, len(input.Tasks))
	jobs := make(chan int)
	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	// 所有子代理共享同一个可取消的父 ctx。Launch 内部对 parent 做 WithCancel，
	// 因此 cancelAll() 会级联取消每一个已启动的子代理——包括"已 Launch 但尚未
	// 写入 handles"的（该窗口内取消循环遍历不到它，若只靠 handles 会漏成孤儿）。
	childCtx, cancelAll := context.WithCancel(ctx)
	defer cancelAll()
	worker := func() {
		defer wg.Done()
		for i := range jobs {
			// fail-fast：任一 Launch 失败后，其他 worker 不得再派生新子代理。
			// 早期实现里失败分支只是 continue，随后又从 jobs 领取任务 Launch，
			// 这些新 child 不在已执行的一次性 cancel 循环内，成为孤儿。
			mu.Lock()
			aborted := firstErr != nil
			mu.Unlock()
			if aborted {
				continue
			}
			t := &input.Tasks[i]
			r := resolved[i]
			h, err := o.Service.Launch(childCtx, &LaunchRequest{
				Goal:            t.Goal,
				Context:         t.Context,
				Role:            r.role,
				Model:           r.model,
				Provider:        r.prov,
				AllowedToolsets: t.Toolsets,
				ParentSessionID: o.ParentSessionID,
				ParentTaskID:    o.ParentTaskID,
				CorrelationID:   fmt.Sprintf("task-%d", i),
				Metadata:        map[string]any{"label": r.label},
			})
			if err != nil {
				mu.Lock()
				if firstErr == nil {
					firstErr = fmt.Errorf("task %d: %w", i, err)
				}
				// 先级联取消所有已启动子代理（含尚未登记进 handles 的），
				// 再遍历 handles 显式 Cancel，双保险覆盖"Launch 中"窗口。
				cancelAll()
				for _, live := range handles {
					if live.SubagentID != "" {
						o.Service.Cancel(live, "sibling launch failed")
					}
				}
				mu.Unlock()
				continue
			}
			// 与失败分支的 cancel 循环共用同一把锁：写在锁外会构成数据竞争，
			// 且 cancel 可能因看不到刚启动的 handle 而漏取消（孤儿子代理）。
			mu.Lock()
			handles[i] = h
			mu.Unlock()
			ts := o.Service.Wait(h, waitTimeoutFor(cfg))
			res := o.Service.Result(h)
			tr := TaskResult{
				Index: t.Index, Group: t.Group,
				SubagentID: h.SubagentID, State: ts.State, Label: r.label,
				Summary: res.Summary, ErrorClassification: res.ErrorClassification,
				ErrorMessage: res.ErrorMessage, ResultHash: res.ResultHash,
				UsageMetadata: res.UsageMetadata, ToolExecution: res.ToolExecutionSummary,
				StructuredPayload: res.StructuredPayload,
			}
			if tr.Index == 0 {
				tr.Index = i
			}
			results[i] = tr
		}
	}
	workers := maxConc
	if workers > len(input.Tasks) {
		workers = len(input.Tasks)
	}
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go worker()
	}
dispatch:
	for i := range input.Tasks {
		// 调用方取消时停止派发：否则 worker 全在 Wait 中，主 goroutine 会卡在
		// 无缓冲 channel 的发送上直到所有任务自然结束，无法及时返回。
		select {
		case jobs <- i:
		case <-ctx.Done():
			cancelAll()
			mu.Lock()
			for _, live := range handles {
				if live.SubagentID != "" {
					o.Service.Cancel(live, "parent context done")
				}
			}
			mu.Unlock()
			break dispatch
		}
	}
	close(jobs)
	wg.Wait()
	if firstErr != nil {
		return errTool("delegate_task: %v", firstErr), nil
	}
	agg := DelegateResult{TaskCount: len(results), Results: results}
	for _, r := range results {
		switch r.State {
		case StateSucceeded:
			agg.Succeeded++
		case StateFailed:
			agg.Failed++
		case StateInterrupted, StateCancelled:
			agg.Interrupted++
		}
	}
	out, _ := json.Marshal(agg)
	return actool.Text(string(out)), nil
}

func waitTimeoutFor(cfg Config) time.Duration {
	if cfg.ChildTimeout() > 0 {
		return time.Duration(cfg.ChildTimeout()) * time.Second
	}
	return 0 // no explicit deadline
}
