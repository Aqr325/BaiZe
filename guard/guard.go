// Package guard implements the safety boundary layer (docs §11): an audit log,
// user-configured intercept-rule evaluation, and Observer/G5 failure attribution.
// Every tool call passes through the PreToolUse hook before executing.
// (The RoE authorization-scope mechanism was removed; a replacement may be added
// later.) Destructive/exfil gating is no longer hard-coded here — it lives in the
// DB intercept rules (seeded as ordinary [内置] rules, so users can disable or
// delete them), evaluated via applyIntercept.
package guard

import (
	"context"
	"encoding/json"
	"regexp"
	"sync"
	"time"

	"github.com/Autumn-27/baize/intercept"
	"github.com/Autumn-27/norma/hook"
)

// AuditEntry records one gated tool call.
type AuditEntry struct {
	TS      int64  `json:"ts"`
	Tool    string `json:"tool"`
	Action  string `json:"action"` // allow|block
	Reason  string `json:"reason,omitempty"`
	Command string `json:"command,omitempty"`
}

// Guard enforces the side-effect policy via agent-core hooks.
type Guard struct {
	mu          sync.Mutex
	audit       []AuditEntry
	attrib      map[string]int // failure attribution counts (Observer / G5)
	reg         *hook.Registry
	interceptor *intercept.Interceptor // optional; nil disables user-configured rules
	// hasDenyConstraint reports whether this task has any deny-class operation
	// constraint. When set and true, every tool call is escalated to human
	// approval so a natural-language "forbidden operation" boundary is enforced
	// by the host instead of relying solely on the model obeying its prompt.
	// Optional: nil keeps the previous rule-only behavior (chat, tests).
	hasDenyConstraint func() bool
	// fence is the optional 允许清单+越界授权 hard boundary. When active (has ≥1
	// structured allow rule), it takes precedence over the legacy deny-escalation:
	// in-scope calls run automatically, out-of-bounds calls require 越界授权,
	// forbidden calls are blocked. nil = no fence (legacy behavior).
	fence *Fence
	// fenceLoader rebuilds the fence from live constraints on each call (runtime
	// edits take effect immediately, matching the deny check's live semantics).
	// Preferred over a static `fence` when set. nil = no live fence.
	fenceLoader func() *Fence
}

// SetDenyConstraintCheck installs a live check for this task's deny constraints.
// It is a callback (not a cached snapshot) because constraints are editable at
// runtime; each tool call re-reads the current answer.
func (g *Guard) SetDenyConstraintCheck(fn func() bool) { g.hasDenyConstraint = fn }

// SetFence installs the task's 允许清单+越界授权 boundary. nil disables the fence.
func (g *Guard) SetFence(f *Fence) { g.fence = f }

// SetFenceLoader installs a live fence builder, re-read from DB each tool call so
// runtime constraint edits take effect immediately. Overrides a static SetFence.
func (g *Guard) SetFenceLoader(fn func() *Fence) { g.fenceLoader = fn }

// New creates a Guard without user-configured intercept rules (used for pentest
// tasks where the Interceptor is not yet available).
func New() *Guard { return newGuard(nil) }

// NewWithInterceptor creates a Guard with user-configured intercept rules.
func NewWithInterceptor(ic *intercept.Interceptor) *Guard { return newGuard(ic) }

func newGuard(ic *intercept.Interceptor) *Guard {
	g := &Guard{attrib: map[string]int{}, interceptor: ic}
	g.reg = hook.NewRegistry().
		On(hook.PreToolUse, g.preToolUse).
		On(hook.PostToolUse, g.postToolUse)
	return g
}

// Hooks returns the hook registry to attach to an agent session.
func (g *Guard) Hooks() *hook.Registry { return g.reg }

func (g *Guard) preToolUse(ctx context.Context, ev hook.Event) hook.Result {
	// Extract the shell-command surface for the audit log: Bash + the interactive-shell
	// tools (shell_open's command, shell_send's text). Destructive/exfil gating is no
	// longer hard-coded here — it now lives in the DB intercept rules, evaluated by
	// applyIntercept below. Other tools record an empty command.
	var cmd string
	switch ev.ToolName {
	case "Bash", "shell_open":
		var in struct {
			Command string `json:"command"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Command
	case "shell_send":
		var in struct {
			Text string `json:"text"`
		}
		_ = json.Unmarshal(ev.Input, &in)
		cmd = in.Text
	}
	g.record(ev.ToolName, "allow", "", cmd)
	return g.applyIntercept(ctx, ev)
}

// applyIntercept evaluates the safety boundary against the tool call.
// 优先级（从严到宽）：
//  1. Fence 激活时（任务声明了结构化允许清单）：用户 deny 规则 → Fence 判定
//     （Forbidden=硬拦 / OutOfBounds=越界授权 / InScope=放行）；
//  2. 旧「deny 清单→全量升级人工审批」：无 Fence 时的兼容路径；
//  3. 用户配置的拦截规则 + LLM 裁判兜底（ruleTail）。
func (g *Guard) applyIntercept(ctx context.Context, ev hook.Event) hook.Result {
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	convID := intercept.ConvIDFromContext(ctx)

	// 取当前 Fence：live fenceLoader（每次现读，约束可运行时增删）优先于静态 SetFence。
	fence := g.fence
	if g.fenceLoader != nil {
		fence = g.fenceLoader()
	}

	// --- 1. Fence 激活：任务级硬边界（允许清单+越界授权）。 ---
	if fence != nil && fence.Active() {
		// 用户配置 deny 规则最严先判（与 Fence 禁止清单同级硬约束）。
		if g.interceptor != nil && g.interceptor.IsToolEnabled(ev.ToolName) {
			if dec, matched := g.interceptor.Match(ev.ToolName, ev.Input); matched && dec.Action == "deny" {
				g.interceptor.Log(ctx, convID, dec, ev.ToolName, ev.Input, "denied")
				return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
			}
		}
		switch fence.Classify(ev.ToolName, ev.Input) {
		case VerdictForbidden:
			return g.block(ev.ToolName, systemBlockMessage("命中操作禁止清单（Fence 硬拦截）"), "")
		case VerdictOutOfBounds:
			surface := fence.SurfaceFor(ev.ToolName, ev.Input)
			if fence.IsAuthorized(surface) {
				return hook.Result{} // 已越界授权 → 放行
			}
			if g.interceptor == nil {
				return g.block(ev.ToolName, systemBlockMessage("越界调用但平台无审批链路，按安全默认拦截"), "")
			}
			return g.fenceAsk(ctx, ev, fence, surface)
		case VerdictInScope:
			// 允许清单内 → 落到规则尾部（ask/allow 操作安全规则仍生效）。
		}
		return g.ruleTail(ctx, ev)
	}

	// --- 2. 无 Fence（或未激活）：旧「deny 清单→全量升级人工审批」。 ---
	if g.hasDenyConstraint != nil && g.hasDenyConstraint() && g.interceptor != nil {
		if dec, matched := g.interceptor.Match(ev.ToolName, ev.Input); matched && dec.Action == "deny" {
			g.interceptor.Log(ctx, convID, dec, ev.ToolName, ev.Input, "denied")
			return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
		}
		return g.askWithDecision(ctx, ev, intercept.Decision{
			Action:   "ask",
			RuleName: "任务禁止类操作约束",
			Message:  "本任务声明了禁止类操作约束，请人工确认本次调用是否越过约束边界",
		})
	}
	return g.ruleTail(ctx, ev)
}

// ruleTail 是既有「用户配置拦截规则 + LLM 裁判兜底」路径，与旧逻辑一致。
func (g *Guard) ruleTail(ctx context.Context, ev hook.Event) hook.Result {
	if g.interceptor == nil {
		return hook.Result{}
	}
	if !g.interceptor.IsToolEnabled(ev.ToolName) {
		return hook.Result{}
	}
	ctx = intercept.WithCall(ctx, ev.ToolName, ev.Input)
	convID := intercept.ConvIDFromContext(ctx)
	dec, matched := g.interceptor.Match(ev.ToolName, ev.Input)
	if !matched {
		// No rule matched. Ask the LLM fallback judge (if enabled); when it is off
		// or unwired, keep current behavior and allow.
		d, judged := g.interceptor.Judge(ctx, ev.ToolName, ev.Input)
		if !judged {
			return hook.Result{}
		}
		dec = d
	}
	switch dec.Action {
	case "deny":
		// 观测:deny 命中不阻塞审批,直接记一条 denied（历史/任务拦截页可见）。
		g.interceptor.Log(ctx, convID, dec, ev.ToolName, ev.Input, "denied")
		return g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
	case "allow":
		// Record explicit rule and model approvals so review details remain auditable.
		g.interceptor.Log(ctx, convID, dec, ev.ToolName, ev.Input, "allowed")
		return hook.Result{}
	case "ask":
		return g.askWithDecision(ctx, ev, dec)
	}
	return hook.Result{}
}

// fenceAsk 把一次越界调用转「越界授权」人工审批；授权通过后记录越界授权，
// 相同 surface 的后续调用不再重复询问。
func (g *Guard) fenceAsk(ctx context.Context, ev hook.Event, fence *Fence, surface string) hook.Result {
	if ctx.Err() != nil {
		return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
	}
	convID := intercept.ConvIDFromContext(ctx)
	dec := intercept.Decision{
		Action:   "ask",
		RuleName: "越界授权",
		Message:  "本次调用超出允许清单（越界），需人工越界授权后才可执行",
	}
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("越界授权未通过（用户拒绝或审批超时）"), "")
	}
	// 授权通过 → 记录越界授权（AuthzStore 持久化），相同 surface 不再询问。
	_ = fence.Authorize(surface, ev.ToolName, ev.Input)
	return hook.Result{}
}

// askWithDecision 把一次工具调用转人工审批（复用 HandleAsk 的完整链路）。
func (g *Guard) askWithDecision(ctx context.Context, ev hook.Event, dec intercept.Decision) hook.Result {
	// If the worker context is already cancelled (task stopped / killed), block
	// immediately without creating a pending record — avoids orphaned DB entries
	// and makes execOne complete fast, reducing the race against drainSynthetic.
	if ctx.Err() != nil {
		return g.block(ev.ToolName, systemBlockMessage("工作已取消，平台安全管控阻止执行"), "")
	}
	convID := intercept.ConvIDFromContext(ctx)
	if !g.interceptor.HandleAsk(ctx, convID, dec, ev.ToolName, ev.Input) {
		return g.block(ev.ToolName, systemBlockMessage("人工审批未通过（用户拒绝或审批超时）"), "")
	}
	return hook.Result{}
}

// systemBlockMessage frames an intercept block as a BaiZe platform-governance
// decision so the agent does not mistake it for a target-side defense.
//
// The bare reasons ("禁止执行此工具" / "用户拒绝") read exactly like a WAF/403 on
// the target, so a pentest agent's instinct is to bypass them — rewrite the
// command, swap the payload, re-encode, retry. That is both futile (the platform
// blocks the class of action, not one string) and wrong (it's a policy decision,
// not an obstacle to defeat). This prefix states plainly that the block comes
// from the platform, is not the target's protection, and that the operation is
// forbidden — so the agent pivots to another approach instead of evading it.
// Audit/history rows keep the raw reason (see Interceptor.Log); only the
// model-facing tool_result carries this framing.
func systemBlockMessage(reason string) string {
	return "【BaiZe 平台管控·非目标防御】此调用被平台拦截。" +
		"原因：" + reason + "。此操作被禁止。"
}

var reBlocked = regexp.MustCompile(`(?i)\b(403|forbidden|waf|blocked|rate.?limit|429|captcha|denied)\b`)

// postToolUse is the Observer failure-attribution hook (G5): it classifies tool
// results into blocked / error / ok so the planner can change strategy instead
// of giving up at a WAF.
func (g *Guard) postToolUse(_ context.Context, ev hook.Event) hook.Result {
	if ev.ToolName != "Bash" {
		return hook.Result{}
	}
	class := "ok"
	switch {
	case reBlocked.Match(ev.Result):
		class = "blocked"
	case ev.IsError:
		class = "error"
	}
	g.mu.Lock()
	g.attrib[class]++
	g.mu.Unlock()
	return hook.Result{}
}

// Attributions returns failure-attribution counts (Observer / G5).
func (g *Guard) Attributions() map[string]int {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make(map[string]int, len(g.attrib))
	for k, v := range g.attrib {
		out[k] = v
	}
	return out
}

func (g *Guard) block(tool, reason, cmd string) hook.Result {
	g.record(tool, "block", reason, cmd)
	return hook.Result{Decision: "block", Message: reason}
}

func (g *Guard) record(tool, action, reason, cmd string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.audit = append(g.audit, AuditEntry{TS: time.Now().Unix(), Tool: tool, Action: action, Reason: reason, Command: cmd})
	if len(g.audit) > 2000 {
		g.audit = g.audit[len(g.audit)-2000:]
	}
}

// Audit returns a snapshot of recent gated calls (most recent last).
func (g *Guard) Audit() []AuditEntry {
	g.mu.Lock()
	defer g.mu.Unlock()
	out := make([]AuditEntry, len(g.audit))
	copy(out, g.audit)
	return out
}
