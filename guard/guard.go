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
	"errors"
	"fmt"
	"regexp"
	"strings"
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
	// skillProbe resolves a skill's 正文 (Instructions) by name, so the guard can
	// apply user-configured deny rules to skill CONTENT — not just the tool call
	// shell. skill content enters the agent context when a skill is invoked, and
	// is otherwise invisible to the tool-call boundary (供应链安全审计 §2.1:
	// 恶意 skill 正文 = 提示注入面，位于 tool-call 防线盲区)。nil = no probe.
	skillProbe func(name string) (content string, ok bool)
	// budget is the task's 动作分级爆炸半径预算(§5.4). When set, every tool call
	// is classified to A0-A4 and spends the corresponding tier's allowance; A4 is
	// always forbidden and exhausted tiers stop. nil = 分级门禁未启用(兼容旧行为).
	budget *ActionBudget
	// loop is the 动作指纹死循环检测器(§7.2). When set, high-tier (A2+) calls
	// with a repeated fingerprint within the window trip the detector and are
	// blocked to prevent runaway retry loops. nil = 循环检测未启用.
	loop *LoopDetector
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

// SetSkillProbe installs a resolver that returns a skill's 正文 (Instructions) by
// name. When set, skill invocations additionally have their content evaluated
// against user-configured deny rules (see checkSkillContent).
func (g *Guard) SetSkillProbe(fn func(name string) (string, bool)) { g.skillProbe = fn }

// SetActionBudget installs the task's 动作分级爆炸半径预算(§5.4). nil disables
// the tier gate (legacy behavior).
func (g *Guard) SetActionBudget(b *ActionBudget) { g.budget = b }

// SetLoopDetector installs the task's 动作指纹死循环检测器(§7.2). nil disables.
func (g *Guard) SetLoopDetector(d *LoopDetector) { g.loop = d }

// isSkillTool reports whether the hook event is a skill invocation. The skill
// meta-tool is named "Skill" (norma), matched case-insensitively so a deny rule
// scoped to "skill" also applies.
func isSkillTool(name string) bool {
	return strings.EqualFold(name, "Skill")
}

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

	// --- 0. skill 正文拦截：恶意 skill 的正文=提示注入面，tool-call 边界看不到。
	// skill 被 invoke 时其 Instructions 进入 agent 上下文；这里用用户配置的 deny
	// 规则对正文跑一遍（Match 以 "Skill" 作 tool name，正文作 input），命中即硬拦。
	// 预检 ①（skillguard.LoadDir 黑名单）拦固定高危模式；本层让操作者可把任意
	// deny 规则（含 tool_input 正则）套到 skill 正文上。优先级最高：正文有毒就不该进上下文。
	if g.skillProbe != nil && g.interceptor != nil && isSkillTool(ev.ToolName) {
		if res, handled := g.checkSkillContent(ctx, ev); handled {
			return res
		}
	}

	// --- 0.5 动作分级门禁（§5/§7.2）：爆炸半径预算 + 死循环检测。 ---
	// 独立安全层：不论 Fence 是否激活，高危动作都受额度与循环门禁约束。
	if res, handled := g.tierGate(ev); handled {
		return res
	}

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
				res := g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
				g.maybeStopWorker(ctx, dec)
				return res
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
			res := g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
			g.maybeStopWorker(ctx, dec)
			return res
		}
		return g.askWithDecision(ctx, ev, intercept.Decision{
			Action:   "ask",
			RuleName: "任务禁止类操作约束",
			Message:  "本任务声明了禁止类操作约束，请人工确认本次调用是否越过约束边界",
		})
	}
	return g.ruleTail(ctx, ev)
}

// tierGate 是动作分级门禁(§5/§7.2)入口：把一个工具调用按 ActionTier 分类,
// 依次做死循环检测(仅 A2+ 高危动作)与爆炸半径预算扣减。返回 (result, true)
// 表示该调用被分级门禁拒绝(预算耗尽 / A4 禁止 / 循环熔断);(zero, false) 表示
// 放行、继续走 Fence/ruleTail 判定。nil budget 且 nil loop 时不启用(兼容旧行为)。
func (g *Guard) tierGate(ev hook.Event) (hook.Result, bool) {
	if g.budget == nil && g.loop == nil {
		return hook.Result{}, false
	}
	tier := ClassifyAction(ev.ToolName, ev.Input)
	// 死循环检测：仅对 A2+ 高危动作启用。重复只读探测(A0/A1，如多次 curl 同一
	// 指纹)是正常行为，不判循环；只有"卡住后反复执行同一高危动作"才熔断(§7.2)。
	if g.loop != nil && tier >= TierA2 {
		if fp := ActionFingerprint(ev.ToolName, ev.Input); fp != "" {
			if _, tripped := g.loop.Record(fp); tripped {
				return g.block(ev.ToolName,
					systemBlockMessage("检测到动作循环：相同目标+动作类型+关键参数在窗口内多次重复，平台已熔断以防失控（§7.2）"),
					""), true
			}
		}
	}
	// 爆炸半径预算：A4 恒拒，A3/A2 额度耗尽即停(§5.4)。
	if g.budget != nil {
		if err := g.budget.Spend(tier); err != nil {
			return g.block(ev.ToolName, systemBlockMessage(tierDenyMessage(tier, err)), ""), true
		}
	}
	return hook.Result{}, false
}

// tierDenyMessage 把一次分级拒绝包装成平台可读的原因文案。
func tierDenyMessage(tier ActionTier, err error) string {
	if errors.Is(err, ErrTierForbidden) {
		return "命中动作禁止等级 A4（不可逆破坏/批量外传/影响第三方），平台硬阻断"
	}
	return fmt.Sprintf("动作分级预算耗尽（%s），额度用尽即停，不因重试追加（§5.4）", tier)
}

// checkSkillContent evaluates a skill invocation's 正文 against user-configured
// deny rules. Returns (result, true) when the content is denied — the skill
// invocation is blocked so its instructions never reach the agent context.
// (result, false) means the content is clean (or unresolved) and the normal
// tool-call boundary continues.
func (g *Guard) checkSkillContent(ctx context.Context, ev hook.Event) (hook.Result, bool) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(ev.Input, &in); err != nil || strings.TrimSpace(in.Name) == "" {
		return hook.Result{}, false
	}
	content, ok := g.skillProbe(strings.TrimSpace(in.Name))
	if !ok || content == "" {
		return hook.Result{}, false
	}
	// 用 "Skill" 作 tool name：deny 规则若按 tool_name 限定到 skill 也命中；
	// tool_input 规则则直接匹配正文（ruleMatches 对 tool_input 先匹配原始串）。
	dec, matched := g.interceptor.Match("Skill", []byte(content))
	if !matched || dec.Action != "deny" {
		return hook.Result{}, false
	}
	convID := intercept.ConvIDFromContext(ctx)
	g.interceptor.Log(ctx, convID, dec, "Skill", []byte(content), "denied")
	msg := systemBlockMessage("skill 正文命中拦截规则 [" + dec.RuleName + "]：" + dec.Message)
	res := g.block("Skill", msg, "")
	g.maybeStopWorker(ctx, dec)
	return res, true
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
		res := g.block(ev.ToolName, systemBlockMessage(dec.Message), "")
		g.maybeStopWorker(ctx, dec)
		return res
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

// maybeStopWorker implements the DENY 熔断(§3): when a deny decision carries
// StopWorker, it cancels the current Worker intent via the per-work stop callback
// injected by the engine (intercept.WithWorkCancel). The callback is a no-arg
// closure that cancels the work context with agent.AbortWorkStopWorker — so the
// guard package never imports agent (no cycle) and never touches a shared cancel
// handle. Safe when no callback is wired (chat/tests): it is a no-op.
func (g *Guard) maybeStopWorker(ctx context.Context, dec intercept.Decision) {
	if !dec.StopWorker {
		return
	}
	if stop := intercept.WorkCancelFromContext(ctx); stop != nil {
		stop()
	}
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
