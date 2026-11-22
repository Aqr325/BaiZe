package delegation

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"
)

// fakeRunner returns a completed outcome.
func fakeRunner() Runner {
	return func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		return ChildOutcome{
			Status:               "completed",
			Summary:              "done:" + cfg.Goal,
			UsageMetadata:        map[string]any{"api_calls": 3},
			ToolExecutionSummary: map[string]any{"duration_seconds": 1},
		}, nil
	}
}

func TestProviderDefaultRouteAndFailClosed(t *testing.T) {
	// Default provider returns the config's default route (empty = inherit).
	p := DefaultProvider{}
	r, err := p.RouteTask(TaskSpec{Goal: "g"}, Config{DefaultRoute: Route{Model: "m", Provider: "p"}})
	if err != nil {
		t.Fatalf("RouteTask err: %v", err)
	}
	if r.Model != "m" || r.Provider != "p" {
		t.Fatalf("route = %+v, want model=m provider=p", r)
	}
	// ActiveProvider on an unknown backend fails closed naming it.
	_, err = ActiveProvider(Config{Backend: "nope"})
	if err == nil {
		t.Fatal("ActiveProvider with unknown backend must fail closed")
	}
	if !strings.Contains(err.Error(), "nope") {
		t.Fatalf("error must name the backend, got: %v", err)
	}
}

func TestProviderRegisterAndBackendStatus(t *testing.T) {
	reg := NewRegistry()
	reg.Register(DefaultProvider{})
	if _, ok := reg.Get("default"); !ok {
		t.Fatal("default provider not registered")
	}
	// Unavailable provider fails closed with reason.
	reg.Register(unavailableProvider{})
	_, reason := BackendStatus("unavail")
	if reason == "" {
		t.Fatal("unavailable provider must produce a reason")
	}
}

type unavailableProvider struct{}

func (unavailableProvider) Name() string                                    { return "unavail" }
func (unavailableProvider) Summary() string                                 { return "" }
func (unavailableProvider) RouteKeys() []string                             { return nil }
func (unavailableProvider) IsAvailable() bool                               { return false }
func (unavailableProvider) TaskParameters(Config) map[string]map[string]any { return nil }
func (unavailableProvider) RouteTask(TaskSpec, Config) (Route, error)       { return Route{}, nil }

func TestLifecycleSucceedAndWait(t *testing.T) {
	svc := NewLifecycleService(fakeRunner(), NewBroker(), func() string { return "sess-1" })
	h, err := svc.Launch(context.Background(), &LaunchRequest{
		Goal: "scan port 443", Role: "leaf", ParentSessionID: "sess-1",
	})
	if err != nil {
		t.Fatalf("Launch err: %v", err)
	}
	if h.ContractVersion != PublicContractVersion || h.SubagentID == "" {
		t.Fatalf("bad handle: %+v", h)
	}
	ts := svc.Wait(h, 5*time.Second)
	if !ts.Completed || ts.State != StateSucceeded {
		t.Fatalf("wait = %+v, want completed/succeeded", ts)
	}
	res := svc.Result(h)
	if !res.Ready || res.TerminalState != StateSucceeded {
		t.Fatalf("result = %+v, want ready/succeeded", res)
	}
	if res.ResultHash == "" {
		t.Fatal("result must carry a hash")
	}
	if res.UsageMetadata["api_calls"] != 3 {
		t.Fatalf("usage not propagated: %+v", res.UsageMetadata)
	}
}

func TestLifecycleCancel(t *testing.T) {
	runner := func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		<-ctx.Done() // blocks until cancelled
		return ChildOutcome{}, ctx.Err()
	}
	svc := NewLifecycleService(runner, NewBroker(), nil)
	h, err := svc.Launch(context.Background(), &LaunchRequest{Goal: "g"})
	if err != nil {
		t.Fatalf("Launch err: %v", err)
	}
	time.Sleep(50 * time.Millisecond)
	cr := svc.Cancel(h, "stop")
	if !cr.Accepted {
		t.Fatalf("cancel not accepted: %+v", cr)
	}
	ts := svc.Wait(h, 3*time.Second)
	if ts.State != StateCancelled {
		t.Fatalf("after cancel state = %s, want cancelled", ts.State)
	}
}

func TestLifecycleValidationAndCapability(t *testing.T) {
	svc := NewLifecycleService(fakeRunner(), NewBroker(), nil)
	// Goal too long.
	_, err := svc.Launch(context.Background(), &LaunchRequest{Goal: strings.Repeat("x", MaxGoalChars+1)})
	if err == nil {
		t.Fatal("oversized goal must be rejected")
	}
	// Bad role.
	_, err = svc.Launch(context.Background(), &LaunchRequest{Goal: "g", Role: "nope"})
	if err == nil {
		t.Fatal("bad role must be rejected")
	}
	// Duplicate correlation in same parent.
	svc2 := NewLifecycleService(fakeRunner(), NewBroker(), func() string { return "s" })
	_, err = svc2.Launch(context.Background(), &LaunchRequest{Goal: "g", CorrelationID: "c1", ParentSessionID: "s"})
	if err != nil {
		t.Fatalf("launch c1 err: %v", err)
	}
	_, err = svc2.Launch(context.Background(), &LaunchRequest{Goal: "g2", CorrelationID: "c1", ParentSessionID: "s"})
	if err == nil {
		t.Fatal("duplicate correlation must be rejected")
	}
	// Forged capability -> UNKNOWN handle.
	h, _ := svc2.Launch(context.Background(), &LaunchRequest{Goal: "g3", ParentSessionID: "s"})
	svc2.Wait(h, 3*time.Second)
	forged := h
	forged.Capability = "deadbeef"
	st := svc2.Status(forged)
	if st.State != StateUnknown {
		t.Fatalf("forged handle must be UNKNOWN, got %s", st.State)
	}
}

func TestDelegateToolAggregate(t *testing.T) {
	broker := NewBroker()
	svc := NewLifecycleService(fakeRunner(), broker, func() string { return "sess" })
	tool := NewDelegateTool(DelegateToolOptions{
		Service: svc, Provider: DefaultProvider{}, Broker: broker,
		MaxConcurrency: 2, ParentSessionID: "sess",
	})
	in := json.RawMessage(`{"tasks":[{"goal":"a","index":0,"role":"leaf"},{"goal":"b","index":1,"role":"leaf"}]}`)
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call err: %v", err)
	}
	if res.IsError {
		t.Fatalf("Call returned error result: %s", res.Content[0].Text)
	}
	var agg DelegateResult
	if err := json.Unmarshal([]byte(res.Content[0].Text), &agg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if agg.TaskCount != 2 || agg.Succeeded != 2 {
		t.Fatalf("agg = %+v, want 2 tasks 2 succeeded", agg)
	}
	for _, r := range agg.Results {
		if r.ResultHash == "" {
			t.Fatal("each task result must carry a hash")
		}
	}
}

func TestDelegateToolValidationAndFailClosed(t *testing.T) {
	svc := NewLifecycleService(fakeRunner(), NewBroker(), nil)
	tool := NewDelegateTool(DelegateToolOptions{Service: svc, Provider: DefaultProvider{}})
	// Empty tasks.
	res, _ := tool.Call(context.Background(), json.RawMessage(`{"tasks":[]}`), nil)
	if !res.IsError {
		t.Fatal("empty tasks must be an error")
	}
	// Bad role.
	res, _ = tool.Call(context.Background(), json.RawMessage(`{"tasks":[{"goal":"g","role":"bad"}]}`), nil)
	if !res.IsError {
		t.Fatal("bad role must be an error")
	}
	// Fail-closed: provider unknown -> whole call refused.
	tool2 := NewDelegateTool(DelegateToolOptions{Service: svc, Provider: DefaultProvider{}})
	res, _ = tool2.Call(context.Background(), json.RawMessage(`{"tasks":[{"goal":"g"}]}`), nil)
	if res.IsError {
		t.Fatal("default provider must succeed")
	}
}

func TestScopeFreezeAndDepth(t *testing.T) {
	parent := &Scope{Depth: 0, ParentSessionID: "root", ParentTaskID: 7}
	cfg := Config{Backend: "default", DefaultRoute: Route{Model: "m"}, Backends: map[string]map[string]any{"b": {"k": "v"}}}
	child := ChildScope(parent, "exec-1", "leaf", cfg)
	if child.Depth != 1 {
		t.Fatalf("child depth = %d, want 1", child.Depth)
	}
	if child.ParentSessionID != "root" {
		t.Fatalf("parent session not inherited: %s", child.ParentSessionID)
	}
	// Freeze: mutating the source config must not change the snapshot.
	src := Config{Backend: "default", Backends: map[string]map[string]any{"b": {"k": "v"}}}
	snap := SnapshotConfig(src)
	src.Backends["b"]["k"] = "changed"
	if snap.Backends["b"]["k"] != "v" {
		t.Fatalf("snapshot not frozen: %v", snap.Backends["b"]["k"])
	}
	// Context round-trip.
	ctx := WithScope(context.Background(), child)
	if ScopeFrom(ctx) != child {
		t.Fatal("scope not round-tripped")
	}
	if ScopeFrom(context.Background()) != nil {
		t.Fatal("no scope must return nil")
	}
}

// TestDelegateToolHonorsMaxConcurrency 验证并发上限真正约束「正在运行的子代理数」，
// 而不只是 Wait 阶段。回归自：所有任务被立即 Launch，semaphore 只加在 Wait 上，
// 导致 maxConc 完全失效、瞬时 N 个子代理同时执行。
func TestDelegateToolHonorsMaxConcurrency(t *testing.T) {
	var mu sync.Mutex
	inFlight, peak := 0, 0
	release := make(chan struct{})
	runner := func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		mu.Lock()
		inFlight++
		if inFlight > peak {
			peak = inFlight
		}
		mu.Unlock()
		<-release // 全部阻塞，直到显式放行，便于观测并发峰值
		mu.Lock()
		inFlight--
		mu.Unlock()
		return ChildOutcome{Status: "completed", Summary: "ok"}, nil
	}
	broker := NewBroker()
	svc := NewLifecycleService(runner, broker, func() string { return "sess" })
	const maxConc = 2
	tool := NewDelegateTool(DelegateToolOptions{
		Service: svc, Provider: DefaultProvider{}, Broker: broker,
		MaxConcurrency: maxConc, ParentSessionID: "sess",
	})
	tasks := `{"tasks":[`
	for i := 0; i < 5; i++ {
		if i > 0 {
			tasks += ","
		}
		tasks += fmt.Sprintf(`{"goal":"g%d","index":%d,"role":"leaf"}`, i, i)
	}
	tasks += `]}`
	done := make(chan struct{})
	go func() {
		_, _ = tool.Call(context.Background(), json.RawMessage(tasks), nil)
		close(done)
	}()
	// 给足时间让所有本应并发的 Launch 发生；受控实现此刻最多 maxConc 个在跑。
	time.Sleep(300 * time.Millisecond)
	mu.Lock()
	observed := peak
	mu.Unlock()
	close(release)
	<-done
	if observed > maxConc {
		t.Fatalf("并发峰值 %d 超过上限 %d：并发闸门失效", observed, maxConc)
	}
	if observed < 1 {
		t.Fatal("没有子代理被执行")
	}
}

// TestDelegateToolCancelsSiblingsOnLaunchFailure 验证：任一 Launch 失败后，
// 已启动的同级子代理会被取消，而不是成为孤儿继续跑。回归自：失败分支只
// 取消已登记进 handles 的条目，且失败后 worker 仍会继续 Launch 新子代理；
// 新子代理与"正在 Launch 中尚未登记"的都不在取消范围内。
func TestDelegateToolCancelsSiblingsOnLaunchFailure(t *testing.T) {
	cancelled := make(chan string, 10)
	runner := func(ctx context.Context, cfg ChildConfig) (ChildOutcome, error) {
		select {
		case <-ctx.Done():
			cancelled <- cfg.Goal
			return ChildOutcome{Status: "interrupted", Summary: "cancelled"}, nil
		case <-time.After(10 * time.Second):
			return ChildOutcome{Status: "completed", Summary: "ok"}, nil
		}
	}
	broker := NewBroker()
	svc := NewLifecycleService(runner, broker, func() string { return "sess" })
	// ParentSessionID 留空：带 toolsets 的任务在 Launch 时被拒绝（无父作用域可
	// 校验子集），触发 sibling-launch-failed 取消路径；CheckToolsets 留 nil 绕过
	// 预检，让失败发生在 Launch 而非参数解析。
	tool := NewDelegateTool(DelegateToolOptions{
		Service: svc, Provider: DefaultProvider{}, Broker: broker,
		MaxConcurrency: 2, ParentSessionID: "",
	})
	// 任务 1 正常启动；任务 2 带 toolsets 且无父会话 → Launch 返回错误。
	in := json.RawMessage(`{"tasks":[
		{"goal":"a","index":0,"role":"leaf"},
		{"goal":"b","index":1,"role":"leaf","toolsets":["shell"]}
	]}`)
	res, err := tool.Call(context.Background(), in, nil)
	if err != nil {
		t.Fatalf("Call err: %v", err)
	}
	if !res.IsError {
		t.Fatalf("launch failure must fail the call, got %s", res.Content[0].Text)
	}
	// 任务 1 必须被取消（不迟到 10s 超时）；任务 2 因 toolsets 未启动。
	select {
	case g := <-cancelled:
		if g != "a" {
			t.Fatalf("cancelled goal = %q, want a", g)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("launched sibling was not cancelled (orphaned)")
	}
	// 确保没有第二个子代理意外启动（b 的 Launch 应已失败）。
	select {
	case g := <-cancelled:
		t.Fatalf("unexpected second child started/cancelled: %q", g)
	case <-time.After(200 * time.Millisecond):
	}
}

func TestClipStringKeepsUTF8Intact(t *testing.T) {
	s := strings.Repeat("中文内容", 100)
	got := clipString(s, 10)
	if !utf8.ValidString(got) {
		t.Fatalf("clipped string must be valid UTF-8, got %q", got)
	}
	if r := []rune(got); len(r) != 10 {
		t.Fatalf("want 10 runes, got %d (%q)", len(r), got)
	}
	if clipString("短文本", 100) != "短文本" {
		t.Fatal("short string must pass through unchanged")
	}
}
