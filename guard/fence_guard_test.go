package guard

import (
	"context"
	"encoding/json"
	"testing"
)

// TestFenceGuardIntegration verifies the guard wiring when a Fence is installed:
// in-scope → allow, forbidden → block, out-of-bounds without an approval link →
// safe block, inactive fence → legacy passthrough. Uses interceptor=nil (chat-style
// guard), which is the path that runs when no approval chain is wired.
func TestFenceGuardIntegration(t *testing.T) {
	block := func(g *Guard, cmd string) bool {
		input, _ := json.Marshal(map[string]string{"command": cmd})
		b, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", input)
		return b
	}

	// 激活 Fence：允许 host *.example.com，禁止 rm*。
	fence := NewFence([]FenceRule{
		{Kind: "allow", Match: "host", Pattern: "*.example.com"},
		{Kind: "deny", Match: "command", Pattern: "rm*"},
	}, &fakeAuthz{})
	g := New()
	g.SetFence(fence)

	// in-scope host → 放行。
	if block(g, "curl http://api.example.com/") {
		t.Error("in-scope host call must pass")
	}
	// 越界 host → 无审批链路 → 安全拦截。
	if !block(g, "curl http://api.evil.org/") {
		t.Error("out-of-bounds host call must be blocked when no approval chain")
	}
	// 命中禁止清单 → 硬拦。
	if !block(g, "rm -rf /") {
		t.Error("forbidden command must be blocked")
	}

	// 未激活 Fence（仅 deny，无 allow）→ 回落旧行为：无拦截器时全部放行。
	g2 := New()
	g2.SetFence(NewFence([]FenceRule{{Kind: "deny", Match: "command", Pattern: "rm*"}}, &fakeAuthz{}))
	if block(g2, "rm -rf /") {
		t.Error("inactive fence with no interceptor must passthrough (legacy)")
	}
}

// TestFenceGuardAuthorizedMemory verifies a previously-authorized surface passes
// through even without an approval link (authorization memory short-circuits).
func TestFenceGuardAuthorizedMemory(t *testing.T) {
	store := &fakeAuthz{}
	fence := NewFence([]FenceRule{{Kind: "allow", Match: "host", Pattern: "*.example.com"}}, store)
	s := fence.SurfaceFor("Bash", input("curl http://api.evil.org/"))
	if s != "host:api.evil.org" {
		t.Fatalf("surface: %q", s)
	}
	if err := fence.Authorize(s, "Bash", input("curl http://api.evil.org/")); err != nil {
		t.Fatal(err)
	}
	g := New()
	g.SetFence(fence)
	in, _ := json.Marshal(map[string]string{"command": "curl http://api.evil.org/"})
	if blocked, _, _ := g.Hooks().PreToolUse(context.Background(), "Bash", in); blocked {
		t.Error("authorized surface must pass through")
	}
}
