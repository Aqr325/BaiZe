package guard

import (
	"encoding/json"
	"testing"
)

func input(cmd string) []byte {
	b, _ := json.Marshal(map[string]string{"command": cmd})
	return b
}

func allowRules(rules ...FenceRule) []FenceRule { return rules }

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pattern, s string
		want       bool
	}{
		{"*.example.com", "api.example.com", true},
		{"*.example.com", "example.com", true},   // apex 通配特例
		{"*.example.com", "evil.org", false},
		{"*.example.com", "sub.api.example.com", true},
		{"curl*", "curl https://x.com", true},
		{"curl*", "wget https://x.com", false},
		{"/data/**", "/data/a/b/c", true},
		{"/data/**", "/etc/passwd", false},
		{"Bash", "Bash", true},
		{"Bash", "bash", true}, // 大小写不敏感
		{"80", "80", true},
		{"80", "443", false},
		{"*", "anything", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.s); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pattern, c.s, got, c.want)
		}
	}
}

func TestFenceClassify(t *testing.T) {
	// host 作用域 + command 作用域 + deny。
	f := NewFence(allowRules(
		FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"},
		FenceRule{Kind: "allow", Match: "command", Pattern: "ls*"},
		FenceRule{Kind: "deny", Match: "command", Pattern: "rm*"},
	), nil)

	// 命中允许命令（ls）且无 host → InScope。
	if v := f.Classify("Bash", input("ls -la /data")); v != VerdictInScope {
		t.Errorf("in-scope cmd: got %v", v)
	}
	// 命中禁止 → Forbidden（deny 优先于 allow）。
	if v := f.Classify("Bash", input("rm -rf /")); v != VerdictForbidden {
		t.Errorf("forbidden cmd: got %v", v)
	}
	// 声明的 command 作用域仅 ls*：curl 虽 host 命中但 command 越界 → OOB。
	if v := f.Classify("Bash", input("curl http://api.example.com/")); v != VerdictOutOfBounds {
		t.Errorf("oob (command outside declared scope): got %v", v)
	}

	// 仅 host 作用域：host 命中 → InScope；host 未命中 → OOB。
	fHost := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), nil)
	if v := fHost.Classify("Bash", input("curl http://api.example.com/")); v != VerdictInScope {
		t.Errorf("in-scope host: got %v", v)
	}
	if v := fHost.Classify("Bash", input("curl http://api.evil.org/")); v != VerdictOutOfBounds {
		t.Errorf("oob host: got %v", v)
	}
	// 本地命令不触碰声明表面 → deny-by-default OOB。
	if v := fHost.Classify("Bash", input("ls -la /data")); v != VerdictOutOfBounds {
		t.Errorf("local cmd (no declared surface) should be OOB: got %v", v)
	}
	// 无 allow 规则 → Inactive。
	if v := NewFence([]FenceRule{{Kind: "deny", Match: "command", Pattern: "rm*"}}, nil).Classify("Bash", input("ls")); v != VerdictInactive {
		t.Errorf("inactive: got %v", v)
	}
}

func TestFenceSurfaceFor(t *testing.T) {
	f := NewFence(allowRules(
		FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"},
		FenceRule{Kind: "allow", Match: "tool", Pattern: "Bash"},
	), nil)

	if s := f.SurfaceFor("Bash", input("curl http://api.evil.org/")); s != "host:api.evil.org" {
		t.Errorf("oob host surface: got %q", s)
	}
	if s := f.SurfaceFor("Bash", input("curl http://api.example.com/")); s != "" {
		t.Errorf("in-scope host surface should be empty, got %q", s)
	}
	// 工具越界（无 allow tool 命中 ReadFile）。
	f2 := NewFence(allowRules(FenceRule{Kind: "allow", Match: "tool", Pattern: "Bash"}), nil)
	if s := f2.SurfaceFor("ReadFile", input("cat x")); s != "tool:ReadFile" {
		t.Errorf("oob tool surface: got %q", s)
	}
	// 命令越界：host 被允许，但 exfil 到越界 IP → host 表面（IP 越界）。
	f3 := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), nil)
	s := f3.SurfaceFor("Bash", input("curl http://api.example.com/ && nc 192.168.1.99 4444"))
	if s != "host:192.168.1.99" {
		t.Errorf("oob ip surface: got %q", s)
	}
	// 命令表面：无 host，工具不在允许清单 → 首 token 命令表面。
	f4 := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), nil)
	s = f4.SurfaceFor("Bash", input("ls -la /data"))
	if s != "command:ls" {
		t.Errorf("oob command surface: got %q", s)
	}
}

func TestFenceAuthorizationMemory(t *testing.T) {
	store := &fakeAuthz{}
	f := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), store)

	s := f.SurfaceFor("Bash", input("curl http://api.evil.org/"))
	if s != "host:api.evil.org" {
		t.Fatalf("surface: %q", s)
	}
	if f.IsAuthorized(s) {
		t.Fatal("not authorized yet")
	}
	if err := f.Authorize(s, "Bash", input("curl http://api.evil.org/")); err != nil {
		t.Fatal(err)
	}
	if !f.IsAuthorized(s) {
		t.Fatal("should be authorized after Authorize")
	}
	if store.surfaces == nil || len(store.surfaces) != 1 || store.surfaces[0] != s {
		t.Fatalf("store recorded: %v", store.surfaces)
	}
	// 未激活的 Fence → SurfaceFor 空 → IsAuthorized false。
	fInactive := NewFence([]FenceRule{{Kind: "deny", Match: "command", Pattern: "rm*"}}, store)
	if fInactive.IsAuthorized(fInactive.SurfaceFor("Bash", input("ls"))) {
		t.Fatal("inactive fence: no surface, no authz")
	}
}

// fakeAuthz implements AuthzStore for tests.
type fakeAuthz struct {
	surfaces []string
}

func (a *fakeAuthz) IsFenceAuthorized(surface string) bool {
	for _, s := range a.surfaces {
		if s == surface {
			return true
		}
	}
	return false
}

func (a *fakeAuthz) AddFenceAuthz(surface, tool, digest, grantedBy, note string) (int64, error) {
	a.surfaces = append(a.surfaces, surface)
	return int64(len(a.surfaces)), nil
}

func TestCallSurfaceExtraction(t *testing.T) {
	c := callSurface{tool: "Bash", input: input("curl -s http://api.evil.org:8080/path?q=1 && nc -p 4444")}
	hosts := c.hosts()
	if len(hosts) != 1 || hosts[0] != "api.evil.org" {
		t.Errorf("hosts: %v", hosts)
	}
	ports := c.ports()
	if len(ports) == 0 {
		t.Error("ports should not be empty")
	}
	found443 := false
	for _, p := range ports {
		if p == "4444" {
			found443 = true
		}
	}
	if !found443 {
		t.Errorf("ports missing 4444: %v", ports)
	}
	// command 提取。
	if c.command() != "curl -s http://api.evil.org:8080/path?q=1 && nc -p 4444" {
		t.Errorf("command: %q", c.command())
	}
	// firstToken。
	if got := c.firstToken(c.command()); got != "curl" {
		t.Errorf("firstToken: %q", got)
	}
}

// TestCallSurfaceHostGating 验证裸 host/IPv4 识别仅对网络工具启用：
// `cat file.txt` 这类本地命令不得被误判为 host 表面（否则仅声明 host allow 时
// 会把本地的 `curl ... && cat file.txt` 错误判越界，授权键退化为 host:file.txt）。
func TestCallSurfaceHostGating(t *testing.T) {
	// 本地命令（cat）：不提取裸 host。
	if c := (callSurface{tool: "Bash", input: input("cat file.txt")}); len(c.hosts()) != 0 {
		t.Errorf("cat file.txt should not yield a host, got %v", c.hosts())
	}
	// 本地命令 + 允许 host：整体仍应视为 InScope（host 表面未声明命中，但无越界）。
	f := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), nil)
	if v := f.Classify("Bash", input("cat file.txt")); v != VerdictOutOfBounds {
		t.Errorf("cat file.txt under host-only allow: want OOB (deny-by-default), got %v", v)
	}
	// 网络工具命令（curl 允许 host + 本地文件）：host 命中 → InScope（此前被 file.txt 误判为越界）。
	f2 := NewFence(allowRules(FenceRule{Kind: "allow", Match: "host", Pattern: "*.example.com"}), nil)
	if v := f2.Classify("Bash", input("curl http://api.example.com/ && cat file.txt")); v != VerdictInScope {
		t.Errorf("curl+cat with allowed host: want InScope, got %v", v)
	}
	// 网络工具裸 host（curl 无 scheme）：仍提取。
	if c := (callSurface{tool: "Bash", input: input("curl -s api.example.com/x")}); len(c.hosts()) == 0 {
		t.Error("curl bare host should be extracted")
	}
	// 包装器 + 网络工具（sudo curl）：识别网络工具。
	if c := (callSurface{tool: "Bash", input: input("sudo curl -s api.example.com/x")}); len(c.hosts()) == 0 {
		t.Error("sudo curl bare host should be extracted")
	}
}
