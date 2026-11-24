package server

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestJudgeDegradeReason(t *testing.T) {
	cases := []struct {
		name             string
		enabled          bool
		fail, askTimeout string
		wantDegrade      bool
		wantContains     []string
	}{
		{"safe defaults", true, "ask", "deny", false, nil},
		{"judge off", false, "ask", "deny", true, []string{"判官已关闭"}},
		{"fail allow", true, "allow", "deny", true, []string{"fail_action=allow"}},
		{"ask timeout allow", true, "ask", "allow", true, []string{"ask_timeout_action=allow"}},
		{"all degraded", false, "allow", "allow", true, []string{"判官已关闭", "fail_action=allow", "ask_timeout_action=allow"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := judgeDegradeReason(c.enabled, c.fail, c.askTimeout)
			if (got != "") != c.wantDegrade {
				t.Fatalf("judgeDegradeReason=%q, wantDegrade=%v", got, c.wantDegrade)
			}
			for _, want := range c.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("reason %q missing %q", got, want)
				}
			}
		})
	}
}

func TestIsBuiltinRule(t *testing.T) {
	for _, name := range []string{"[内置] 递归强制删除 rm -rf", "[内置反蜜罐] 下载管道直接执行"} {
		if !isBuiltinRule(name) {
			t.Errorf("%q should be builtin", name)
		}
	}
	for _, name := range []string{"我的自定义规则", "custom deny", ""} {
		if isBuiltinRule(name) {
			t.Errorf("%q should not be builtin", name)
		}
	}
}

// 审计事件序列化必须是稳定 JSON，便于事后按字段检索（日志页/服务器日志）。
func TestInterceptConfigEventJSON(t *testing.T) {
	ev := interceptConfigEvent{
		Op: "set_judge_config", Actor: "127.0.0.1", Target: "",
		Detail: "enabled=false fail=allow", Degrade: true, Why: "判官已关闭; fail_action=allow",
	}
	b, err := json.Marshal(ev)
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"op", "actor", "detail", "degrade", "why"} {
		if _, ok := got[key]; !ok {
			t.Errorf("missing stable field %q in %s", key, b)
		}
	}
	if got["degrade"] != true {
		t.Errorf("degrade not encoded as bool: %s", b)
	}
}
