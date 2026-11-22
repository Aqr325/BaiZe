package server

import (
	"testing"
)

func TestBuiltinScenarios(t *testing.T) {
	scs := builtinScenarios()
	if len(scs) < 1 {
		t.Fatal("至少应有内置场景")
	}
	seen := map[string]bool{}
	for _, s := range scs {
		if s.Name == "" || len(s.Stages) == 0 {
			t.Fatalf("场景 %q 缺 name 或 stages", s.Name)
		}
		if seen[s.Name] {
			t.Fatalf("场景重名: %s", s.Name)
		}
		seen[s.Name] = true
		for _, st := range s.Stages {
			if !validScenarioKind(st.Kind) {
				t.Fatalf("场景 %s 含未知阶段 %q", s.Name, st.Kind)
			}
		}
	}
}

func TestValidScenarioKind(t *testing.T) {
	for _, k := range []string{"dns", "http", "crawl", "nuclei"} {
		if !validScenarioKind(k) {
			t.Fatalf("%q 应为合法阶段类型", k)
		}
	}
	if validScenarioKind("ssh") || validScenarioKind("") || validScenarioKind("nmap") {
		t.Fatal("ssh/空/nmap 应为非法阶段类型")
	}
}

func TestScenarioAutomationBoundary(t *testing.T) {
	// 非 automation + confirm 边界 → 停在边界；automation → 一路推进（无 engine 时 Queued=0，不崩）。
	guided := Scenario{Name: "g", Automation: false, Stages: []ScenarioStage{{Kind: "http", Confirm: "confirm"}}}
	res := runScenario(nil, nil, guided, []string{"http://a.test"})
	if !res.AwaitingConfirm || res.PendingStage != "http" {
		t.Fatalf("guided 应停在 confirm 边界: %+v", res)
	}

	auto := Scenario{Name: "a", Automation: true, Stages: []ScenarioStage{{Kind: "http"}, {Kind: "crawl"}}}
	res2 := runScenario(nil, nil, auto, []string{"http://a.test"})
	if res2.AwaitingConfirm {
		t.Fatalf("automation 不应停在边界: %+v", res2)
	}
}

func TestScenarioNilEngineSafe(t *testing.T) {
	sc := Scenario{Name: "n", Automation: true, Stages: []ScenarioStage{{Kind: "http"}}}
	res := runScenario(nil, nil, sc, []string{"http://a.test"})
	if res.Queued != 0 {
		t.Fatalf("nil engine 不应入队: %+v", res)
	}
}

func TestHostOfURL(t *testing.T) {
	if got := hostOfURL("http://example.com/path?q=1"); got != "example.com" {
		t.Fatalf("hostOfURL 解析错误: %q", got)
	}
	if got := hostOfURL("https://sub.example.org"); got != "sub.example.org" {
		t.Fatalf("hostOfURL 解析错误: %q", got)
	}
	if got := hostOfURL("example.com"); got != "example.com" {
		t.Fatalf("hostOfURL 无 scheme 应原样返回: %q", got)
	}
}
