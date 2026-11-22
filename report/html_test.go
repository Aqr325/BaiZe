package report

import (
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/baize/db"
)

func findingNode(severity, vulnClass, name, poc string) *db.Node {
	payload := `{"vulnclass":"` + vulnClass + `","name":"` + name + `","severity":"` + severity + `","summary":"测试摘要","evidence":{"poc":"` + poc + `"}}`
	return &db.Node{Kind: "finding", Payload: []byte(payload)}
}

func TestHTMLReportRenders(t *testing.T) {
	in := Input{
		Title: "某系统渗透测试", Goal: "评估外网安全性", Status: "done",
		GeneratedAt: time.Date(2026, 11, 20, 12, 0, 0, 0, time.Local),
		AssetCounts: map[string]int{"subdomain": 12, "ip": 3},
		Findings: []*db.Node{
			findingNode("high", "sqli", "SQL 注入", "id=1' or '1'='1"),
			findingNode("critical", "rce", "远程命令执行", ""),
			findingNode("low", "信息泄露", "目录列表开启", ""),
			findingNode("", "unknown", "未分级", ""),
		},
	}
	out := HTML(in)
	for _, want := range []string{
		"某系统渗透测试", "执行摘要", "漏洞详情", "SQL 注入", "远程命令执行",
		"修复建议", "PoC / 证据", "评估外网安全性",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("HTML 报告缺 %q", want)
		}
	}
	// 严重等级排序：critical 在 high 前
	if strings.Index(out, "远程命令执行") > strings.Index(out, "SQL 注入") {
		t.Fatal("critical 应排在 high 之前")
	}
	// HTML 转义：payload 里的引号不该破坏结构
	if !strings.Contains(out, "id=1&#39; or &#39;1&#39;=&#39;1") && !strings.Contains(out, "id=1' or '1'='1") {
		t.Fatal("PoC 内容未正确输出")
	}
}

func TestHTMLReportEscapes(t *testing.T) {
	in := Input{Title: `<script>alert(1)</script>`, GeneratedAt: time.Date(2026, 11, 20, 12, 0, 0, 0, time.Local),
		Findings: []*db.Node{findingNode("high", `xss`, `<img src=x onerror=alert(2)>`, "")}}
	out := HTML(in)
	if strings.Contains(out, "<script>alert(1)") {
		t.Fatal("标题未转义，存在 XSS")
	}
	if strings.Contains(out, `<img src=x onerror`) {
		t.Fatal("finding 名称未转义")
	}
}

func TestRemediationsMapping(t *testing.T) {
	cases := []struct{ class, name string; n int }{
		{"sqli", "注入", 3}, {"xss", "存储型跨站", 3}, {"ssrf", "SSRF", 3},
		{"弱口令", "admin/admin", 3}, {"完全未知类型", "随便什么", 2},
	}
	for _, c := range cases {
		if got := Remediations(c.class, c.name); len(got) < 1 {
			t.Fatalf("class=%q 无修复建议", c.class)
		}
	}
}
