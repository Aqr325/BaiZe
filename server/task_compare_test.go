package server

import (
	"encoding/json"
	"net/http/httptest"
	"strconv"
	"testing"
)

func TestFindingKeyNormalization(t *testing.T) {
	if findingKey("SQLi", " SQL 注入 ") != findingKey("sqli", "sql 注入") {
		t.Fatal("findingKey 应忽略大小写与首尾空白")
	}
	if findingKey("xss", "a") == findingKey("sqli", "a") {
		t.Fatal("不同 vulnclass 不应同键")
	}
}

func TestSevOrderIdx(t *testing.T) {
	order := []string{"critical", "high", "medium", "low", "info"}
	for i := 1; i < len(order); i++ {
		if sevOrderIdx(order[i-1]) >= sevOrderIdx(order[i]) {
			t.Fatalf("等级排序错误: %s(%d) 应先于 %s(%d)", order[i-1], sevOrderIdx(order[i-1]), order[i], sevOrderIdx(order[i]))
		}
	}
	// 未知等级与 info 同级兜底
	if sevOrderIdx("unknown") != sevOrderIdx("info") {
		t.Fatal("未知等级应与 info 同级")
	}
}

func TestTasksCompareDiff(t *testing.T) {
	m, err := NewManager(t.TempDir(), "")
	if err != nil {
		t.Skipf("postgres unavailable (%v) — skipping", err)
	}
	t.Cleanup(func() { _ = m.Close() })
	if m.pg == nil {
		t.Skip("no pg — skipping")
	}

	ta, err := m.pg.CreateTask("基线任务", "对比测试", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	tb, err := m.pg.CreateTask("复测任务", "对比测试", nil, 0, 0)
	if err != nil {
		t.Fatal(err)
	}

	// A: SQL注入(固定) + XSS(将修复)
	if _, err := m.pg.AddFinding(ta.ID, 0, "sqli", "SQL 注入", "high", "s", "e", "t", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.AddFinding(ta.ID, 0, "xss", "存储型 XSS", "medium", "s", "e", "t", nil); err != nil {
		t.Fatal(err)
	}
	// B: SQL注入(复现) + 新增 SSRF
	if _, err := m.pg.AddFinding(tb.ID, 0, "sqli", "SQL 注入", "high", "s", "e", "t", nil); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pg.AddFinding(tb.ID, 0, "ssrf", "内网 SSRF", "critical", "s", "e", "t", nil); err != nil {
		t.Fatal(err)
	}

	s := &Server{m: m}
	req := httptest.NewRequest("GET", "/api/tasks/compare?a="+strconv.FormatInt(ta.ID, 10)+"&b="+strconv.FormatInt(tb.ID, 10), nil)
	rec := httptest.NewRecorder()
	s.getTasksCompare(rec, req)
	if rec.Code != 200 {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Fixed      []map[string]any `json:"fixed"`
		New        []map[string]any `json:"new"`
		Persistent []map[string]any `json:"persistent"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Persistent) != 1 || out.Persistent[0]["name"] != "SQL 注入" {
		t.Fatalf("复现组应为 SQL 注入: %v", out.Persistent)
	}
	if len(out.Fixed) != 1 || out.Fixed[0]["name"] != "存储型 XSS" {
		t.Fatalf("已修复组应为 XSS: %v", out.Fixed)
	}
	if len(out.New) != 1 || out.New[0]["name"] != "内网 SSRF" {
		t.Fatalf("新发现组应为 SSRF: %v", out.New)
	}

	// 同任务参数应 400
	req = httptest.NewRequest("GET", "/api/tasks/compare?a="+strconv.FormatInt(ta.ID, 10)+"&b="+strconv.FormatInt(ta.ID, 10), nil)
	rec = httptest.NewRecorder()
	s.getTasksCompare(rec, req)
	if rec.Code != 400 {
		t.Fatalf("同任务应 400, got %d", rec.Code)
	}
}
