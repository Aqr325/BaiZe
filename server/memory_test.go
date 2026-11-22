package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 记忆端点在「无数据源」时应干净地返回 503，而不是裸 panic。PG 不可用时
// memoryStore() 返回 nil，所有 handler 必须走这一条降级路径。
// （读写路径的完整覆盖需要 PG，走集成测试。）

func TestMemoryHandlersUnavailable(t *testing.T) {
	s := &Server{} // 无 manager/pg

	cases := []struct {
		name, method, path, body string
	}{
		{"list", "GET", "/api/memories", ""},
		{"create", "POST", "/api/memories", `{"content":"x"}`},
		{"update", "PATCH", "/api/memories/1", `{"title":"x"}`},
		{"delete", "DELETE", "/api/memories/1", ""},
		{"recall", "POST", "/api/memories/recall", `{"query":"x"}`},
		{"stats", "GET", "/api/memories/stats", ""},
		{"entities", "GET", "/api/memories/entities", ""},
		{"graph", "GET", "/api/memories/1/graph", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			if c.method == "PATCH" || c.method == "DELETE" || c.name == "graph" {
				req.SetPathValue("id", "1")
			}
			w := httptest.NewRecorder()
			var handler http.HandlerFunc
			switch c.name {
			case "list":
				handler = s.listMemories
			case "create":
				handler = s.createMemory
			case "update":
				handler = s.updateMemory
			case "delete":
				handler = s.deleteMemory
			case "recall":
				handler = s.recallMemories
			case "stats":
				handler = s.memoryStats
			case "entities":
				handler = s.listMemoryEntities
			case "graph":
				handler = s.memoryEntityGraph
			}
			handler(w, req)
			if w.Code != http.StatusServiceUnavailable {
				t.Errorf("%s: 应返回 503，得 %d（body=%s）", c.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestMemoryInt64Or(t *testing.T) {
	if int64Or(nil) != 0 {
		t.Error("nil 指针应得 0")
	}
	v := int64(9)
	if int64Or(&v) != 9 {
		t.Error("非 nil 应解引用")
	}
}

func TestMemoryPromptMaxIsSane(t *testing.T) {
	if memoryPromptMax <= 0 || memoryPromptMax > 20000 {
		t.Errorf("提示词记忆块上限应为一个合理的正整数，得 %d", memoryPromptMax)
	}
}
