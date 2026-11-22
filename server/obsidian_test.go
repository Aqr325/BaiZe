package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// 无数据源时两个 Obsidian 端点都应 503 降级。
func TestObsidianHandlersUnavailable(t *testing.T) {
	s := &Server{}
	cases := []struct {
		name, method, path, body string
	}{
		{"sync", "POST", "/api/obsidian/sync", `{"vault":"/tmp/v"}`},
		{"status", "GET", "/api/obsidian/status", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, strings.NewReader(c.body))
			w := httptest.NewRecorder()
			var h http.HandlerFunc
			if c.name == "sync" {
				h = s.syncObsidian
			} else {
				h = s.obsidianStatus
			}
			h(w, req)
			if w.Code != 503 {
				t.Errorf("无数据源应 503，得 %d", w.Code)
			}
		})
	}
}
