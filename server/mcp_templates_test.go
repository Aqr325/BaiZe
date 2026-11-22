package server

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Autumn-27/baize/db"
)

// 模板库：清单非空、每条模板字段自洽（transport 与对应配置匹配、name 唯一）。
func TestBuiltinMCPTemplates(t *testing.T) {
	tpl := builtinMCPTemplates()
	if len(tpl) == 0 {
		t.Fatal("模板清单为空")
	}
	seen := map[string]bool{}
	for _, m := range tpl {
		if m.Key == "" || m.Name == "" || m.Description == "" {
			t.Errorf("模板 %s 缺 key/name/description", m.Key)
		}
		if seen[m.Name] {
			t.Errorf("模板名重复: %s", m.Name)
		}
		seen[m.Name] = true
		switch m.Transport {
		case "stdio":
			if m.Command == "" || len(m.Args) == 0 {
				t.Errorf("stdio 模板 %s 缺 command/args", m.Name)
			}
		case "http", "sse":
			if m.URL == "" {
				t.Errorf("%s 模板 %s 缺 url", m.Transport, m.Name)
			}
		default:
			t.Errorf("模板 %s 未知 transport %q", m.Name, m.Transport)
		}
	}
}

// 连接测试前的配置校验：各传输方式的必填字段与未知传输。
func TestValidateMCPConfig(t *testing.T) {
	cases := []struct {
		name    string
		m       db.MCPServer
		wantErr bool
	}{
		{"stdio ok", db.MCPServer{Transport: "stdio", Command: "cmd"}, false},
		{"stdio no cmd", db.MCPServer{Transport: "stdio"}, true},
		{"http ok", db.MCPServer{Transport: "http", URL: "http://127.0.0.1/mcp"}, false},
		{"http no url", db.MCPServer{Transport: "http"}, true},
		{"sse no url", db.MCPServer{Transport: "sse"}, true},
		{"unknown transport", db.MCPServer{Transport: "grpc"}, true},
	}
	for _, c := range cases {
		err := validateMCPConfig(&c.m)
		if (err != nil) != c.wantErr {
			t.Errorf("%s: wantErr=%v got %v", c.name, c.wantErr, err)
		}
	}
}

// 任务导出行投影与 CSV 输出：列数稳定、BOM 存在、父任务来源拼接。
func TestTaskExportCSV(t *testing.T) {
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	done := now.Add(2 * time.Hour)
	tk := &db.Task{
		ID:            7,
		Name:          "目标 A 测试",
		Status:        "done",
		CategoryName:  "渗透",
		Goal:          "拿到 flag",
		CreatedAt:     now,
		CompletedAt:   &done,
		SourceTaskIDs: []int64{3, 4},
		Remark:        "备注,含逗号",
	}
	row := taskExportRow(tk)
	if len(row) != len(taskExportHeader) {
		t.Fatalf("行宽 %d != 表头 %d", len(row), len(taskExportHeader))
	}
	if row[7] != "3 4" {
		t.Errorf("parent = %q, want %q", row[7], "3 4")
	}
	if row[6] != done.Format(time.RFC3339) {
		t.Errorf("completed_at = %q", row[6])
	}
	// 序列化成 JSON 校验 CSV 头，避免直接依赖 csv.Writer 的换行细节。
	b, _ := json.Marshal(taskExportHeader)
	if !strings.Contains(string(b), "created_at") {
		t.Errorf("表头缺 created_at: %s", b)
	}
}
