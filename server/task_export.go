package server

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/Autumn-27/baize/db"
)

// ---------- 任务导出 ----------
//
// GET /api/export/tasks?format=csv|json[&status=][&category=]
// 与发现页导出互补：发现已有 /api/exploration/findings/export（含报告正文与
// 证据打包），这里导出任务维度清单（名称/目标/状态/耗时/父任务等），供复盘
// 汇总或导入外部表格。CSV 带_utf-8 BOM，Excel 打开不乱码。

func (s *Server) exportTasks(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	q := r.URL.Query()
	format := strings.ToLower(q.Get("format"))
	if format == "" {
		format = "csv"
	}
	if format != "csv" && format != "json" {
		writeErr(w, 400, "format 仅支持 csv|json")
		return
	}
	statusFilter := q.Get("status")

	tasks, err := pg.ListTasks()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}

	// ListTasks 返回全量（含归档），按可选状态过滤。
	filtered := make([]*db.Task, 0, len(tasks))
	for _, t := range tasks {
		if statusFilter != "" && t.Status != statusFilter {
			continue
		}
		filtered = append(filtered, t)
	}

	stamp := time.Now().Format("20060102-150405")
	setDownload := func(contentType, filename string) {
		w.Header().Set("Content-Type", contentType)
		// ASCII fallback + RFC 5987 UTF-8 name，与 findingsExport 同一套约定。
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"; filename*=UTF-8''%s`, sanitizeFilename(filename), url.PathEscape(filename)))
	}

	switch format {
	case "json":
		setDownload("application/json; charset=utf-8", "artex-tasks-"+stamp+".json")
		writeJSON(w, 200, map[string]any{"tasks": filtered})
	default:
		setDownload("text/csv; charset=utf-8", "artex-tasks-"+stamp+".csv")
		_ = writeTasksCSV(w, filtered)
	}
}

// taskExportRow 是 CSV 的一行投影。字段顺序即列顺序，保持稳定避免下游表格断裂。
func taskExportRow(t *db.Task) []string {
	completed := ""
	if t.CompletedAt != nil {
		completed = t.CompletedAt.Format(time.RFC3339)
	}
	parent := strings.Join(int64SliceStrings(t.SourceTaskIDs), " ")
	if t.ParentRef != "" {
		parent = t.ParentRef
	}
	return []string{
		strconv.FormatInt(t.ID, 10),
		t.Name,
		t.Status,
		t.CategoryName,
		t.Goal,
		t.CreatedAt.Format(time.RFC3339),
		completed,
		parent,
		t.Remark,
	}
}

var taskExportHeader = []string{"id", "name", "status", "category", "goal", "created_at", "completed_at", "parent", "remark"}

func writeTasksCSV(w http.ResponseWriter, tasks []*db.Task) error {
	cw := csv.NewWriter(w)
	// UTF-8 BOM: Excel 在无 BOM 时按系统 ANSI 码页解码，中文必乱码。
	if _, err := w.Write([]byte("\xef\xbb\xbf")); err != nil {
		return err
	}
	if err := cw.Write(taskExportHeader); err != nil {
		return err
	}
	for _, t := range tasks {
		if err := cw.Write(taskExportRow(t)); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func int64SliceStrings(v []int64) []string {
	out := make([]string, 0, len(v))
	for _, n := range v {
		out = append(out, strconv.FormatInt(n, 10))
	}
	return out
}
