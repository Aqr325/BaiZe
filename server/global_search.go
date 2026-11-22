package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// searchItem 是全局搜索的统一结果单元。
type searchItem struct {
	Kind      string `json:"kind"` // task | finding | conversation | asset
	ID        string `json:"id"`
	Title     string `json:"title"`
	Subtitle  string `json:"subtitle,omitempty"`
	URL       string `json:"url"`
	Severity  string `json:"severity,omitempty"`
	Status    string `json:"status,omitempty"`
	CreatedAt string `json:"created_at,omitempty"`
}

// getGlobalSearch 跨任务/发现/对话/资产的统一检索。
// GET /api/search?q=&limit=20（limit 上限 50）
// 空查询返回空结果（前端展示引导态）。
func (s *Server) getGlobalSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	limit := 20
	if v, err := strconv.Atoi(r.URL.Query().Get("limit")); err == nil {
		if v < 1 {
			v = 1
		}
		if v > 50 {
			v = 50
		}
		limit = v
	}
	out := map[string]any{"q": q, "items": []searchItem{}}
	if q == "" {
		writeJSON(w, 200, out)
		return
	}
	pg := s.m.pg
	if pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()
	pattern := "%" + escapeLike(q) + "%"
	items := make([]searchItem, 0, limit)

	// 任务：名称/描述/目标。
	if rows, err := pg.QueryContext(ctx, `
		SELECT id::text, coalesce(nullif(name,''), description), description, status, created_at
		FROM tasks
		WHERE name ILIKE $1 OR description ILIKE $1 OR goal ILIKE $1
		ORDER BY created_at DESC LIMIT $2`, pattern, limit); err == nil {
		for rows.Next() {
			var it searchItem
			var created time.Time
			if err := rows.Scan(&it.ID, &it.Title, &it.Subtitle, &it.Status, &created); err == nil {
				it.Kind = "task"
				it.CreatedAt = created.Format(time.RFC3339)
				it.URL = "/function/tasks"
				items = append(items, it)
			}
		}
		rows.Close()
	}

	// 发现：名称/摘要/漏洞分类（含任务 ID 供展示）。
	if rows, err := pg.QueryContext(ctx, `
		SELECT f.id::text, coalesce(nullif(f.name,''), f.vulnclass), f.summary, f.severity, f.status,
		       coalesce(f.task_id, 0), f.created_at
		FROM findings f
		WHERE f.name ILIKE $1 OR f.summary ILIKE $1 OR f.vulnclass ILIKE $1
		ORDER BY f.created_at DESC LIMIT $2`, pattern, limit); err == nil {
		for rows.Next() {
			var it searchItem
			var taskID int64
			var created time.Time
			if err := rows.Scan(&it.ID, &it.Title, &it.Subtitle, &it.Severity, &it.Status, &taskID, &created); err == nil {
				it.Kind = "finding"
				it.CreatedAt = created.Format(time.RFC3339)
				it.URL = "/function/findings"
				if it.Subtitle != "" {
					it.Subtitle = truncateRunes(it.Subtitle, 80)
				}
				if taskID > 0 {
					it.Subtitle = "任务 #" + strconv.FormatInt(taskID, 10) + " · " + it.Subtitle
				}
				items = append(items, it)
			}
		}
		rows.Close()
	}

	// 对话：标题。
	if rows, err := pg.QueryContext(ctx, `
		SELECT id::text, title, agent_key, created_at
		FROM conversations
		WHERE title ILIKE $1
		ORDER BY updated_at DESC LIMIT $2`, pattern, limit); err == nil {
		for rows.Next() {
			var it searchItem
			var created time.Time
			if err := rows.Scan(&it.ID, &it.Title, &it.Subtitle, &created); err == nil {
				it.Kind = "conversation"
				it.CreatedAt = created.Format(time.RFC3339)
				it.URL = "/chat?c=" + it.ID
				items = append(items, it)
			}
		}
		rows.Close()
	}

	// 资产：域名/IP。
	if rows, err := pg.QueryContext(ctx, `
		SELECT id::text, coalesce(domain, coalesce(root_domain, ip::text, '')), type, created_at
		FROM assets
		WHERE domain ILIKE $1 OR root_domain ILIKE $1 OR ip::text ILIKE $1
		ORDER BY created_at DESC LIMIT $2`, pattern, limit); err == nil {
		for rows.Next() {
			var it searchItem
			var created time.Time
			if err := rows.Scan(&it.ID, &it.Title, &it.Subtitle, &created); err == nil {
				it.Kind = "asset"
				it.Status = it.Subtitle // type 复用 status 字段展示
				it.CreatedAt = created.Format(time.RFC3339)
				it.URL = "/function/assets?asset=" + it.ID
				items = append(items, it)
			}
		}
		rows.Close()
	}

	if len(items) > limit {
		items = items[:limit]
	}
	out["items"] = items
	writeJSON(w, 200, out)
}

// escapeLike 转义 ILIKE 通配符，防止用户输入 % _ 造成全表扫描式误配。
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
