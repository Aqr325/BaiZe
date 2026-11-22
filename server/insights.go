package server

import (
	"net/http"
	"strconv"
	"time"
)

type tasksInsightDay struct {
	Date    string `json:"date"`
	Created int    `json:"created"`
	Done    int    `json:"done"`
	Failed  int    `json:"failed"` // failed + timeout 合并计数
}

type findingsInsightDay struct {
	Date     string `json:"date"`
	Critical int    `json:"critical"`
	High     int    `json:"high"`
	Medium   int    `json:"medium"`
	Low      int    `json:"low"`
	Info     int    `json:"info"`
}

type tokensInsightDay struct {
	Date   string `json:"date"`
	Input  int64  `json:"input"`
	Output int64  `json:"output"`
}

// zeroDays 生成 since 起连续 days 天的日期键列表（YYYY-MM-DD，升序）。
func zeroDays(since time.Time, days int) []string {
	out := make([]string, 0, days)
	for i := 0; i < days; i++ {
		out = append(out, since.AddDate(0, 0, i).Format("2006-01-02"))
	}
	return out
}

// getInsights 全局数据洞察：任务/发现/Token 用量的按日聚合。
// GET /api/insights?days=30（7..90，缺省 30）
func (s *Server) getInsights(w http.ResponseWriter, r *http.Request) {
	days := 30
	if v, err := strconv.Atoi(r.URL.Query().Get("days")); err == nil {
		if v < 7 {
			v = 7
		}
		if v > 90 {
			v = 90
		}
		days = v
	}
	pg := s.m.pg
	if pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	since := time.Now().AddDate(0, 0, -days+1).Truncate(24 * time.Hour)
	dateKeys := zeroDays(since, days)

	out := map[string]any{"days": days}

	// 1) 任务：按创建日与结束日聚合（done/failed+timeout）。
	tasksByDay := map[string]*tasksInsightDay{}
	for _, k := range dateKeys {
		tasksByDay[k] = &tasksInsightDay{Date: k}
	}
	if rows, err := pg.Query(`
		SELECT created_at::date, count(*) FROM tasks
		WHERE created_at >= $1 GROUP BY 1`, since); err == nil {
		for rows.Next() {
			var d time.Time
			var n int
			if rows.Scan(&d, &n) == nil {
				if v, ok := tasksByDay[d.Format("2006-01-02")]; ok {
					v.Created += n
				}
			}
		}
		rows.Close()
	}
	if rows, err := pg.Query(`
		SELECT completed_at::date,
		       count(*) FILTER (WHERE status='done'),
		       count(*) FILTER (WHERE status IN ('failed','timeout'))
		FROM tasks
		WHERE completed_at IS NOT NULL AND completed_at >= $1 GROUP BY 1`, since); err == nil {
		for rows.Next() {
			var d time.Time
			var done, failed int
			if rows.Scan(&d, &done, &failed) == nil {
				if v, ok := tasksByDay[d.Format("2006-01-02")]; ok {
					v.Done += done
					v.Failed += failed
				}
			}
		}
		rows.Close()
	}
	tasksList := make([]tasksInsightDay, 0, len(dateKeys))
	for _, k := range dateKeys {
		tasksList = append(tasksList, *tasksByDay[k])
	}
	out["tasks_by_day"] = tasksList

	// 2) 发现：确认漏洞按发现日 + 等级分布（排除已 dismissed）。
	findingsByDay := map[string]*findingsInsightDay{}
	for _, k := range dateKeys {
		findingsByDay[k] = &findingsInsightDay{Date: k}
	}
	if rows, err := pg.Query(`
		SELECT created_at::date,
		       count(*) FILTER (WHERE payload->>'severity'='critical'),
		       count(*) FILTER (WHERE payload->>'severity'='high'),
		       count(*) FILTER (WHERE payload->>'severity'='medium'),
		       count(*) FILTER (WHERE payload->>'severity'='low'),
		       count(*) FILTER (WHERE coalesce(payload->>'severity','info') NOT IN ('critical','high','medium','low'))
		FROM exploration_nodes
		WHERE kind='finding' AND state='confirmed' AND created_at >= $1
		GROUP BY 1`, since); err == nil {
		for rows.Next() {
			var d time.Time
			var c, h, m, l, i int
			if rows.Scan(&d, &c, &h, &m, &l, &i) == nil {
				if v, ok := findingsByDay[d.Format("2006-01-02")]; ok {
					v.Critical += c
					v.High += h
					v.Medium += m
					v.Low += l
					v.Info += i
				}
			}
		}
		rows.Close()
	}
	findingsList := make([]findingsInsightDay, 0, len(dateKeys))
	for _, k := range dateKeys {
		findingsList = append(findingsList, *findingsByDay[k])
	}
	out["findings_by_day"] = findingsList

	var sevCritical, sevHigh, sevMedium, sevLow, sevInfo int
	if err := pg.QueryRow(`
		SELECT count(*) FILTER (WHERE payload->>'severity'='critical'),
		       count(*) FILTER (WHERE payload->>'severity'='high'),
		       count(*) FILTER (WHERE payload->>'severity'='medium'),
		       count(*) FILTER (WHERE payload->>'severity'='low'),
		       count(*) FILTER (WHERE coalesce(payload->>'severity','info') NOT IN ('critical','high','medium','low'))
		FROM exploration_nodes WHERE kind='finding' AND state='confirmed'`).
		Scan(&sevCritical, &sevHigh, &sevMedium, &sevLow, &sevInfo); err == nil {
		out["severity_now"] = map[string]int{
			"critical": sevCritical, "high": sevHigh, "medium": sevMedium,
			"low": sevLow, "info": sevInfo,
		}
	}

	// 3) LLM Token 用量：activity 表按日汇总。
	tokensByDay := map[string]*tokensInsightDay{}
	for _, k := range dateKeys {
		tokensByDay[k] = &tokensInsightDay{Date: k}
	}
	if rows, err := pg.Query(`
		SELECT created_at::date,
		       coalesce(sum(input_tokens),0),
		       coalesce(sum(output_tokens),0)
		FROM activity
		WHERE created_at >= $1 GROUP BY 1`, since); err == nil {
		for rows.Next() {
			var d time.Time
			var in, outp int64
			if rows.Scan(&d, &in, &outp) == nil {
				if v, ok := tokensByDay[d.Format("2006-01-02")]; ok {
					v.Input += in
					v.Output += outp
				}
			}
		}
		rows.Close()
	}
	tokensList := make([]tokensInsightDay, 0, len(dateKeys))
	for _, k := range dateKeys {
		tokensList = append(tokensList, *tokensByDay[k])
	}
	out["tokens_by_day"] = tokensList

	writeJSON(w, 200, out)
}
