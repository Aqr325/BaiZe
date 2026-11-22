package server

import (
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
)

// compareFindingItem 是对比结果中的发现摘要。
type compareFindingItem struct {
	ID        int64  `json:"id"`
	TaskID    int64  `json:"task_id"`
	Name      string `json:"name"`
	VulnClass string `json:"vulnclass"`
	Severity  string `json:"severity"`
	Status    string `json:"status"`
	Summary   string `json:"summary,omitempty"`
}

// compareTaskMeta 是对比侧的任务摘要。
type compareTaskMeta struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	Status      string `json:"status"`
	Description string `json:"description"`
	CreatedAt   string `json:"created_at,omitempty"`
	CompletedAt string `json:"completed_at,omitempty"`
}

// compareResult 是任务 findings 对比的三分类结果。
// A=基线（旧），B=复测（新）：only_in_a=已修复（复测未复现）、only_in_b=新发现、both=复现。
type compareResult struct {
	A          *compareTaskMeta     `json:"a"`
	B          *compareTaskMeta     `json:"b"`
	Fixed      []compareFindingItem `json:"fixed"`      // 仅在 A 出现：复测未复现
	New        []compareFindingItem `json:"new"`        // 仅在 B 出现：新发现
	Persistent []compareFindingItem `json:"persistent"` // 两侧都有：仍存在
}

// getTasksCompare 对比两个任务的确认漏洞差集。
// GET /api/tasks/compare?a={id}&b={id}
// 匹配键：vulnclass + name（小写归一）。取 findings 表（findings.go 语义：确认漏洞），
// 状态为 false_positive/ignored/duplicate 的记录不参与对比。
func (s *Server) getTasksCompare(w http.ResponseWriter, r *http.Request) {
	pg := s.m.pg
	if pg == nil {
		writeErr(w, 503, "database unavailable")
		return
	}
	taskA, taskB := r.URL.Query().Get("a"), r.URL.Query().Get("b")
	if taskA == "" || taskB == "" {
		writeErr(w, 400, "需要 a 与 b 两个任务参数")
		return
	}
	if taskA == taskB {
		writeErr(w, 400, "a 与 b 不能是同一个任务")
		return
	}
	idA, errA := strconv.ParseInt(taskA, 10, 64)
	idB, errB := strconv.ParseInt(taskB, 10, 64)
	if errA != nil || errB != nil {
		writeErr(w, 400, "任务参数格式错误")
		return
	}

	metaOf := func(id int64) (*compareTaskMeta, bool) {
		var m compareTaskMeta
		var created, completed *time.Time
		err := pg.QueryRow(`
			SELECT id, coalesce(nullif(name,''), description), status, description,
			       created_at, completed_at
			FROM tasks WHERE id=$1`, id).
			Scan(&m.ID, &m.Name, &m.Status, &m.Description, &created, &completed)
		if err != nil {
			return nil, false
		}
		if created != nil {
			m.CreatedAt = created.Format(time.RFC3339)
		}
		if completed != nil {
			m.CompletedAt = completed.Format(time.RFC3339)
		}
		return &m, true
	}
	metaA, foundA := metaOf(idA)
	metaB, foundB := metaOf(idB)
	if !foundA || !foundB {
		writeErr(w, 404, "任务不存在")
		return
	}

	loadFindings := func(taskID int64) map[string]compareFindingItem {
		out := map[string]compareFindingItem{}
		rows, err := pg.Query(`
			SELECT id, task_id, coalesce(nullif(name,''), vulnclass), vulnclass,
			       severity, status, summary
			FROM findings
			WHERE task_id=$1 AND status NOT IN ('false_positive','ignored','duplicate')`, taskID)
		if err != nil {
			return out
		}
		defer rows.Close()
		for rows.Next() {
			var it compareFindingItem
			if err := rows.Scan(&it.ID, &it.TaskID, &it.Name, &it.VulnClass, &it.Severity, &it.Status, &it.Summary); err == nil {
				out[findingKey(it.VulnClass, it.Name)] = it
			}
		}
		return out
	}

	setA, setB := loadFindings(idA), loadFindings(idB)
	res := compareResult{A: metaA, B: metaB, Fixed: []compareFindingItem{}, New: []compareFindingItem{}, Persistent: []compareFindingItem{}}
	for k, f := range setA {
		if _, inB := setB[k]; inB {
			res.Persistent = append(res.Persistent, setB[k])
		} else {
			res.Fixed = append(res.Fixed, f)
		}
	}
	for k, f := range setB {
		if _, inA := setA[k]; !inA {
			res.New = append(res.New, f)
		}
	}
	bySev := func(a, b compareFindingItem) bool { return sevOrderIdx(a.Severity) < sevOrderIdx(b.Severity) }
	sort.SliceStable(res.Fixed, func(i, j int) bool { return bySev(res.Fixed[i], res.Fixed[j]) })
	sort.SliceStable(res.New, func(i, j int) bool { return bySev(res.New[i], res.New[j]) })
	sort.SliceStable(res.Persistent, func(i, j int) bool { return bySev(res.Persistent[i], res.Persistent[j]) })
	writeJSON(w, 200, res)
}

// findingKey 归一化匹配键：漏洞分类 + 名称小写。
func findingKey(class, name string) string {
	return strings.ToLower(strings.TrimSpace(class)) + "|" + strings.ToLower(strings.TrimSpace(name))
}

// sevOrderIdx 等级排序权重（critical 最前）。
func sevOrderIdx(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}
