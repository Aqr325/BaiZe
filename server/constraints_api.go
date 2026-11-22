package server

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/guard"
)

// 总览「约束管理」的人工 CRUD 接口 + 注入范围开关的解析。操作约束(allow/deny)与 agent 侧的
// set_constraints 工具写同一张 task_constraints 表;这里是人类在 UI 上直接增删改。约束仅是
// 提示上下文——增删改后【不】通知 planner,下一轮规划自然读库生效(按产品决策)。每个变更 handler
// 都走 beginTaskOperation/decInflight,避免与任务删除竞态(与目标/意图 CRUD 一致)。

// 注入范围开关的 settings key,默认都开(GetBool 第二参数 = true)。
const (
	settingConstraintsInjectPlanner = "constraints_inject_planner"
	settingConstraintsInjectWorker  = "constraints_inject_worker"
)

// constraintInjectPlanner / constraintInjectWorker 报告是否把操作约束注入对应 agent 的
// 系统提示(默认开)。作为 resolver 传给 planner/worker,每轮读 → 改开关即时生效。
func (s *Server) constraintInjectPlanner() bool {
	return s.m.pg.GetBool(settingConstraintsInjectPlanner, true)
}

func (s *Server) constraintInjectWorker() bool {
	return s.m.pg.GetBool(settingConstraintsInjectWorker, true)
}

// listConstraints 返回本任务的全部操作约束(allow 在前、deny 在后)。
func (s *Server) listConstraints(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	rows, err := t.Store.ListConstraints()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"constraints": constraintDTOs(rows)})
}

// addConstraint 人工新增一条操作约束(kind=allow|deny)。不通知 planner。
func (s *Server) addConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法新增约束")
		return
	}
	defer s.engine.decInflight(t.ID)

	var body struct {
		Text    string `json:"text"`
		Kind    string `json:"kind"`
		Match   string `json:"match"`
		Pattern string `json:"pattern"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, "约束内容不能为空")
		return
	}
	kind := normalizeConstraintKind(body.Kind)
	if kind == "" {
		writeErr(w, 400, "kind 必须是 allow 或 deny")
		return
	}
	match := normalizeFenceMatch(body.Match)
	pattern := strings.TrimSpace(body.Pattern)
	if match != "" && pattern == "" {
		writeErr(w, 400, "结构化规则（match）必须同时提供 pattern")
		return
	}
	id, err := t.Store.AddStructuredConstraint(kind, text, match, pattern, "human")
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ConstraintDTO{ID: strconv.FormatInt(id, 10), Kind: kind, Text: text, Match: match, Pattern: pattern, Origin: "human"})
}

// editConstraint 人工修改一条约束(kind + text)。不通知 planner。
func (s *Server) editConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法修改约束")
		return
	}
	defer s.engine.decInflight(t.ID)

	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, 400, "bad constraint id")
		return
	}
	var body struct {
		Text    string `json:"text"`
		Kind    string `json:"kind"`
		Match   string `json:"match"`
		Pattern string `json:"pattern"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "invalid JSON")
		return
	}
	text := strings.TrimSpace(body.Text)
	if text == "" {
		writeErr(w, 400, "约束内容不能为空")
		return
	}
	kind := normalizeConstraintKind(body.Kind)
	if kind == "" {
		writeErr(w, 400, "kind 必须是 allow 或 deny")
		return
	}
	match := normalizeFenceMatch(body.Match)
	pattern := strings.TrimSpace(body.Pattern)
	if match != "" && pattern == "" {
		writeErr(w, 400, "结构化规则（match）必须同时提供 pattern")
		return
	}
	if err := t.Store.UpdateStructuredConstraint(cid, kind, text, match, pattern); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, ConstraintDTO{ID: strconv.FormatInt(cid, 10), Kind: kind, Text: text, Match: match, Pattern: pattern})
}

// deleteConstraint 人工删除一条约束。不通知 planner。
func (s *Server) deleteConstraint(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法删除约束")
		return
	}
	defer s.engine.decInflight(t.ID)

	cid, err := strconv.ParseInt(r.PathValue("cid"), 10, 64)
	if err != nil || cid <= 0 {
		writeErr(w, 400, "bad constraint id")
		return
	}
	if err := t.Store.DeleteConstraint(cid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

// normalizeConstraintKind lowercases + validates the kind; "" on invalid.
func normalizeConstraintKind(k string) string {
	k = strings.TrimSpace(strings.ToLower(k))
	if k == "allow" || k == "deny" {
		return k
	}
	return ""
}

// normalizeFenceMatch lowercases + validates the fence match domain; "" on invalid.
// ""（空）表示自由文本规则。
func normalizeFenceMatch(m string) string {
	m = strings.TrimSpace(strings.ToLower(m))
	switch m {
	case "", "tool", "command", "host", "path", "port", "all":
		return m
	}
	return ""
}

// constraintDTOs converts db rows to the frontend shape.
func constraintDTOs(in []db.Constraint) []ConstraintDTO {
	out := make([]ConstraintDTO, 0, len(in))
	for _, c := range in {
		dto := ConstraintDTO{
			ID:     strconv.FormatInt(c.ID, 10),
			Kind:   c.Kind,
			Text:   c.Text,
			Origin: c.Origin,
			TS:     rfc3339(c.CreatedAt),
		}
		if c.Match != nil {
			dto.Match = *c.Match
		}
		if c.Pattern != nil {
			dto.Pattern = *c.Pattern
		}
		out = append(out, dto)
	}
	return out
}

// buildTaskFence 由结构化约束（match+pattern 均非空）构建本任务的 Fence。
// 无结构化 allow 规则时 Fence 不激活（Active()==false），守卫回落到 deny 清单升级。
// AuthzStore 就是 ExplorationStore 本身（实现 IsFenceAuthorized/AddFenceAuthz）。
func buildTaskFence(store *db.ExplorationStore) *guard.Fence {
	if store == nil {
		return nil
	}
	rows, err := store.ListConstraints()
	if err != nil {
		return nil
	}
	var rules []guard.FenceRule
	for _, c := range rows {
		if !c.Structured() {
			continue
		}
		rules = append(rules, guard.FenceRule{
			Kind:    c.Kind,
			Match:   *c.Match,
			Pattern: *c.Pattern,
			Text:    c.Text,
		})
	}
	return guard.NewFence(rules, store)
}

// --- 越界授权（FenceAuthz）端点 ---

// listFenceAuthz 返回本任务的越界授权记录（新→旧）+ Fence 激活状态。
func (s *Server) listFenceAuthz(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	rows, err := t.Store.ListFenceAuthz()
	if err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	fence := buildTaskFence(t.Store)
	writeJSON(w, 200, map[string]any{
		"authorizations": fenceAuthzDTOs(rows),
		"fence_active":   fence != nil && fence.Active(),
	})
}

// revokeFenceAuthz 撤销一条越界授权。
func (s *Server) revokeFenceAuthz(w http.ResponseWriter, r *http.Request) {
	t, ok := s.m.Task(r.PathValue("id"))
	if !ok {
		writeErr(w, 404, "task not found")
		return
	}
	if !s.engine.beginTaskOperation(t.ID) {
		writeErr(w, 409, "任务正在删除,无法撤销授权")
		return
	}
	defer s.engine.decInflight(t.ID)
	aid, err := strconv.ParseInt(r.PathValue("aid"), 10, 64)
	if err != nil || aid <= 0 {
		writeErr(w, 400, "bad authorization id")
		return
	}
	if err := t.Store.DeleteFenceAuthz(aid); err != nil {
		writeErr(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func fenceAuthzDTOs(in []db.FenceAuthz) []FenceAuthzDTO {
	out := make([]FenceAuthzDTO, 0, len(in))
	for _, a := range in {
		dto := FenceAuthzDTO{
			ID:        strconv.FormatInt(a.ID, 10),
			Surface:   a.Surface,
			Tool:      a.Tool,
			GrantedBy: a.GrantedBy,
			Note:      a.Note,
			CreatedAt: rfc3339(a.CreatedAt),
		}
		if a.ExpiresAt != nil {
			dto.HasExpiry = true
			dto.ExpiresAt = rfc3339(*a.ExpiresAt)
		}
		out = append(out, dto)
	}
	return out
}
