// memory.go — 长期记忆（memories 表）的服务端接线与 REST 端点。
//
// 服务端做了两件事：
//  1. 把 agent.MemoryBlock 接到 memories 表：每次构建 agent 系统提示词时，按当前
//     run 的任务取「global + 该任务关联企业 + 该任务」的可见记忆，格式化成一段
//     【已沉淀记忆】注入正文之后（字符上限 memoryPromptMax，防上下文膨胀）。
//  2. 暴露管理端点：列表 / 新建 / 编辑 / 删除 / 召回 / 统计，供 UI 的「记忆库」页用。
package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"

	"github.com/Autumn-27/baize/agent"
	"github.com/Autumn-27/baize/db"
)

// memoryPromptMax 是注入系统提示词的记忆块字符上限。记忆的价值在精炼：宁可少
// 注入几条，也不能让一段手写的长记忆把上下文窗口吃掉。
const memoryPromptMax = 4000

// wireMemoryHooks connects agent.MemoryBlock to the memories table. Called once
// from server.New's m.pg block. With no memories (or the toggle off), the hook
// returns "" and agents' prompts are byte-identical to before.
func (s *Server) wireMemoryHooks() {
	agent.MemoryBlock = func(taskID int64) string {
		if !s.m.pg.GetBool(settingMemoryEnabled, true) {
			return ""
		}
		ms := s.m.pg.Memories()
		// 先解析任务的企业上下文：company 级记忆只在企业已知时可见（防跨客户泄露）。
		var companyID int64
		if taskID > 0 {
			if ids, err := ms.CompanyIDsForTask(context.Background(), taskID); err == nil && len(ids) > 0 {
				companyID = ids[0]
			}
		}
		mems, err := ms.Search(context.Background(), db.MemorySearch{
			TaskID: taskID, CompanyID: companyID, Limit: 12,
		})
		if err != nil || len(mems) == 0 {
			return ""
		}
		entries := make([]agent.MemoryEntry, 0, len(mems))
		ids := make([]int64, 0, len(mems))
		for _, mm := range mems {
			entries = append(entries, agent.MemoryEntry{Kind: mm.Kind, Title: mm.Title, Body: mm.Content})
			ids = append(ids, mm.ID)
		}
		// 被注入过系统提示词的记忆就是「被用过」：记一次强化，后续打分略上浮。
		_, _ = ms.Touch(context.Background(), ids)
		return agent.FormatMemoryBlock(entries, memoryPromptMax)
	}
}

// memoryStore returns the memory store, or nil when PG is unavailable.
func (s *Server) memoryStore() *db.MemoryStore {
	if s.m == nil || s.m.pg == nil {
		return nil
	}
	return s.m.pg.Memories()
}

// GET /api/memories — 列表（管理界面）。
func (s *Server) listMemories(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	q := r.URL.Query()
	var companyID, taskID int64
	companyID, _ = strconv.ParseInt(q.Get("company_id"), 10, 64)
	taskID, _ = strconv.ParseInt(q.Get("task_id"), 10, 64)
	limit, _ := strconv.Atoi(q.Get("limit"))
	offset, _ := strconv.Atoi(q.Get("offset"))
	mems, total, err := ms.List(r.Context(), db.MemoryFilter{
		Scope: q.Get("scope"), Kind: q.Get("kind"), Status: q.Get("status"), Q: q.Get("q"),
		CompanyID: companyID, TaskID: taskID, Limit: limit, Offset: offset,
		Entity: q.Get("entity"),
	})
	if err != nil {
		writeErr(w, 400, "查询失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"total": total, "memories": mems})
}

// POST /api/memories — 新建一条记忆。
func (s *Server) createMemory(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	var in db.MemoryInput
	if err := decode(r, &in); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if in.Source == "" {
		in.Source = "user"
	}
	m, created, err := ms.Put(r.Context(), in)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	if _, err := ms.Prune(r.Context(), m.Scope, int64Or(m.CompanyID), int64Or(m.TaskID)); err != nil {
		writeErr(w, 400, "已写入，但整理旧记忆失败: "+err.Error())
		return
	}
	writeJSON(w, 201, map[string]any{"memory": m, "created": created})
}

// PATCH /api/memories/{id} — 局部更新（title/kind/content/status/salience）。
func (s *Server) updateMemory(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "记忆编号无效")
		return
	}
	var body struct {
		Title    *string  `json:"title"`
		Kind     *string  `json:"kind"`
		Content  *string  `json:"content"`
		Status   *string  `json:"status"`
		Salience *float64 `json:"salience"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	patch := db.MemoryPatch{Salience: body.Salience}
	if body.Title != nil {
		patch.Title = *body.Title
	}
	if body.Kind != nil {
		patch.Kind = *body.Kind
	}
	if body.Content != nil {
		patch.Content = *body.Content
	}
	if body.Status != nil {
		patch.Status = *body.Status
	}
	m, err := ms.Update(r.Context(), id, patch)
	if err != nil {
		writeErr(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"memory": m})
}

// DELETE /api/memories/{id} — 删除一条记忆。
func (s *Server) deleteMemory(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "记忆编号无效")
		return
	}
	ok, err := ms.Delete(r.Context(), id)
	if err != nil {
		writeErr(w, 400, "删除失败: "+err.Error())
		return
	}
	if !ok {
		writeErr(w, 404, "记忆不存在")
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": true, "id": id})
}

// POST /api/memories/recall — 按关键词召回（给 UI 的「试试你能用上什么」）。
func (s *Server) recallMemories(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	var body struct {
		Query          string `json:"query"`
		TaskID         int64  `json:"task_id"`
		Limit          int    `json:"limit"`
		Entity         string `json:"entity"`
		IncludeExpired bool   `json:"include_expired"`
	}
	if err := decode(r, &body); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if strings.TrimSpace(body.Query) == "" && strings.TrimSpace(body.Entity) == "" {
		writeErr(w, 400, "query 或 entity 至少给一个")
		return
	}
	var companyID int64
	if body.TaskID > 0 {
		if ids, err := ms.CompanyIDsForTask(r.Context(), body.TaskID); err == nil && len(ids) > 0 {
			companyID = ids[0]
		}
	}
	mems, err := ms.Search(r.Context(), db.MemorySearch{
		Query: body.Query, TaskID: body.TaskID, CompanyID: companyID, Limit: body.Limit,
		Entity: body.Entity, IncludeExpired: body.IncludeExpired,
	})
	if err != nil {
		writeErr(w, 400, "检索失败: "+err.Error())
		return
	}
	if len(mems) > 0 {
		ids := make([]int64, 0, len(mems))
		for _, m := range mems {
			ids = append(ids, m.ID)
		}
		_, _ = ms.Touch(r.Context(), ids)
	}
	writeJSON(w, 200, map[string]any{"count": len(mems), "memories": mems})
}

// GET /api/memories/stats — 记忆库分布概览。
func (s *Server) memoryStats(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	stats, err := ms.Stats(r.Context())
	if err != nil {
		writeErr(w, 400, "统计失败: "+err.Error())
		return
	}
	total := 0
	for _, st := range stats {
		total += st.Count
	}
	writeJSON(w, 200, map[string]any{"total": total, "stats": stats, "enabled": s.m.pg.GetBool(settingMemoryEnabled, true)})
}

func int64Or(p *int64) int64 {
	if p == nil {
		return 0
	}
	return *p
}

// DELETE /api/memories/all — 清空整个记忆库（含实体与 Obsidian 追踪）。
// 破坏性操作：前端必须二次确认；这里只做一次幂等清空，返回各表删除计数。
func (s *Server) clearAllMemories(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	counts, err := ms.ClearAll(r.Context())
	if err != nil {
		writeErr(w, 500, "清空失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"deleted": counts})
}

// GET /api/memories/entities — 实体库列表（图谱浏览/按目标聚合）。
func (s *Server) listMemoryEntities(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	q := r.URL.Query()
	limit, _ := strconv.Atoi(q.Get("limit"))
	entities, err := ms.ListEntities(r.Context(), q.Get("kind"), limit)
	if err != nil {
		writeErr(w, 400, "查询失败: "+err.Error())
		return
	}
	writeJSON(w, 200, map[string]any{"entities": entities})
}

// GET /api/memories/{id}/graph — 单条记忆的图谱：记忆 + 其实体 + 实体关联的其它记忆。
func (s *Server) memoryEntityGraph(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil || id <= 0 {
		writeErr(w, 400, "记忆编号无效")
		return
	}
	companyID, _ := strconv.ParseInt(r.URL.Query().Get("company_id"), 10, 64)
	taskID, _ := strconv.ParseInt(r.URL.Query().Get("task_id"), 10, 64)
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	graph, err := ms.EntityGraph(r.Context(), id, companyID, taskID, limit)
	if err != nil {
		writeErr(w, 400, "图谱查询失败: "+err.Error())
		return
	}
	writeJSON(w, 200, graph)
}
