// obsidian.go — 本地 Obsidian 知识库的服务端接线（导入 + 状态）。
//
// 两个端点：
//   - POST /api/obsidian/sync   扫描 vault 增量导入记忆（幂等，可反复触发）
//   - GET  /api/obsidian/status 查询当前 vault 的同步状态
//
// vault 路径优先取请求体，其次读设置 obsidian_vault；sync 成功后回写设置。
package server

import (
	"net/http"
	"strings"

	"github.com/Autumn-27/baize/db"
)

// POST /api/obsidian/sync — 把本地 Obsidian 知识库增量导入记忆库。
func (s *Server) syncObsidian(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	var body struct {
		Vault string `json:"vault"`
		Scope string `json:"scope"`
		Limit int    `json:"limit"`
	}
	_ = decode(r, &body)
	vault := strings.TrimSpace(body.Vault)
	if vault == "" {
		if v, ok, _ := s.m.pg.GetSetting(settingObsidianVault); ok {
			vault = strings.TrimSpace(v)
		}
	}
	if vault == "" {
		writeErr(w, 400, "vault 不能为空：请求体传 vault，或在设置里配置 obsidian_vault")
		return
	}
	scope := strings.TrimSpace(body.Scope)
	if scope == "" {
		scope = "global"
	}
	res, err := ms.SyncObsidian(r.Context(), db.ObsidianSyncOpts{
		Vault: vault, Scope: scope, Limit: body.Limit,
	})
	if err != nil {
		writeErr(w, 400, "同步失败: "+err.Error())
		return
	}
	// 记住 vault（变化时才写）。
	if cur, ok, _ := s.m.pg.GetSetting(settingObsidianVault); !ok || strings.TrimSpace(cur) != vault {
		_ = s.m.pg.SetSetting(settingObsidianVault, vault)
	}
	writeJSON(w, 200, map[string]any{"vault": vault, "result": res})
}

// GET /api/obsidian/status — 查询当前 vault 的同步状态。
func (s *Server) obsidianStatus(w http.ResponseWriter, r *http.Request) {
	ms := s.memoryStore()
	if ms == nil {
		writeErr(w, 503, "数据源不可用")
		return
	}
	vault, _, _ := s.m.pg.GetSetting(settingObsidianVault)
	st, err := ms.ObsidianStatus(r.Context(), vault)
	if err != nil {
		writeErr(w, 400, "状态查询失败: "+err.Error())
		return
	}
	writeJSON(w, 200, st)
}
