package server

import (
	"log"

	"github.com/Autumn-27/baize/agent"
)

// seedDynamicAgent 以「一次性、可编辑、可删除」的会话级 Agent 创建某个内置增强角色：
// 幂等（flag + key 已存在判断）、首次创建时播种默认提示词并绑定工具。
// 与 seedReporterAgent / seedFindingRetester 同一套模式，保证 UI 可编辑/可删除、
// 重启不覆盖用户改动。
func (s *Server) seedDynamicAgent(key, name, desc, prompt string, tools []string) {
	const flagPrefix = "_agent_seed_v1"
	flag := key + flagPrefix
	if v, _, _ := s.m.pg.GetSetting(flag); v == "true" {
		return
	}
	defer func() { _ = s.m.pg.SetSetting(flag, "true") }() // 无论成功与否只尝试一次

	if exist, _ := s.m.pg.GetAgentByKey(key); exist != nil {
		return // key 已被占用(用户手建过)——不覆盖
	}
	a, err := s.m.pg.CreateAgent(key, name, desc)
	if err != nil {
		log.Printf("[%s] 创建 agent 失败: %v", key, err)
		return
	}
	if err := s.m.pg.SeedPromptIfEmpty(a.ID, prompt); err != nil {
		log.Printf("[%s] seed prompt 失败: %v", key, err)
	}
	if len(tools) > 0 {
		if err := s.m.pg.AddAgentToToolBinding(key, tools); err != nil {
			log.Printf("[%s] 绑定工具失败: %v", key, err)
		}
	}
}

// seedEnhancementAgents 预置三个「整理 Agent」增强角色（均在 UI 可编辑/可删除）：
//   - batch_reporter  批量汇总报告：聚合任务/范围的多漏洞+资产，生成汇总 Markdown
//   - asset_recon     资产测绘：主动登记资产+归入公司范围+触发 enrich 丰富化
//   - redteam         红队/横向：立足点攻击者视角，链式推进入口→立足→横向
func (s *Server) seedEnhancementAgents() {
	s.seedDynamicAgent(
		"batch_reporter", "批量汇总报告",
		"把指定任务/范围已确认的漏洞连同资产拓扑聚合为一份可交付的汇总 Markdown 报告。只读聚合与写作，不重复渗透。",
		agent.BatchReporterDefaultPrompt,
		[]string{
			"list_task_findings", "list_findings", "get_task_node_detail",
			"list_assets", "list_companies",
		},
	)
	s.seedDynamicAgent(
		"asset_recon", "资产测绘",
		"对授权目标做主动资产测绘：登记发现的域名/子域/IP/服务/端点、归入公司范围、核对覆盖面，并推动平台 enrich（DNS/httpx/katana/nuclei）完成丰富化。",
		agent.AssetReconDefaultPrompt,
		[]string{
			"list_assets", "insert_assets", "list_untested_assets",
			"add_company_scope", "list_companies",
		},
	)
	s.seedDynamicAgent(
		"redteam", "红队/横向",
		"红队视角渗透：把已确认弱点当入口，链式推进 入口→立足→横向移动→内网资产，对抗式自检，全程只登记真实证据。",
		agent.RedTeamDefaultPrompt,
		[]string{
			"list_assets", "insert_assets", "report_finding", "list_findings", "list_companies",
		},
	)
}
