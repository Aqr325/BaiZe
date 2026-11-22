// scenario.go — 可配置扫描工作流 + 自动化模式（借鉴 openEuler AET）。
//
// scenarios.json（随 exe 旁）定义命名扫描流水线：有序阶段（dns/http/crawl/
// nuclei）+ 每阶段确认点（""|auto|confirm）+ 场景级 automation 开关。运行一个
// 场景按序把各阶段入队 enrich，automation:true 时短路 confirm、无人值守推进，
// 并把决策追加到 scenario_decisions.log 供事后复核；有 confirm 且非 automation
// 时返回 awaiting_confirm，停在阶段边界等确认。
package server

import (
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Autumn-27/baize/config"
	"github.com/Autumn-27/baize/db"
	"github.com/Autumn-27/baize/enrich"
)

// ScenarioStage is one step of a scan pipeline.
type ScenarioStage struct {
	Kind    string         `json:"kind"`              // dns|http|crawl|nuclei
	Params  map[string]any `json:"params,omitempty"`  // optional per-stage params
	Confirm string         `json:"confirm,omitempty"` // ""|auto|confirm (hook point)
}

// Scenario is a reusable, ordered scan pipeline.
type Scenario struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Automation  bool            `json:"automation"` // 无人值守：短路 confirm + 决策留档
	Stages      []ScenarioStage `json:"stages"`
}

type scenarioConfig struct {
	Scenarios []Scenario `json:"scenarios"`
}

// builtinScenarios are the default pipelines so the feature works out of the box;
// user scenarios.json entries are appended after them (no override).
func builtinScenarios() []Scenario {
	return []Scenario{
		{
			Name:        "quick-recon",
			Description: "轻量侦察：HTTP 指纹 + katana 爬虫端点发现。适合单目标快速摸清面。",
			Automation:  true,
			Stages: []ScenarioStage{
				{Kind: "http"},
				{Kind: "crawl"},
			},
		},
		{
			Name:        "full-audit",
			Description: "完整审计：HTTP 指纹 → 爬虫端点 → nuclei 漏洞扫描。自动化运行，决策留档。",
			Automation:  true,
			Stages: []ScenarioStage{
				{Kind: "http"},
				{Kind: "crawl"},
				{Kind: "nuclei"},
			},
		},
		{
			Name:        "guided-audit",
			Description: "分阶段确认：每阶段后停在 confirm 边界等人工确认，适合逐层推进的授权测试。",
			Automation:  false,
			Stages: []ScenarioStage{
				{Kind: "http", Confirm: "confirm"},
				{Kind: "crawl", Confirm: "confirm"},
				{Kind: "nuclei", Confirm: "confirm"},
			},
		},
	}
}

// loadScenarios reads BaseDir()/scenarios.json and merges builtin defaults.
// A missing/malformed file yields only the builtins (no hard failure).
func loadScenarios() []Scenario {
	out := builtinScenarios()
	seen := map[string]bool{}
	for _, s := range out {
		seen[s.Name] = true
	}
	b, err := os.ReadFile(filepath.Join(config.BaseDir(), "scenarios.json"))
	if err != nil {
		return out
	}
	var cfg scenarioConfig
	if err := json.Unmarshal(b, &cfg); err != nil {
		log.Printf("[scenario] scenarios.json 解析失败（仅用内置场景）: %v", err)
		return out
	}
	for _, s := range cfg.Scenarios {
		if s.Name == "" || len(s.Stages) == 0 {
			continue // skip invalid
		}
		ok := true
		for _, st := range s.Stages {
			if !validScenarioKind(st.Kind) {
				ok = false
				break
			}
		}
		if !ok {
			log.Printf("[scenario] 场景 %q 含未知阶段类型，跳过", s.Name)
			continue
		}
		if seen[s.Name] {
			log.Printf("[scenario] 场景 %q 与内置重名，跳过（保留内置）", s.Name)
			continue
		}
		seen[s.Name] = true
		out = append(out, s)
	}
	return out
}

// validScenarioKind reports whether a stage kind maps to an enrich job.
func validScenarioKind(k string) bool {
	switch k {
	case "dns", "http", "crawl", "nuclei":
		return true
	}
	return false
}

// logScenarioDecision appends an automation-mode decision for post-hoc review.
func logScenarioDecision(line string) {
	path := filepath.Join(config.BaseDir(), "scenario_decisions.log")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer f.Close()
	_, _ = f.WriteString(time.Now().Format("2006-01-02 15:04:05") + " " + line + "\n")
}

// runScenarioResult reports how a scenario run was dispatched.
type runScenarioResult struct {
	Scenario        string   `json:"scenario"`
	Automation      bool     `json:"automation"`
	Queued          int      `json:"queued"`           // jobs dispatched this call
	AwaitingConfirm bool     `json:"awaiting_confirm"` // stopped at a confirm boundary
	PendingStage    string   `json:"pending_stage,omitempty"`
	Targets         []string `json:"targets"`
}

// runScenario orchestrates a scenario over targets. In automation mode every stage
// is enqueued and the decision logged; otherwise it stops at the first confirm
// boundary and returns AwaitingConfirm (the caller resumes on explicit confirm).
func runScenario(as *db.AssetStore, en *enrich.Engine, sc Scenario, targets []string) runScenarioResult {
	res := runScenarioResult{
		Scenario:   sc.Name,
		Automation: sc.Automation,
		Targets:    targets,
	}
	for _, stage := range sc.Stages {
		// Non-automation + confirm boundary → stop and wait. This is a workflow
		// decision independent of the engine, so it's evaluated first.
		if !sc.Automation && strings.EqualFold(stage.Confirm, "confirm") {
			res.AwaitingConfirm = true
			res.PendingStage = stage.Kind
			logScenarioDecision("scenario=" + sc.Name + " 停在确认边界 stage=" + stage.Kind)
			return res
		}
		if en == nil {
			continue // can't dispatch, but the workflow decision already stands
		}
		for _, t := range targets {
			if t == "" {
				continue
			}
			if enqueueScenarioStage(as, en, stage.Kind, t) {
				res.Queued++
			}
		}
		if sc.Automation {
			logScenarioDecision("scenario=" + sc.Name + " stage=" + stage.Kind +
				" targets=" + strings.Join(targets, ","))
		}
	}
	return res
}

// enqueueScenarioStage maps a stage kind + target URL to the enrich engine. It
// materializes the asset id via the idempotent UpsertHTTPService, then dispatches.
func enqueueScenarioStage(as *db.AssetStore, en *enrich.Engine, kind, rawURL string) bool {
	if en == nil || rawURL == "" {
		return false
	}
	id, err := scenarioAssetID(as, rawURL)
	if err != nil || id <= 0 {
		log.Printf("[scenario] 无法解析资产 %q: %v", rawURL, err)
		return false
	}
	switch kind {
	case "http":
		en.ProbeSite(id, rawURL)
	case "crawl":
		en.CrawlSite(id, rawURL)
	case "nuclei":
		en.ScanVulns(id, rawURL)
	case "dns":
		en.ResolveDomain(id, hostOfURL(rawURL))
	default:
		return false
	}
	return true
}

// scenarioAssetID materializes/returns the asset id for a URL via the idempotent
// upsert (creates the row on first sight, returns the existing id thereafter).
func scenarioAssetID(as *db.AssetStore, rawURL string) (int64, error) {
	if as == nil {
		return 0, nil
	}
	return as.UpsertHTTPService(db.UpsertHTTPServiceReq{URL: rawURL})
}

// hostOfURL extracts the hostname from a URL (or returns the input verbatim).
func hostOfURL(rawURL string) string {
	if strings.Contains(rawURL, "://") {
		if u, err := url.Parse(rawURL); err == nil {
			return u.Hostname()
		}
	}
	return rawURL
}

// ---- HTTP handlers ----

// listScenarios handles GET /api/enrich/scenarios.
func (s *Server) listScenarios(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, 200, map[string]any{"scenarios": loadScenarios()})
}

// runScenarioHandler handles POST /api/enrich/scenarios/run.
func (s *Server) runScenarioHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name    string   `json:"name"`
		Targets []string `json:"targets"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "无效请求体: "+err.Error())
		return
	}
	if req.Name == "" || len(req.Targets) == 0 {
		writeErr(w, 400, "需要 name 与至少一个 targets")
		return
	}
	var found *Scenario
	all := loadScenarios()
	for i := range all {
		if all[i].Name == req.Name {
			found = &all[i]
			break
		}
	}
	if found == nil {
		writeErr(w, 404, "未找到场景 "+req.Name)
		return
	}
	res := runScenario(s.m.assets, s.m.Enrich(), *found, req.Targets)
	writeJSON(w, 202, res)
}
