package enrich

import (
	"bufio"
	"context"
	"encoding/json"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/Autumn-27/baize/db"
)

// ScanVulns enqueues a nuclei template scan for a web asset (vulnerability
// discovery). rawURL is the site URL. Same RoE gating as ProbeSite/CrawlSite
// (the caller enforces scope) — this never scans out-of-scope targets.
//
// nuclei is an optional external CLI (not a Go dependency, to keep the binary
// lean): if the "nuclei" binary is not on PATH, the job degrades gracefully to
// a log hint instead of failing the whole engine.
func (e *Engine) ScanVulns(id int64, rawURL string) { e.enqueue(job{jobNuclei, id, rawURL}) }

// nucleiTimeout bounds a single nuclei run. Template scans are heavier than a
// plain probe, but we keep it bounded so a slow target can't wedge a worker.
const nucleiTimeout = 3 * time.Minute

// doNuclei runs the nuclei CLI against rawURL and folds its JSONL output back
// into the asset graph (matched URLs as endpoints) plus a per-hit severity log.
func (e *Engine) doNuclei(id int64, rawURL string) {
	if hostOf(rawURL) == "" {
		return
	}
	nucleiBin, err := exec.LookPath("nuclei")
	if err != nil {
		log.Printf("[enrich] nuclei 未安装，漏洞扫描跳过 %s (安装: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 后运行 nuclei -update-templates)", rawURL)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), nucleiTimeout)
	defer cancel()

	args := []string{"-u", rawURL, "-jsonl", "-silent", "-no-color"}
	if p := e.liveProxy(); p != "" {
		args = append(args, "-proxy", p)
	}
	cmd := exec.CommandContext(ctx, nucleiBin, args...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		log.Printf("[enrich] nuclei stdout 管道失败 %s: %v", rawURL, err)
		return
	}
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		log.Printf("[enrich] nuclei 启动失败 %s: %v", rawURL, err)
		return
	}
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 1<<20), 4<<20)
	for scanner.Scan() {
		e.handleNucleiLine(scanner.Text())
	}
	if err := cmd.Wait(); err != nil && ctx.Err() == nil {
		log.Printf("[enrich] nuclei 退出异常 %s: %v", rawURL, err)
	}
}

// nucleiHit mirrors the subset of nuclei's JSONL line we consume.
type nucleiHit struct {
	TemplateID string `json:"template-id"`
	Info       struct {
		Name     string `json:"name"`
		Severity string `json:"severity"`
	} `json:"info"`
	MatchedAt string `json:"matched-at"`
}

// handleNucleiLine folds one nuclei JSONL finding into the asset graph.
func (e *Engine) handleNucleiLine(line string) {
	if e == nil || e.as == nil {
		return
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return
	}
	var f nucleiHit
	if json.Unmarshal([]byte(line), &f) != nil {
		return
	}
	url := f.MatchedAt
	if url == "" {
		return
	}
	// Every matched URL is itself a discovered asset/endpoint worth keeping.
	_, _ = e.as.UpsertEndpoint(db.UpsertEndpointReq{
		URL:    url,
		Method: "GET",
	})
	sev := f.Info.Severity
	if sev == "" {
		sev = "info"
	}
	log.Printf("[enrich] nuclei 命中 [%s] %s (%s): %s", sev, url, f.TemplateID, f.Info.Name)
}
