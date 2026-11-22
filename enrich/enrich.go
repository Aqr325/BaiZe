// Package enrich is the engine-side (non-AI) asset auto-completion layer described
// in docs/资产模型与自动关联设计.md §5: an async worker pool that resolves domains
// (dnsx) and probes web assets (HTTP, through the recording proxy) and writes the
// results back into the asset graph — creating IP/port nodes, resolves/exposes
// edges, and filling attrs.dns / attrs.http. DNS is ungated; HTTP probing is gated
// by RoE (§5.2).
package enrich

import (
	"crypto/tls"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/Autumn-27/baize/db"

	"github.com/miekg/dns"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	goflags "github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/httpx/runner"
	katanaengine "github.com/projectdiscovery/katana/pkg/engine/standard"
	katanaoutput "github.com/projectdiscovery/katana/pkg/output"
	katanatypes "github.com/projectdiscovery/katana/pkg/types"
)

type jobKind int

const (
	jobDNS    jobKind = iota // resolve a domain
	jobHTTP                  // probe a web asset (site) — httpx, tech fingerprint
	jobCrawl                 // crawl a web asset (site) — katana, endpoint discovery
	jobNuclei                // vuln scan (site) — nuclei CLI, optional external binary
)

type job struct {
	kind jobKind
	id   int64  // asset id (domain for DNS, site for HTTP/crawl)
	arg  string // host (DNS) or url (HTTP/crawl)
}

// Engine owns the resolver, the proxy-routed HTTP client, and the worker pool.
type Engine struct {
	as     *db.AssetStore
	resolv *dnsx.DNSX
	client *http.Client
	proxy  func() string // live recording-proxy address, shared with httpx/katana

	jobs   chan job
	cool   sync.Map         // dedup/cooldown: "kind:id" -> time.Time (last run)
	ckpt   *checkpointStore // disk-backed progress journal (断点恢复)
	once   sync.Once
	closed chan struct{}
}

const (
	cooldown    = 5 * time.Minute
	httpTimeout = 12 * time.Second
	queueSize   = 1024
)

// New builds the engine. proxy() returns the recording-proxy address to route HTTP
// probes through (so they land in the traffic store), evaluated per request so the
// runtime traffic-capture toggle takes effect live; "" = direct. Returns a usable
// engine even if the resolver fails to init (DNS becomes a no-op).
func New(as *db.AssetStore, proxy func() string, workers int) *Engine {
	if workers <= 0 {
		workers = 4
	}
	resolv, err := dnsx.New(dnsx.Options{
		BaseResolvers: dnsx.DefaultResolvers,
		MaxRetries:    3,
		QuestionTypes: []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME},
		Timeout:       4 * time.Second,
	})
	if err != nil {
		log.Printf("[enrich] dnsx 初始化失败，DNS 解析停用：%v", err)
		resolv = nil
	}
	e := &Engine{
		as:     as,
		resolv: resolv,
		client: buildClient(proxy),
		proxy:  proxy,
		jobs:   make(chan job, queueSize),
		ckpt:   newCheckpointStore(),
		closed: make(chan struct{}),
	}
	for i := 0; i < workers; i++ {
		go e.worker()
	}
	return e
}

// buildClient returns an HTTP client that dials via the recording proxy (resolved
// per-request via proxy(), so the traffic-capture toggle applies live) and skips
// TLS verification (the proxy re-signs with its MITM CA; targets are often
// self-signed — this is a pentest probe).
func buildClient(proxy func() string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		DisableKeepAlives:   true,
		TLSHandshakeTimeout: httpTimeout,
	}
	if proxy != nil {
		tr.Proxy = func(*http.Request) (*url.URL, error) {
			p := proxy()
			if p == "" {
				return nil, nil // direct
			}
			return url.Parse(p)
		}
	}
	return &http.Client{
		Transport: tr,
		Timeout:   httpTimeout,
		// cap redirects; keep them within scope by re-checking at probe time
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// ResolveDomain enqueues a DNS resolution for a domain asset (ungated). host is the
// FQDN. No-op for an empty engine.
func (e *Engine) ResolveDomain(id int64, host string) { e.enqueue(job{jobDNS, id, host}) }

// ProbeSite enqueues an HTTP probe for a web-asset (site). rawURL is the site URL.
func (e *Engine) ProbeSite(id int64, rawURL string) { e.enqueue(job{jobHTTP, id, rawURL}) }

// CrawlSite enqueues a katana crawl for a web-asset (site), discovering endpoints.
// rawURL is the site URL. Same RoE gating as ProbeSite (the caller enforces scope).
func (e *Engine) CrawlSite(id int64, rawURL string) { e.enqueue(job{jobCrawl, id, rawURL}) }

func (e *Engine) enqueue(j job) {
	if e == nil || id0(j.id) || j.arg == "" {
		return
	}
	select {
	case e.jobs <- j:
	default: // queue full → drop (best-effort enrichment)
		log.Printf("[enrich] 队列已满，丢弃任务 kind=%d id=%d", j.kind, j.id)
	}
}

func id0(id int64) bool { return id <= 0 }

// Close stops the workers (idempotent) and flushes the checkpoint journal.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.once.Do(func() { close(e.closed) })
	if e.ckpt != nil {
		e.ckpt.save()
	}
}

// ResumeInterrupted re-enqueues jobs that were marked running when the process
// last exited (a restart mid-work). The upsert targets are idempotent, so replay
// is safe. Call once after New (before accepting new work) to pick up where the
// previous run stopped.
func (e *Engine) ResumeInterrupted() {
	if e == nil || e.ckpt == nil {
		return
	}
	for _, j := range e.ckpt.interrupted() {
		log.Printf("[enrich] 断点恢复：重新入队 kind=%d id=%d %s", j.kind, j.id, j.arg)
		e.enqueue(j)
	}
}

func (e *Engine) worker() {
	for {
		select {
		case <-e.closed:
			return
		case j := <-e.jobs:
			if e.onCooldown(j) {
				continue
			}
			if e.ckpt != nil {
				e.ckpt.markRunning(j)
			}
			switch j.kind {
			case jobDNS:
				e.doDNS(j.id, j.arg)
			case jobHTTP:
				e.doHTTP(j.id, j.arg)
			case jobCrawl:
				e.doCrawl(j.id, j.arg)
			case jobNuclei:
				e.doNuclei(j.id, j.arg)
			}
			if e.ckpt != nil {
				e.ckpt.markDone(j.kind, j.id)
			}
		}
	}
}

// onCooldown returns true (skip) if this (kind,id) ran within the cooldown window.
// The checkpoint journal makes this survive a restart: a job that completed within
// cooldown is not re-run, while an interrupted (running) one is resumed instead.
func (e *Engine) onCooldown(j job) bool {
	if e.ckpt != nil && e.ckpt.doneRecently(j.kind, j.id) {
		return true
	}
	key := string(rune(j.kind)) + ":" + itoa(j.id)
	if v, ok := e.cool.Load(key); ok {
		if t, ok := v.(time.Time); ok && time.Since(t) < cooldown {
			return true
		}
	}
	e.cool.Store(key, time.Now())
	return false
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// ---- DNS ----

func (e *Engine) doDNS(id int64, host string) {
	if e.resolv == nil {
		return
	}
	data, err := e.resolv.QueryMultiple(host)
	if err != nil || data == nil {
		return
	}
	ips := uniq(append(append([]string{}, data.A...), data.AAAA...))
	// Upsert resolved IPs into the asset store.
	for _, ip := range ips {
		_, _ = e.as.UpsertIP(db.UpsertIPReq{
			IP:           ip,
			BoundDomains: []string{host},
		})
	}
	// Record A records as subdomains if host looks like a subdomain.
	for _, a := range data.A {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "A",
			RecordValue: []string{a},
		})
	}
	for _, aaaa := range data.AAAA {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "AAAA",
			RecordValue: []string{aaaa},
		})
	}
	for _, cname := range data.CNAME {
		_, _ = e.as.UpsertSubdomain(db.UpsertSubdomainReq{
			Domain:      host,
			RecordType:  "CNAME",
			RecordValue: []string{cname},
		})
	}
}

// ---- HTTP probe ----

// doHTTP probes a web asset with the httpx library (replacing the former
// hand-rolled single-request probe). It surfaces the technical fingerprint that
// the old probe lacked: Technologies (wappalyzer), favicon hash, response
// headers, status, title, and content length. httpx dials through the recording
// proxy when one is active (Options.Proxy), so the traffic stays in the store.
func (e *Engine) doHTTP(id int64, rawURL string) {
	if hostOf(rawURL) == "" {
		return
	}
	options := runner.Options{
		Methods:         "GET",
		InputTargetHost: goflags.StringSlice{rawURL},
		Timeout:         10,
		OnResult: func(r runner.Result) {
			if r.Err != nil {
				return
			}
			e.recordHTTP(r)
		},
	}
	if p := e.liveProxy(); p != "" {
		options.Proxy = p
	}
	if err := options.ValidateOptions(); err != nil {
		log.Printf("[enrich] httpx 选项校验失败 %s: %v", rawURL, err)
		return
	}
	hx, err := runner.New(&options)
	if err != nil {
		log.Printf("[enrich] httpx 初始化失败 %s: %v", rawURL, err)
		return
	}
	defer hx.Close()
	hx.RunEnumeration()
}

// recordHTTP writes one httpx Result into the asset store, filling the tech
// fingerprint fields (Technologies / favicon / headers) the old probe skipped.
func (e *Engine) recordHTTP(r runner.Result) {
	if e == nil || e.as == nil {
		return
	}
	u := r.URL
	if u == "" {
		u = r.Input
	}
	if u == "" {
		return
	}
	statusCode := r.StatusCode
	bodyLen := int64(r.ContentLength)
	_, _ = e.as.UpsertHTTPService(db.UpsertHTTPServiceReq{
		URL:           u,
		Technologies:  r.Technologies,
		FaviconMMH3:   r.FavIconMMH3,
		StatusCode:    &statusCode,
		ContentLength: &bodyLen,
		PageTitle:     r.Title,
		IP:            hostOf(u),
	})
}

// doCrawl runs a katana standard (non-headless) crawl over a web asset to
// discover endpoints (URLs/methods). Found URLs are upserted as endpoint assets.
// katana's high-level runner lives in internal/ (not importable), so we use the
// public pkg/engine/standard crawler. Same proxy path as doHTTP.
func (e *Engine) doCrawl(id int64, rawURL string) {
	if hostOf(rawURL) == "" {
		return
	}
	opts := katanatypes.Options{
		URLs:     goflags.StringSlice{rawURL},
		MaxDepth: 3,
		Timeout:  10,
		OnResult: func(res katanaoutput.Result) {
			if e.as == nil || res.Request == nil || res.Request.URL == "" {
				return
			}
			method := res.Request.Method
			if method == "" {
				method = "GET"
			}
			_, _ = e.as.UpsertEndpoint(db.UpsertEndpointReq{
				URL:    res.Request.URL,
				Method: method,
			})
		},
	}
	if p := e.liveProxy(); p != "" {
		opts.Proxy = p
	}
	crawlerOptions, err := katanatypes.NewCrawlerOptions(&opts)
	if err != nil {
		log.Printf("[enrich] katana 选项构造失败 %s: %v", rawURL, err)
		return
	}
	crawler, err := katanaengine.New(crawlerOptions)
	if err != nil {
		log.Printf("[enrich] katana 初始化失败 %s: %v", rawURL, err)
		return
	}
	defer crawler.Close()
	if err := crawler.Crawl(rawURL); err != nil {
		log.Printf("[enrich] katana 爬取失败 %s: %v", rawURL, err)
	}
}

// liveProxy resolves the recording-proxy address at call time (so the runtime
// traffic-capture toggle applies live), returning "" for direct.
func (e *Engine) liveProxy() string {
	if e.proxy == nil {
		return ""
	}
	return e.proxy()
}

func hostOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Hostname()
}

func isBlank(v any) bool {
	switch x := v.(type) {
	case nil:
		return true
	case string:
		return x == ""
	case float64:
		return x == 0
	case int:
		return x == 0
	}
	return false
}

func uniq(in []string) []string {
	seen := map[string]struct{}{}
	out := in[:0]
	for _, s := range in {
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}
