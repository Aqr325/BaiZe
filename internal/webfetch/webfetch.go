// Adapted from github.com/Autumn-27/norma/tool/webfetch.go at v0.4.3.
// Keep the SDK tool metadata and fetch/render behavior; use BaiZe's explicit
// HTTP identity for both the proxy attempt and its direct fallback. This local
// adapter is needed until the SDK exposes request headers in actool.WebFetchConfig.
package webfetch

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"syscall"
	"time"

	"github.com/Autumn-27/baize/internal/httpidentity"
	actool "github.com/Autumn-27/norma/tool"
	"golang.org/x/net/html"
)

// New keeps the SDK's schema, permission checks and tool metadata.
func New(cfg actool.WebFetchConfig) actool.CoreTool {
	base := actool.NewWebFetch(cfg)
	return actool.Build(actool.Spec{
		Name: base.Name(), Description: base.Description(), Prompt: base.Prompt(),
		Schema: base.InputSchema(), Permissions: base.CheckPermissions,
		ReadOnly: base.IsReadOnly, Concurrent: base.IsConcurrencySafe,
		Run: webFetchRunner(cfg),
	})
}

const maxFetchBytes = 2 << 20 // 2 MiB

// isSensitiveFetchIP 判定 WebFetch 必须拒绝的目标 IP。
//
// 与其它出口守卫的刻意差异：这里放行环回与 RFC1918 私网。WebFetch 的 URL 由 AI
// 自主决定、目标本就是被测资产，本机靶场（127.0.0.1）和内网服务都是完全合法的
// 抓取对象，一刀切挡掉会让渗透测试直接不可用。只拒绝链路本地（含云厂商元数据
// 端点 169.254.169.254）、组播与未指定地址——它们没有任何正常抓取用途，却是
// prompt injection 诱导 AI 读取实例凭据的通道。
func isSensitiveFetchIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4 // IPv4-mapped IPv6（::ffff:169.254.169.254）还原后再判，避免绕过
	}
	return ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified()
}

// blockSensitiveDial 是拨号级 SSRF 守卫。Go 在拨号阶段把 address 传成 DNS 解析后
// 的真实 IP（已实测 localhost → 127.0.0.1 / [::1]），所以在此检查能覆盖域名重绑定
// 与重定向到链路本地这两类绕过——纯 URL 字符串层检查做不到这点。
func blockSensitiveDial(_, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	ip := net.ParseIP(host)
	if ip == nil { // Control 收到的应已是解析后的 IP；拿不到就拒绝，不放过
		return fmt.Errorf("webfetch: 无法解析拨号目标 %q", host)
	}
	if isSensitiveFetchIP(ip) {
		return fmt.Errorf("webfetch: 拒绝访问链路本地/组播地址 %s", ip)
	}
	return nil
}

// literalSensitiveHost 检查 URL 里的字面 IP 主机。拨号守卫只在直连时看得到目标，
// 配了代理时目标是代理去连的；这一层挡住「AI 直接把元数据 IP 写进 URL」经代理
// 出去的情形。域名目标仍由拨号守卫在解析后拦截，两层互补。
func literalSensitiveHost(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return false // 后续 http.NewRequest 会给出更准确的报错
	}
	host := strings.TrimSuffix(strings.TrimSpace(u.Hostname()), ".")
	if zone := strings.IndexByte(host, '%'); zone >= 0 { // IPv6 zone 不参与地址分类
		host = host[:zone]
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return false // 域名：交给 resolvedSensitiveHost 解析后判断，此处不能误拦
	}
	return isSensitiveFetchIP(ip)
}

// lookupFetchIPAddr is indirected so tests can simulate a hostname that resolves
// to a link-local address without touching the machine's DNS or any real target.
var lookupFetchIPAddr = net.DefaultResolver.LookupIPAddr

// resolvedSensitiveHost 在字面 IP 之外补一层 DNS 解析检查。配代理时拨号目标是代理，
// Dialer.Control 看不到最终目标，因此「域名解析到 169.254.169.254」这条绕过必须
// 在这里拦住：任一解析结果命中 isSensitiveFetchIP 即拒绝。
//
// 解析失败按 fail-closed 处置（记日志后拒绝）：本地解析不出来却由代理侧解析到元数据
// 地址是真实存在的绕过路径，宁可拒绝也不能放过。环回/RFC1918 仍按既有策略放行。
// host 为空、IPv6 zone、域名尾点都先归一化再处理。
func resolvedSensitiveHost(ctx context.Context, rawURL string) (bool, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true, err
	}
	host := strings.TrimSuffix(strings.TrimSpace(u.Hostname()), ".")
	if zone := strings.IndexByte(host, '%'); zone >= 0 { // IPv6 zone 不参与地址分类/解析
		host = host[:zone]
	}
	if host == "" {
		return true, fmt.Errorf("webfetch: URL 缺少主机 %q", rawURL)
	}
	if net.ParseIP(host) != nil {
		return false, nil // 字面 IP 由 literalSensitiveHost 判定，无需 DNS
	}
	addrs, err := lookupFetchIPAddr(ctx, host)
	if err != nil {
		log.Printf("webfetch: 解析主机 %q 失败，按 fail-closed 拒绝: %v", host, err)
		return true, err
	}
	for _, addr := range addrs {
		if isSensitiveFetchIP(addr.IP) {
			return true, nil
		}
	}
	return false, nil
}

// maxFetchRedirects 限制重定向跳数，防止无限循环（含被 injection 诱导的跳转链）。
const maxFetchRedirects = 5

// newFetchClient returns an HTTP client honoring the proxy / TLS config.
func newFetchClient(cfg actool.WebFetchConfig) *http.Client {
	tr := &http.Transport{}
	if cfg.Proxy != "" {
		if pu, err := url.Parse(cfg.Proxy); err == nil {
			tr.Proxy = http.ProxyURL(pu)
		}
	}
	// 挂拨号级守卫；main client 与 direct 回退都经此构造，一处覆盖全部出口。
	// 超时/KeepAlive 取 net/http 默认值，除守卫外不改变原有传输行为。
	tr.DialContext = (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   blockSensitiveDial,
	}).DialContext

	switch {
	case cfg.InsecureTLS:
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	case cfg.CACert != "":
		// Trust the proxy's CA in addition to the system roots, so certs it
		// re-signs verify while every other connection stays fully checked.
		if pem, err := os.ReadFile(cfg.CACert); err == nil {
			pool, _ := x509.SystemCertPool()
			if pool == nil {
				pool = x509.NewCertPool()
			}
			if pool.AppendCertsFromPEM(pem) {
				tr.TLSClientConfig = &tls.Config{RootCAs: pool}
			}
		}
	}
	// CheckRedirect 对每一跳做 SSRF 守卫。client.Do 默认跟随重定向，而配代理时
	// Dialer.Control 只看得到代理 IP、无法看到最终目标；这一层按 req.URL 检查字面
	// IP 与解析后 IP，覆盖 302 到元数据的绕过。direct 回退 client 也经此构造，
	// 守卫自动生效。
	return &http.Client{
		Transport: tr,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxFetchRedirects {
				return fmt.Errorf("webfetch: 重定向超过 %d 跳，拒绝", maxFetchRedirects)
			}
			if literalSensitiveHost(req.URL.String()) {
				return fmt.Errorf("webfetch: 拒绝重定向到链路本地/组播地址 %s", req.URL.Host)
			}
			blocked, err := resolvedSensitiveHost(req.Context(), req.URL.String())
			if blocked {
				if err != nil {
					return fmt.Errorf("webfetch: 无法校验重定向目标 %q，拒绝: %v", req.URL.Host, err)
				}
				return fmt.Errorf("webfetch: 重定向目标 %q 解析到受限地址，拒绝", req.URL.Host)
			}
			return nil
		},
	}
}

// proxyLikelyErr reports whether a fetch error is the kind a recording/MITM proxy
// introduces — a closed tunnel (EOF / connection reset), a failed CONNECT, or a
// TLS/HTTP2 mismatch — so a direct (no-proxy) retry may succeed. Name-resolution
// failures and caller cancellation/timeout are target- or caller-side problems a
// direct retry won't fix, so those return false (no retry).
func proxyLikelyErr(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	for _, n := range []string{"no such host", "context canceled", "context deadline", "timeout"} {
		if strings.Contains(s, n) {
			return false
		}
	}
	for _, p := range []string{
		"eof", "connection reset", "connection refused", "proxyconnect",
		"broken pipe", "forcibly closed", "malformed", "http2", "http/2",
		"tls:", "protocol error",
	} {
		if strings.Contains(s, p) {
			return true
		}
	}
	return false
}

// staticAssetExts are file extensions WebFetch refuses: linked resources (scripts,
// styles, source maps, images, fonts, media, wasm) that are not page content.
var staticAssetExts = map[string]bool{
	".js": true, ".mjs": true, ".cjs": true, ".css": true, ".map": true,
	".png": true, ".jpg": true, ".jpeg": true, ".gif": true, ".svg": true,
	".webp": true, ".avif": true, ".ico": true, ".bmp": true,
	".woff": true, ".woff2": true, ".ttf": true, ".otf": true, ".eot": true,
	".wasm": true, ".mp4": true, ".webm": true, ".mp3": true, ".wav": true, ".ogg": true,
}

// staticAssetExt returns the offending extension (with dot) if rawURL points at a
// static asset, or "" otherwise. The query string and fragment are ignored, so
// "/app.js?v=3" is still caught.
func staticAssetExt(rawURL string) string {
	path := rawURL
	if u, err := url.Parse(rawURL); err == nil {
		path = u.Path
	}
	if i := strings.LastIndexByte(path, '/'); i >= 0 {
		path = path[i+1:] // last segment only
	}
	dot := strings.LastIndexByte(path, '.')
	if dot < 0 {
		return ""
	}
	if ext := strings.ToLower(path[dot:]); staticAssetExts[ext] {
		return ext
	}
	return ""
}

func webFetchRunner(cfg actool.WebFetchConfig) func(context.Context, json.RawMessage, *actool.ToolContext) (actool.Result, error) {
	client := newFetchClient(cfg)
	// direct is the no-proxy fallback used when a proxied fetch fails for a
	// proxy-caused reason (closed tunnel / failed CONNECT / TLS or HTTP2 mismatch):
	// it bypasses the configured proxy so a recording/MITM hiccup doesn't fail an
	// otherwise-reachable URL. nil when no proxy is configured (nothing to bypass).
	var direct *http.Client
	if cfg.Proxy != "" {
		direct = newFetchClient(actool.WebFetchConfig{InsecureTLS: cfg.InsecureTLS})
	}
	return func(ctx context.Context, input json.RawMessage, _ *actool.ToolContext) (actool.Result, error) {
		var in struct {
			URL     string `json:"url"`
			Extract bool   `json:"extract"`
		}
		if err := json.Unmarshal(input, &in); err != nil {
			return actool.Result{}, err
		}
		if !strings.HasPrefix(in.URL, "http://") && !strings.HasPrefix(in.URL, "https://") {
			return actool.Errorf("Error: url must start with http:// or https://"), nil
		}
		if literalSensitiveHost(in.URL) {
			return actool.Errorf("Error: url resolves to a blocked address (link-local/multicast, e.g. cloud metadata 169.254.169.254)"), nil
		}
		if ext := staticAssetExt(in.URL); ext != "" {
			return actool.Errorf("Error: WebFetch does not fetch static assets (" + ext + " file). It reads HTML pages, documentation, and API responses — not linked resources like scripts, styles, images, or fonts. Fetch the page that references this asset instead."), nil
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		// 初始 URL 也做解析后 IP 检查：直连时 Dialer.Control 会拦，但配代理时它看不到
		// 最终目标，域名若解析到元数据地址就会绕过字面检查。解析有延迟，可接受。
		if blocked, err := resolvedSensitiveHost(cctx, in.URL); blocked {
			if err != nil {
				return actool.Errorf("Error: cannot verify url host, refusing: " + err.Error()), nil
			}
			return actool.Errorf("Error: url resolves to a blocked address (link-local/multicast, e.g. cloud metadata 169.254.169.254)"), nil
		}
		req, err := http.NewRequestWithContext(cctx, http.MethodGet, in.URL, nil)
		if err != nil {
			return actool.Errorf("Error: " + err.Error()), nil
		}
		userAgent := httpidentity.UserAgent()
		req.Header.Set("User-Agent", userAgent)
		resp, err := client.Do(req)
		// One direct retry when the proxied attempt failed for a proxy-caused reason.
		// A non-proxy error (bad host, caller timeout/cancel) is returned as-is — a
		// direct retry wouldn't fix it. The direct response is NOT captured by the proxy.
		if err != nil && direct != nil && proxyLikelyErr(err) {
			if r2, e2 := http.NewRequestWithContext(cctx, http.MethodGet, in.URL, nil); e2 == nil {
				r2.Header.Set("User-Agent", userAgent)
				if resp2, err2 := direct.Do(r2); err2 == nil {
					resp, err = resp2, nil
				} else {
					err = err2 // surface the direct failure (more representative of the target)
				}
			}
		}
		if err != nil {
			return actool.Errorf("Error fetching URL: " + err.Error()), nil
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxFetchBytes))

		header := fmt.Sprintf("[%d %s] %s\n", resp.StatusCode, http.StatusText(resp.StatusCode), in.URL)
		// Cheap fingerprint signal that HTML→Markdown would otherwise hide.
		if sv := resp.Header.Get("Server"); sv != "" {
			header += "Server: " + sv + "\n"
		}
		if xp := resp.Header.Get("X-Powered-By"); xp != "" {
			header += "X-Powered-By: " + xp + "\n"
		}

		var out string
		if strings.Contains(strings.ToLower(resp.Header.Get("content-type")), "html") {
			doc, perr := html.Parse(strings.NewReader(string(body)))
			if perr != nil { // html.Parse is lenient; this is effectively unreachable
				out = string(body)
			} else {
				out = htmlToMarkdown(doc)
				if in.Extract {
					if recon := extractRecon(doc); recon != "" {
						out += "\n\n" + recon
					}
				}
			}
		} else {
			out = string(body)
		}
		return actool.Text(truncate(header+strings.TrimSpace(out), 50000)), nil
	}
}

var (
	reWS         = regexp.MustCompile(`[ \t]+`)
	reLineTrim   = regexp.MustCompile(` *\n *`) // strip spaces hugging a newline
	reBlankLines = regexp.MustCompile(`\n{2,}`) // collapse blank lines → one newline
	// reEndpoint matches quoted absolute URLs and root-relative paths in inline JS.
	reEndpoint = regexp.MustCompile("[\"'`](https?://[^\"'`\\s]+|/[A-Za-z0-9._~$&'()*+,;=:@%/?#\\[\\]-]{2,})[\"'`]")
)

// skipMarkdown are elements whose subtree carries no readable prose.
var skipMarkdown = map[string]bool{"script": true, "style": true, "noscript": true, "svg": true, "template": true}

// htmlToMarkdown renders the visible content of a parsed document as Markdown.
// Text nodes are already entity-decoded by the parser, so no unescaping is needed.
func htmlToMarkdown(doc *html.Node) string {
	var b strings.Builder
	renderNode(&b, doc)
	s := reWS.ReplaceAllString(b.String(), " ")
	s = reLineTrim.ReplaceAllString(s, "\n")   // drop indentation / trailing spaces per line
	s = reBlankLines.ReplaceAllString(s, "\n") // no blank lines — compact, token-lean output
	return strings.TrimSpace(s)
}

func renderNode(b *strings.Builder, n *html.Node) {
	switch n.Type {
	case html.TextNode:
		b.WriteString(strings.ReplaceAll(n.Data, "\n", " "))
		return
	case html.ElementNode:
		if skipMarkdown[n.Data] {
			return
		}
	default:
		if n.Type != html.DocumentNode {
			return
		}
	}
	tag := ""
	if n.Type == html.ElementNode {
		tag = n.Data
	}
	switch tag {
	case "h1", "h2", "h3", "h4", "h5", "h6":
		b.WriteString("\n\n" + strings.Repeat("#", int(tag[1]-'0')) + " ")
		renderChildren(b, n)
		b.WriteString("\n\n")
	case "title":
		b.WriteString("\n\n# ")
		renderChildren(b, n)
		b.WriteString("\n\n")
	case "p", "div", "section", "article", "header", "footer", "main", "ul", "ol", "table", "tr", "blockquote":
		b.WriteString("\n\n")
		renderChildren(b, n)
		b.WriteString("\n\n")
	case "br":
		b.WriteString("\n")
	case "hr":
		b.WriteString("\n\n---\n\n")
	case "li":
		b.WriteString("\n- ")
		renderChildren(b, n)
	case "a":
		var inner strings.Builder
		renderChildren(&inner, n)
		text := strings.TrimSpace(inner.String())
		if href := attr(n, "href"); href != "" && text != "" {
			fmt.Fprintf(b, "[%s](%s)", text, href)
		} else {
			b.WriteString(text)
		}
	case "img":
		if src := attr(n, "src"); src != "" {
			fmt.Fprintf(b, "![%s](%s)", attr(n, "alt"), src)
		}
	case "strong", "b":
		b.WriteString("**")
		renderChildren(b, n)
		b.WriteString("**")
	case "em", "i":
		b.WriteString("*")
		renderChildren(b, n)
		b.WriteString("*")
	case "code":
		b.WriteString("`")
		renderChildren(b, n)
		b.WriteString("`")
	case "pre":
		var inner strings.Builder
		textOnly(&inner, n)
		b.WriteString("\n\n```\n" + strings.TrimSpace(inner.String()) + "\n```\n\n")
	default:
		renderChildren(b, n)
	}
}

func renderChildren(b *strings.Builder, n *html.Node) {
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		renderNode(b, c)
	}
}

// extractRecon walks the document for security-relevant signal that Markdown
// rendering drops: comments, script sources, inline endpoints, forms, meta, links.
func extractRecon(doc *html.Node) string {
	var comments, scriptSrcs, inlineEndpoints, forms, metas, links []string
	seenLink := map[string]bool{}

	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		switch n.Type {
		case html.CommentNode:
			if c := oneLine(n.Data, 300); c != "" {
				comments = append(comments, c)
			}
		case html.ElementNode:
			switch n.Data {
			case "script":
				if src := attr(n, "src"); src != "" {
					scriptSrcs = append(scriptSrcs, src)
				} else {
					var body strings.Builder
					textOnly(&body, n)
					for _, m := range reEndpoint.FindAllStringSubmatch(body.String(), 40) {
						inlineEndpoints = append(inlineEndpoints, m[1])
					}
				}
			case "form":
				forms = append(forms, describeForm(n))
			case "meta":
				name := attr(n, "name")
				if name == "" {
					name = attr(n, "property")
				}
				if content := attr(n, "content"); name != "" && content != "" {
					metas = append(metas, name+"="+oneLine(content, 120))
				}
			case "a", "link":
				if h := attr(n, "href"); h != "" && !seenLink[h] {
					seenLink[h] = true
					links = append(links, h)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(doc)

	var b strings.Builder
	b.WriteString("=== RECON ===")
	reconSection(&b, "COMMENTS", comments)
	reconSection(&b, "SCRIPTS (src)", dedup(scriptSrcs))
	reconSection(&b, "INLINE ENDPOINTS", dedup(inlineEndpoints))
	reconSection(&b, "FORMS", forms)
	reconSection(&b, "META", metas)
	reconSection(&b, "LINKS", capSlice(links, 100))
	if b.Len() == len("=== RECON ===") {
		return "" // nothing worth reporting
	}
	return b.String()
}

// describeForm summarizes a <form> as "METHOD action → name(type[=value]) …".
// Hidden inputs keep their value (CSRF tokens, parameter defaults matter in recon).
func describeForm(form *html.Node) string {
	method := strings.ToUpper(attr(form, "method"))
	if method == "" {
		method = "GET"
	}
	var inputs []string
	var walk func(n *html.Node)
	walk = func(n *html.Node) {
		if n.Type == html.ElementNode {
			switch n.Data {
			case "input", "textarea", "select":
				typ := attr(n, "type")
				if typ == "" {
					typ = n.Data
				}
				desc := attr(n, "name") + "(" + typ
				if typ == "hidden" {
					if v := attr(n, "value"); v != "" {
						desc += "=" + oneLine(v, 60)
					}
				}
				inputs = append(inputs, desc+")")
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			walk(c)
		}
	}
	walk(form)
	return fmt.Sprintf("%s %s → %s", method, attr(form, "action"), strings.Join(inputs, " "))
}

// --- small helpers ---

func attr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func textOnly(b *strings.Builder, n *html.Node) {
	if n.Type == html.TextNode {
		b.WriteString(n.Data)
		return
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		textOnly(b, c)
	}
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	// 按 rune 截断：中文等占 3 字节，按字节切会把 UTF-8 序列切成非法字节。
	r := []rune(s)
	if len(r) > max {
		return string(r[:max]) + "…"
	}
	return s
}

func reconSection(b *strings.Builder, title string, items []string) {
	if len(items) == 0 {
		return
	}
	b.WriteString("\n\n## " + title + "\n")
	for _, it := range items {
		b.WriteString("- " + it + "\n")
	}
}

func dedup(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func capSlice(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return append(in[:n:n], fmt.Sprintf("… (%d more)", len(in)-n))
}

// truncate retains the SDK's head/tail output limit. 按 rune 截断以免把中文切成
// 非法 UTF-8 交给 LLM（参考 agent/delegation/lifecycle.go 的 clipString）。
func truncate(s string, max int) string {
	r := []rune(s)
	if max <= 0 || len(r) <= max {
		return s
	}
	half := max / 2
	return string(r[:half]) + fmt.Sprintf("\n\n... [%d characters truncated] ...\n\n", len(r)-max) + string(r[len(r)-half:])
}
