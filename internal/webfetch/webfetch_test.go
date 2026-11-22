package webfetch

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"unicode/utf8"

	actool "github.com/Autumn-27/norma/tool"
)

func callFetch(t *testing.T, tool actool.CoreTool, target string, extract bool) actool.Result {
	t.Helper()
	input, err := json.Marshal(map[string]any{"url": target, "extract": extract})
	if err != nil {
		t.Fatal(err)
	}
	result, err := tool.Call(context.Background(), input, nil)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestIdentityAcrossRoutes(t *testing.T) {
	for _, ua := range []string{"", "Captured-UA/1.0"} {
		for _, route := range []string{"direct", "proxy", "fallback"} {
			t.Run(route+"/"+ua, func(t *testing.T) {
				t.Setenv("ARTEX_HTTP_USER_AGENT", ua)
				var targetCalls, proxyCalls atomic.Int32
				var mu sync.Mutex
				var selected string
				checkUA := func(r *http.Request) {
					mu.Lock()
					defer mu.Unlock()
					got := r.UserAgent()
					if ua == "" && !strings.HasPrefix(got, "Mozilla/5.0 ") {
						t.Errorf("random UA missing: %q", got)
					} else if ua != "" && got != ua {
						t.Errorf("User-Agent = %q, want %q", got, ua)
					}
					if selected != "" && selected != got {
						t.Errorf("redirect/retry UA changed from %q to %q", selected, got)
					}
					selected = got
				}
				target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					targetCalls.Add(1)
					checkUA(r)
					if r.URL.Path == "/start" {
						http.Redirect(w, r, "/page", http.StatusFound)
						return
					}
					w.Header().Set("Content-Type", "text/html")
					fmt.Fprint(w, `<h1>Page</h1><!--keep--><script src="/app.js"></script><form action="/submit"><input name="csrf" type="hidden" value="token"></form>`)
				}))
				defer target.Close()
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					proxyCalls.Add(1)
					checkUA(r)
					if route == "fallback" {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						conn.Close() // Deterministic EOF, causing the SDK-compatible retry.
						return
					}
					req := r.Clone(r.Context())
					req.RequestURI = ""
					// A forwarding proxy must preserve absence, like ARTEX's sink.
					if _, present := req.Header["User-Agent"]; !present {
						req.Header.Set("User-Agent", "")
					}
					resp, err := target.Client().Do(req)
					if err != nil {
						t.Error(err)
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					for key, values := range resp.Header {
						w.Header()[key] = values
					}
					w.WriteHeader(resp.StatusCode)
					io.Copy(w, resp.Body)
				}))
				defer proxy.Close()
				cfg := actool.WebFetchConfig{}
				if route != "direct" {
					cfg.Proxy = proxy.URL
				}
				result := callFetch(t, New(cfg), target.URL+"/start", true)
				for _, want := range []string{"[200 OK]", "# Page", "=== RECON ===", "keep", "/app.js", "csrf(hidden=token)"} {
					if result.IsError || !strings.Contains(result.Flatten(), want) {
						t.Fatalf("missing %q in result: %+v", want, result)
					}
				}
				if targetCalls.Load() != 2 {
					t.Errorf("target calls = %d, want 2", targetCalls.Load())
				}
				if route != "direct" && proxyCalls.Load() == 0 {
					t.Error("configured proxy was bypassed")
				}
			})
		}
	}
}

func TestTLSAndStaticAssetGuard(t *testing.T) {
	t.Setenv("ARTEX_HTTP_USER_AGENT", "Captured-UA/1.0")
	var calls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.UserAgent() != "Captured-UA/1.0" {
			t.Errorf("User-Agent = %q", r.UserAgent())
		}
		fmt.Fprint(w, "verified")
	}))
	defer server.Close()
	certPath := filepath.Join(t.TempDir(), "ca.pem")
	cert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	if err := os.WriteFile(certPath, cert, 0600); err != nil {
		t.Fatal(err)
	}
	tool := New(actool.WebFetchConfig{CACert: certPath})
	if result := callFetch(t, tool, server.URL, false); result.IsError || !strings.Contains(result.Flatten(), "verified") {
		t.Fatalf("CA trust lost: %+v", result)
	}
	if result := callFetch(t, tool, server.URL+"/app.js?v=1", false); !result.IsError {
		t.Fatalf("static asset guard lost: %+v", result)
	}
	if calls.Load() != 1 {
		t.Errorf("static asset triggered network request: calls = %d", calls.Load())
	}
}

func TestIdentitySelectedForEachCall(t *testing.T) {
	t.Setenv("ARTEX_HTTP_USER_AGENT", "Before-Tool-Creation")
	tool := New(actool.WebFetchConfig{})
	seen := make(chan string, 2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.UserAgent()
		fmt.Fprint(w, "ok")
	}))
	defer server.Close()
	for _, want := range []string{"First-Call", "Second-Call"} {
		t.Setenv("ARTEX_HTTP_USER_AGENT", want)
		if result := callFetch(t, tool, server.URL, false); result.IsError {
			t.Fatal(result.Flatten())
		}
		if got := <-seen; got != want {
			t.Fatalf("identity cached across calls: got %q, want %q", got, want)
		}
	}
}

func TestSDKMetadataPreserved(t *testing.T) {
	base := actool.NewWebFetch(actool.WebFetchConfig{})
	local := New(actool.WebFetchConfig{})
	if local.Name() != base.Name() || local.Description() != base.Description() || !reflect.DeepEqual(local.InputSchema(), base.InputSchema()) {
		t.Fatal("SDK tool contract changed")
	}
}

// TestSensitiveIPClassification 锁定守卫的放行/拒绝边界：链路本地/组播/未指定地址
// 必须拒绝，环回与 RFC1918 必须放行（渗透测试要用本机靶场和内网）。
func TestSensitiveIPClassification(t *testing.T) {
	blocked := []string{
		"169.254.169.254", "169.254.1.1", "224.0.0.1", "239.255.255.250",
		"0.0.0.0", "fe80::1", "ff02::1", "::",
		"::ffff:169.254.169.254", // IPv4-mapped IPv6 不能绕过
	}
	for _, s := range blocked {
		if ip := net.ParseIP(s); !isSensitiveFetchIP(ip) {
			t.Errorf("isSensitiveFetchIP(%s) = false, want true", s)
		}
	}
	allowed := []string{"127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "::1"}
	for _, s := range allowed {
		if ip := net.ParseIP(s); isSensitiveFetchIP(ip) {
			t.Errorf("isSensitiveFetchIP(%s) = true, want false", s)
		}
	}
	if !isSensitiveFetchIP(nil) {
		t.Error("nil IP 应视为受限")
	}

	// literalSensitiveHost 覆盖 URL 字符串层，含 zone 与尾点的归一化。
	for _, tc := range []struct {
		url  string
		want bool
	}{
		{"http://169.254.169.254/latest/meta-data/", true},
		{"http://[fe80::1%25eth0]/", true},
		{"http://169.254.169.254./x", true}, // 域名尾点
		{"http://127.0.0.1:8080/", false},
		{"http://10.0.0.1/", false},
		{"http://example.com/", false}, // 域名交给解析层
		{"not a url", false},
	} {
		if got := literalSensitiveHost(tc.url); got != tc.want {
			t.Errorf("literalSensitiveHost(%q) = %v, want %v", tc.url, got, tc.want)
		}
	}
}

// TestResolvedSensitiveHost 通过替换 lookupFetchIPAddr 模拟域名解析，无需真实 DNS
// 或云元数据端点，即可验证「域名→链路本地 IP」「解析失败 fail-closed」两条路径。
func TestResolvedSensitiveHost(t *testing.T) {
	orig := lookupFetchIPAddr
	defer func() { lookupFetchIPAddr = orig }()

	ips := func(vals ...string) []net.IPAddr {
		out := make([]net.IPAddr, 0, len(vals))
		for _, v := range vals {
			out = append(out, net.IPAddr{IP: net.ParseIP(v)})
		}
		return out
	}
	resolver := func(addrs []net.IPAddr, err error) func(context.Context, string) ([]net.IPAddr, error) {
		return func(context.Context, string) ([]net.IPAddr, error) { return addrs, err }
	}

	cases := []struct {
		name    string
		url     string
		lookup  func(context.Context, string) ([]net.IPAddr, error)
		blocked bool
		wantErr bool
	}{
		{"域名解析到元数据IP", "http://metadata.example/latest", resolver(ips("169.254.169.254"), nil), true, false},
		{"解析结果混有元数据IP", "http://mixed.example/", resolver(ips("10.0.0.1", "169.254.169.254"), nil), true, false},
		{"域名解析到私网放行", "http://internal.example/", resolver(ips("10.0.0.1"), nil), false, false},
		{"域名解析到环回放行", "http://local.example/", resolver(ips("127.0.0.1"), nil), false, false},
		{"解析失败拒绝", "http://broken.example/", resolver(nil, fmt.Errorf("dial dns: failure")), true, true},
		{"字面IP不触发DNS", "http://127.0.0.1:8080/", resolver(nil, fmt.Errorf("不应被调用")), false, false},
		{"空主机拒绝", "http:///path", resolver(nil, nil), true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lookupFetchIPAddr = tc.lookup
			blocked, err := resolvedSensitiveHost(context.Background(), tc.url)
			if blocked != tc.blocked {
				t.Errorf("blocked = %v, want %v", blocked, tc.blocked)
			}
			if (err != nil) != tc.wantErr {
				t.Errorf("err = %v, wantErr = %v", err, tc.wantErr)
			}
		})
	}
}

// TestRedirectToSensitiveTargetBlocked 验证 302 到元数据 IP 在发起第二跳前被拒绝，
// 不依赖真的有服务监听 169.254.169.254。direct 与 proxy 两条路径都要拦住。
func TestRedirectToSensitiveTargetBlocked(t *testing.T) {
	t.Setenv("ARTEX_HTTP_USER_AGENT", "Captured-UA/1.0")
	var firstHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		firstHits.Add(1)
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/iam/security-credentials/", http.StatusFound)
	}))
	defer server.Close()

	for _, route := range []string{"direct", "proxy"} {
		t.Run(route, func(t *testing.T) {
			firstHits.Store(0)
			cfg := actool.WebFetchConfig{}
			var proxyHits atomic.Int32
			if route == "proxy" {
				forward := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
					return http.ErrUseLastResponse // 原样回传 302，由被测 client 的 CheckRedirect 拦截
				}}
				proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					proxyHits.Add(1)
					req := r.Clone(r.Context())
					req.RequestURI = ""
					resp, err := forward.Do(req)
					if err != nil {
						w.WriteHeader(http.StatusBadGateway)
						return
					}
					defer resp.Body.Close()
					for k, vs := range resp.Header {
						w.Header()[k] = vs
					}
					w.WriteHeader(resp.StatusCode)
					io.Copy(w, resp.Body)
				}))
				defer proxy.Close()
				cfg.Proxy = proxy.URL
			}
			result := callFetch(t, New(cfg), server.URL, false)
			if !result.IsError {
				t.Fatalf("%s: 期望拒绝到元数据 IP 的重定向，实际成功: %+v", route, result)
			}
			if !strings.Contains(result.Flatten(), "拒绝") {
				t.Fatalf("%s: 错误信息应说明拒绝原因: %s", route, result.Flatten())
			}
			if got := firstHits.Load(); got != 1 {
				t.Errorf("%s: 第一跳命中 %d 次，期望 1", route, got)
			}
			if route == "proxy" && proxyHits.Load() != 1 {
				t.Errorf("proxy: 代理收到 %d 次请求，期望 1", proxyHits.Load())
			}
		})
	}
}

// TestRedirectToNormalTargetSucceeds 正常重定向（域名/字面 IP 均非受限）不受影响。
func TestRedirectToNormalTargetSucceeds(t *testing.T) {
	t.Setenv("ARTEX_HTTP_USER_AGENT", "Captured-UA/1.0")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			http.Redirect(w, r, "/page", http.StatusFound)
			return
		}
		fmt.Fprint(w, "landed")
	}))
	defer server.Close()
	result := callFetch(t, New(actool.WebFetchConfig{}), server.URL+"/start", false)
	if result.IsError || !strings.Contains(result.Flatten(), "landed") {
		t.Fatalf("正常重定向失败: %+v", result)
	}
}

// TestUTF8Truncation 确保按 rune 截断，不产生非法 UTF-8。
func TestUTF8Truncation(t *testing.T) {
	full := strings.Repeat("中文", 20)
	if got := oneLine(full, 5); !utf8.ValidString(got) || got != "中文中文中…" {
		t.Errorf("oneLine 中文截断错误: %q", got)
	}
	got := truncate(full, 6)
	if !utf8.ValidString(got) {
		t.Fatalf("truncate 产生非法 UTF-8: %q", got)
	}
	for _, valid := range []struct {
		s   string
		max int
	}{{"中文", 10}, {full, 0}, {full, -1}, {"abc", 2}} {
		if out := truncate(valid.s, valid.max); !utf8.ValidString(out) {
			t.Errorf("truncate(%q, %d) 非法 UTF-8: %q", valid.s, valid.max, out)
		}
	}
}

// TestChineseContentStaysValidUTF8 中文路径 + 中文正文/recon 经读取后仍是合法 UTF-8。
func TestChineseContentStaysValidUTF8(t *testing.T) {
	t.Setenv("ARTEX_HTTP_USER_AGENT", "Captured-UA/1.0")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<h1>中文标题</h1><!--这是一段很长的中文注释用于触发截断--><p>正文内容</p>`)
	}))
	defer server.Close()
	result := callFetch(t, New(actool.WebFetchConfig{}), server.URL+"/路径", true)
	if result.IsError {
		t.Fatal(result.Flatten())
	}
	flat := result.Flatten()
	if !utf8.ValidString(flat) {
		t.Fatalf("结果含非法 UTF-8: %q", flat)
	}
	for _, want := range []string{"中文标题", "这是一段很长的中文注释"} {
		if !strings.Contains(flat, want) {
			t.Errorf("缺少 %q: %s", want, flat)
		}
	}
}
