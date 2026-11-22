package server

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// controllableClock 让测试拨动窗口而不用真睡一分钟。
type controllableClock struct{ now time.Time }

func (c *controllableClock) Now() time.Time { return c.now }

func (c *controllableClock) advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestLimiter() (*authLimiter, *controllableClock) {
	clk := &controllableClock{now: time.Date(2026, 11, 22, 10, 0, 0, 0, time.UTC)}
	return newAuthLimiter(clk.Now), clk
}

// TestAuthLimiterPerIPWindow 验证单一来源的窗口预算：用满即拒，窗口翻转即恢复。
func TestAuthLimiterPerIPWindow(t *testing.T) {
	l, clk := newTestLimiter()

	for i := 0; i < authPerIPLimit; i++ {
		if ok, _ := l.attempt("10.0.0.1"); !ok {
			t.Fatalf("第 %d 次尝试应放行", i+1)
		}
	}
	if ok, retry := l.attempt("10.0.0.1"); ok {
		t.Fatal("窗口预算用尽后应拒绝")
	} else if retry <= 0 {
		t.Fatal("拒绝时应给出正的 Retry-After")
	}

	// 另一个来源不受影响——per-IP 计数不能串。
	if ok, _ := l.attempt("10.0.0.2"); !ok {
		t.Fatal("其他来源不应被单个来源的窗口拖累")
	}

	clk.advance(authWindow + time.Second)
	if ok, _ := l.attempt("10.0.0.1"); !ok {
		t.Fatal("窗口翻转后应重新放行")
	}
}

// TestAuthLimiterGlobalWindow 验证全局桶：换 IP 也绕不过。这是分布式爆破的
// 唯一防线（per-IP 计数天然被换出口绕过）。
func TestAuthLimiterGlobalWindow(t *testing.T) {
	l, _ := newTestLimiter()

	for i := 0; i < authGlobalLimit; i++ {
		ip := "10.1." + fmt.Sprintf("%d", i/256) + "." + fmt.Sprintf("%d", i%256)
		if ok, _ := l.attempt(ip); !ok {
			t.Fatalf("第 %d 次尝试应放行（全局预算未用尽）", i+1)
		}
	}
	if ok, _ := l.attempt("10.9.9.9"); ok {
		t.Fatal("全局预算用尽后，新来源也应被拒绝")
	}
}

// TestAuthLimiterFailureLock 验证失败锁定：达到阈值直接锁一段时间，
// 比"再试几次就放行"硬得多。
func TestAuthLimiterFailureLock(t *testing.T) {
	l, clk := newTestLimiter()

	for i := 0; i < authFailTrips; i++ {
		l.attempt("10.0.0.1")
		l.recordFailure("10.0.0.1")
	}
	if ok, retry := l.attempt("10.0.0.1"); ok {
		t.Fatal("失败次数达阈值后应锁定")
	} else if retry <= 0 {
		t.Fatal("锁定状态应报告剩余锁定时间")
	}

	clk.advance(authLockDur / 2)
	if ok, _ := l.attempt("10.0.0.1"); ok {
		t.Fatal("锁定期内不应放行")
	}
	clk.advance(authLockDur)
	if ok, _ := l.attempt("10.0.0.1"); !ok {
		t.Fatal("锁定期满后应放行")
	}
}

// TestAuthLimiterLockSurvivesWindowRoll 是回归测试。
//
// 早期实现里窗口翻转会把整张计数 map 重建，而未到期锁定也存在同一张 map 里——
// 于是"锁定 10 分钟"会在下一个 1 分钟窗口开始的那一刻自动消失。攻击者只要把
// 请求匀速挂满十分钟就能白拿一整份新预算，锁定形同虚设。这条测试专门钉住
// 这个行为：跨越多轮窗口翻转，未到期锁定必须仍然生效。
func TestAuthLimiterLockSurvivesWindowRoll(t *testing.T) {
	l, clk := newTestLimiter()

	for i := 0; i < authFailTrips; i++ {
		l.attempt("10.0.0.1")
		l.recordFailure("10.0.0.1")
	}
	// 跨过 3 个完整窗口。锁定期 10 分钟 > 3 分钟，锁定必须还在。
	clk.advance(3 * authWindow)
	if ok, _ := l.attempt("10.0.0.1"); ok {
		t.Fatal("锁定期未满，窗口翻转不能解除锁定")
	}
	// 已锁定期间继续失败不应把锁定推得更长（会制造永久的拒绝）。
	l.recordFailure("10.0.0.1")
	if ok, _ := l.attempt("10.0.0.1"); ok {
		t.Fatal("锁定期间不应放行")
	}

	// 其余来源不受这个锁定牵连。
	if ok, _ := l.attempt("10.0.0.9"); !ok {
		t.Fatal("未锁定的来源不应被别人的锁定连带拒绝")
	}
}

// TestAuthLimiterPruneOnRoll 验证窗口翻转会清掉已失效的条目——
// 不清的话 map 会随见过的来源数单调增长，是个慢性内存泄漏。
func TestAuthLimiterPruneOnRoll(t *testing.T) {
	l, clk := newTestLimiter()
	l.attempt("10.0.0.1")
	l.mu.Lock()
	l.fails["phantom"] = &authBucket{count: 5, locked: time.Time{}}
	total := len(l.fails)
	l.mu.Unlock()
	if total != 2 {
		t.Fatalf("前置状态不对：want 2 条目，got %d", total)
	}
	clk.advance(authWindow + time.Second)
	l.attempt("10.0.0.2") // 触发翻转
	l.mu.Lock()
	remaining := len(l.fails)
	l.mu.Unlock()
	if remaining != 1 {
		t.Fatalf("翻转后应只剩当前来源，got %d 条目", remaining)
	}
}

// TestAuthLimiterRecordsEmptyIP 验证来源未知（ip 为空）时只吃全局预算，
// 不往 map 里塞空键。
func TestAuthLimiterRecordsEmptyIP(t *testing.T) {
	l, _ := newTestLimiter()
	if ok, _ := l.attempt(""); !ok {
		t.Fatal("首次尝试应放行")
	}
	l.recordFailure("")
	l.mu.Lock()
	_, hasEmpty := l.fails[""]
	l.mu.Unlock()
	if hasEmpty {
		t.Fatal("空来源不应建立 per-IP 桶")
	}
}

// TestAuthClientIP 验证来源地址解析：剥端口，畸形地址原样返回。
func TestAuthClientIP(t *testing.T) {
	cases := []struct {
		remote, want string
	}{
		{"192.168.1.10:51234", "192.168.1.10"},
		{"[::1]:443", "::1"},
		{"garbage", "garbage"},
	}
	for _, c := range cases {
		r := &http.Request{RemoteAddr: c.remote}
		if got := authClientIP(r); got != c.want {
			t.Errorf("authClientIP(%q) = %q，want %q", c.remote, got, c.want)
		}
	}
}

// TestAuthLimiterNilSafe 对应 authLimiterOrDummy 的降级路径：未走 New 的
// 测试用 Server 不该 panic。
func TestAuthLimiterNilSafe(t *testing.T) {
	s := &Server{}
	if got := s.authLimiterOrDummy(); got != nil {
		t.Fatal("未初始化时应返回 nil 而不是空对象")
	}
}

// TestDenyRateLimited 验证 429 响应体：状态码、Retry-After、no-store。
func TestDenyRateLimited(t *testing.T) {
	rec := httptest.NewRecorder()
	denyRateLimited(rec, 42*time.Second)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("状态码 = %d，want 429", rec.Code)
	}
	if got := rec.Header().Get("Retry-After"); got != "42" {
		t.Errorf("Retry-After = %q，want %q", got, "42")
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Errorf("Cache-Control = %q，want no-store", got)
	}
}

// TestDenyRateLimitedMinOneSecond 验证 Retry-After 下限：0 会让客户端立刻重试，
// 等于没限。
func TestDenyRateLimitedMinOneSecond(t *testing.T) {
	rec := httptest.NewRecorder()
	denyRateLimited(rec, 0)
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("Retry-After = %q，want %q", got, "1")
	}
}

// TestBcryptDummyHashNeverMatches 验证时序侧信道防护用的 dummy 密文是合法的
// bcrypt 输出（不合法会让 CompareHashAndPassword 提前报错而不是走完整计算，
// 耗时保护随之失效），并且对任何候选密码都必然失败——它只是拿来"耗时间"的，
// 绝不能因为某个真实密码碰巧撞上而误放行。
func TestBcryptDummyHashNeverMatches(t *testing.T) {
	for _, pw := range []string{"", "correct horse battery staple", "ARTEX"} {
		if err := bcrypt.CompareHashAndPassword(bcryptDummyHash, []byte(pw)); err == nil {
			t.Fatalf("dummy 密文不该匹配任何密码（%q）", pw)
		}
	}
}

// TestSecurityHeaders 验证全局安全响应头确实出现在最终响应上。
func TestSecurityHeaders(t *testing.T) {
	want := map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "strict-origin-when-cross-origin",
		"X-XSS-Protection":       "0",
		"Permissions-Policy":     "camera=(), microphone=(), geolocation=(), payment=()",
	}
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte("ok"))
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}})
	for k, v := range want {
		if got := rec.Header().Get(k); got != v {
			t.Errorf("缺少 %s=%q，实际 %q", k, v, got)
		}
	}
}

// TestSecurityHeadersNotOverridden 验证 handler 自己设置同名头时覆盖中间件，
// 不会破坏已有的局部设置（例如文件下载的显式头）。
func TestSecurityHeadersNotOverridden(t *testing.T) {
	h := securityHeaders(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}})
	if got := rec.Header().Get("X-Frame-Options"); got != "SAMEORIGIN" {
		t.Errorf("X-Frame-Options = %q，want SAMEORIGIN（handler 应优先）", got)
	}
}
