package server

import (
	"log"
	"net"
	"net/http"
	"strconv"
	"sync"
	"time"
)

// 认证接口的双层速率限制。
//
// 白泽是个会暴露到局域网的 Web 应用（--addr 默认 :8787，监听所有网卡），
// 而 POST /api/auth/login 此前没有任何速率限制——攻击者可以每秒发几十次猜密码，
// bcrypt 再慢也只是让攻击者慢一点，不阻止。这里补上两层：
//
//  1. per-IP 桶：挡住对单一来源的定点爆破。
//  2. 全局桶：挡住"每个 IP 只试几次、轮换着来"的分布式爆破。per-IP 计数天然
//     被换 IP 绕过（NAT / 代理池 / 每次换个出口），全局桶不认来源、只认
//     "这台白泽此刻总共被试了多少次"，换 IP 无用。
//
// 失败锁定比单纯限速更硬：窗口内连续失败够多，该 IP 直接被锁一段时间，
// 而不是"再试 N 次就让你过"。锁定期间 attempt 立即拒绝，连计数都不消耗。
//
// 实现是固定窗口计数 + 惰性清理：不另起 goroutine 定时清扫（白泽的常驻循环
// 已经不少，再加一个只为清 map 不值得），改在每次访问时顺手丢弃过期条目。
// map 里最多积累"最近一个窗口内活跃过的 IP 数"，本地工具的量级下微不足道。
type authLimiter struct {
	mu         sync.Mutex
	now        time.Time // 窗口起点
	counts     int64     // 全局窗口计数
	fails      map[string]*authBucket
	globalFail int64 // 全局窗口失败数

	perIP     int // 每 IP 每窗口允许的尝试次数
	global    int // 全局每窗口允许的尝试次数
	failTrips int // 窗口内失败多少次触发锁定
	dur       time.Duration
	lock      time.Duration

	// 时钟可注入，单测里能拨动窗口而不用真睡。生产路径恒为 time.Now。
	clock func() time.Time
}

// authBucket 是单个来源的计数状态。
type authBucket struct {
	count  int64
	fails  int64
	locked time.Time // 零值表示未锁定
}

// 默认阈值。取值原则：足够大，不误伤真人（手抖连点十几次登录也该能过）；
// 足够小，让暴力破解在几分钟内撞上墙。全局桶给 per-IP 的 6 倍余量，正常本地
// 单用户场景根本碰不到，只有多来源并发爆破才会触发。
const (
	authPerIPLimit  = 30
	authGlobalLimit = 180
	authFailTrips   = 8
	authWindow      = time.Minute
	authLockDur     = 10 * time.Minute
	authWarnEvery   = 50 // 每拒绝多少请求告警一次，避免日志被刷爆
)

// newAuthLimiter 建一个默认参数的限流器。clock 传 nil 用 time.Now。
func newAuthLimiter(clock func() time.Time) *authLimiter {
	if clock == nil {
		clock = time.Now
	}
	return &authLimiter{
		now:       clock(),
		fails:     make(map[string]*authBucket),
		perIP:     authPerIPLimit,
		global:    authGlobalLimit,
		failTrips: authFailTrips,
		dur:       authWindow,
		lock:      authLockDur,
		clock:     clock,
	}
}

// authDenialCounter 累计被拒次数，用于按固定间隔打日志。
type authDenialCounter struct {
	mu     sync.Mutex
	denied int64
}

var authDenials authDenialCounter

// attempt 在每次认证尝试前调用。返回 (是否放行, 建议的 Retry-After 秒数)。
// allowed=false 时调用方必须直接回 429，不要继续走校验（跑了 bcrypt 等于白给
// 攻击者一次免费的算力，而且照样消耗了我们的窗口预算）。
func (l *authLimiter) attempt(ip string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	// 窗口翻转：重置计数。顺带清掉这个 map——过期窗口里的条目已经没意义，
	// 不清就会随见过的 IP 数单调增长（内存缓慢性泄漏）。
	if now.Sub(l.now) >= l.dur {
		l.now = now
		l.counts = 0
		l.globalFail = 0
		l.pruneOnWindowRoll(now)
	}

	if ip != "" {
		if b := l.fails[ip]; b != nil && now.Before(b.locked) {
			// 用注入时钟算剩余时间，而不是 time.Now：生产路径两者相同，
			// 但这样单测里拨动时钟时算出的 Retry-After 才符合预期。
			return false, b.locked.Sub(now).Round(time.Second)
		}
	}

	retry := 0 * time.Second
	if l.counts >= int64(l.global) {
		retry = l.dur - now.Sub(l.now)
	} else if ip != "" {
		if b := l.fails[ip]; b != nil && b.count >= int64(l.perIP) {
			retry = l.dur - now.Sub(l.now)
		}
	}
	if retry <= 0 {
		l.counts++
		if ip != "" {
			b := l.fails[ip]
			if b == nil {
				b = &authBucket{}
				l.fails[ip] = b
			}
			b.count++
		}
		return true, 0
	}
	if retry < time.Second {
		retry = time.Second
	}
	return false, retry
}

// recordFailure 在一次认证失败后调用。累计失败达到阈值就把该来源锁一段时间。
func (l *authLimiter) recordFailure(ip string) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.clock()
	if now.Sub(l.now) >= l.dur {
		l.now = now
		l.counts = 0
		l.globalFail = 0
		l.pruneOnWindowRoll(now)
	}
	l.globalFail++

	if ip == "" {
		return
	}
	b := l.fails[ip]
	if b == nil {
		b = &authBucket{}
		l.fails[ip] = b
	}
	b.fails++
	if b.fails >= int64(l.failTrips) && !now.Before(b.locked) {
		b.locked = now.Add(l.lock)
		log.Printf("[auth] 来源 %s 窗口内失败 %d 次，锁定 %s", ip, b.fails, l.lock)
	}
}

// pruneOnWindowRoll 在窗口翻转时清零计数，但保留尚未到期的锁定。
//
// 必须区分对待这两样：锁定期（10 分钟）比窗口期（1 分钟）长得多，若像早期
// 实现那样整个 map 重建，锁定会在下一个窗口开始的那一刻自动消失——等于从未
// 锁过，攻击者只要挂满十分钟就能白拿一次满额预算。
//
// 同时仍要清理已失效的条目，否则 map 会随见过的来源数单调增长（慢性内存
// 泄漏），这一点不能因为上面那个原因就一起牺牲。
func (l *authLimiter) pruneOnWindowRoll(now time.Time) {
	for k, b := range l.fails {
		if now.Before(b.locked) {
			b.count = 0
			b.fails = 0
			continue
		}
		delete(l.fails, k)
	}
}

// maybeWarn 按固定间隔把"拒绝"这件事写进日志。渗透工具自己被人扫是重要事件，
// 静默放过等于把报警器拆了；但每条拒绝都打日志又会把日志刷成噪音，所以折中。
func (l *authLimiter) maybeWarn(ip, path string) {
	authDenials.mu.Lock()
	authDenials.denied++
	n := authDenials.denied
	authDenials.mu.Unlock()
	if n == 1 || n%authWarnEvery == 0 {
		log.Printf("[auth] %s 被速率限制拒绝（来源 %s），累计 %d 次", path, ip, n)
	}
}

// denyRateLimited 回 429 + Retry-After。Retry-After 是窗口剩余时间，客户端
// （以及扫描器）都能据此知道该等多久，而不是盲目重试继续撞墙。
func denyRateLimited(w http.ResponseWriter, retry time.Duration) {
	if retry < time.Second {
		retry = time.Second
	}
	w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())))
	w.Header().Set("Cache-Control", "no-store")
	writeProductError(w, http.StatusTooManyRequests, "rate_limited",
		"尝试次数过多，请稍后再试", nil)
}

// authClientIP 取来源 IP。刻意不读 X-Forwarded-For：该头可被客户端任意伪造，
// 一旦信任，攻击者每次请求换个头就能把 per-IP 计数全部清零，限流形同虚设。
// 白泽是本地/局域网工具，直接信任 TCP 对端地址即可；确有反代部署的场景，
// 应让反代终结 TLS 并把真实地址落到 RemoteAddr（如 proxy_protocol）。
func authClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
