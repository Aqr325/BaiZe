package server

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	// authTokenVersionKey 是管理员 JWT 的撤销版本号。改密成功后递增，
	// 旧 token 因 claim 里的 "tv" 与当前版本不符而被拒绝。缺省/空视为 "1"。
	authTokenVersionKey     = "auth.token_version"
	defaultAuthTokenVersion = "1"
	jwtTTL                  = 7 * 24 * time.Hour
	keyChars                = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// loginUsername 是默认登录用户名，可从 DB settings(auth_username) 覆盖。
	// 提常量而不是散在 handler 里的字符串字面量：它同时被时序侧信道防护用到，
	// 散字面量容易改漏一处造成不一致。
	loginUsername = "ARTEX"

	// authUserKey 允许部署方覆盖登录用户名（如改 "baize" 避免暴露 ARTEX 指纹）。
	// 未设置时回退到 loginUsername 常量。
	authUserKey = "auth_username"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// bcryptDummyHash 是一个合法但从不匹配任何用户密码的 bcrypt 密文。
// 登录的用户名校验失败路径上比对它一次，只为让耗时和"密码比对"路径一致。
// 值为 bcrypt.DefaultCost 格式，保证 CompareHashAndPassword 走完整计算。
var bcryptDummyHash = []byte("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")

// authLimiterOrDummy 让 handler 在限流器缺失时（例如未走 New 的单元测试直接
// 构造 Server）优雅降级成不限流，而不是空指针 panic。
func (s *Server) authLimiterOrDummy() *authLimiter { return s.authLimit }

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// adminClaims is the admin JWT payload. "tv" (token version) makes tokens
// revocable: changing the admin password bumps the persisted version, so every
// token minted before the change stops verifying without waiting for jwtTTL.
type adminClaims struct {
	TokenVersion string `json:"tv,omitempty"`
	jwt.RegisteredClaims
}

// signJWT issues a 7-day HS256 token for user BaiZe carrying the current token
// version. version is variadic so existing callers/tests default to version "1";
// all production callers pass s.currentAuthTokenVersion() explicitly.
// NOTE: Subject is display-only (前端用它渲染用户名); verifyJWT 只校验签名与版本,
// 不检查 Subject 内容, 因此改动不影响认证。
func signJWT(key []byte, version ...string) (string, error) {
	tv := defaultAuthTokenVersion
	if len(version) > 0 && version[0] != "" {
		tv = version[0]
	}
	claims := adminClaims{
		TokenVersion: tv,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "白泽",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	return jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(key)
}

// verifyJWT returns true only for a valid, non-expired HS256 token whose "tv"
// claim matches the expected token version. A missing claim is treated as "1"
// so tokens issued before this mechanism shipped stay valid until the next
// password change (which bumps the version and rejects them all).
// version is variadic for the same reason as signJWT; production callers pass
// the current version explicitly.
func verifyJWT(tokenStr string, key []byte, version ...string) bool {
	want := defaultAuthTokenVersion
	if len(version) > 0 && version[0] != "" {
		want = version[0]
	}
	claims := &adminClaims{}
	t, err := jwt.ParseWithClaims(tokenStr, claims, func(*jwt.Token) (any, error) {
		return key, nil
	}, jwt.WithValidMethods([]string{"HS256"}))
	if err != nil || !t.Valid {
		return false
	}
	got := claims.TokenVersion
	if got == "" {
		got = defaultAuthTokenVersion
	}
	return got == want
}

// currentAuthTokenVersion returns the active version used to sign and verify
// admin JWTs. The settings row is the source of truth and is read on every
// call: reset-password.sh bumps the version directly in the database, so an
// in-memory-only cache would keep issuing/accepting tokens at a stale version
// until restart. The settings lookup is a single indexed query on a hot path
// that already touches the DB; the in-memory value is kept as a fallback for
// DB outages and for Servers built directly in tests.
func (s *Server) currentAuthTokenVersion() string {
	if s.m != nil && s.m.pg != nil {
		if v, _, err := s.m.pg.GetSetting(authTokenVersionKey); err == nil && v != "" {
			return v
		}
	}
	s.authTokenVerMu.RLock()
	defer s.authTokenVerMu.RUnlock()
	if s.authTokenVer == "" {
		return defaultAuthTokenVersion
	}
	return s.authTokenVer
}

// nextAuthTokenVersion returns the successor of v. Non-numeric custom values
// restart the counter at "2" rather than bricking the revocation mechanism.
func nextAuthTokenVersion(v string) string {
	n, err := strconv.ParseUint(v, 10, 64)
	if err != nil {
		n = 1
	}
	return strconv.FormatUint(n+1, 10)
}

// atomicSettingsWriter is the subset of db.DB used to commit a password change.
type atomicSettingsWriter interface {
	SetSettingsAtomic(ctx context.Context, values map[string]string) error
}

// commitPasswordChange persists the new password hash and the bumped token
// version in ONE transaction, then refreshes the in-memory version cache.
// Holding authTokenVerMu across the write serializes concurrent changes so two
// requests cannot compute the same successor. A failed commit leaves both the
// stored password and the cached version untouched (fail closed).
func (s *Server) commitPasswordChange(ctx context.Context, store atomicSettingsWriter, newHash string) (string, error) {
	// Read the current version before taking the mutex (the read may hit the DB).
	cur := s.currentAuthTokenVersion()
	s.authTokenVerMu.Lock()
	defer s.authTokenVerMu.Unlock()
	next := nextAuthTokenVersion(cur)
	if err := store.SetSettingsAtomic(ctx, map[string]string{
		authPassKey:         newHash,
		authTokenVersionKey: next,
	}); err != nil {
		return "", err
	}
	s.authTokenVer = next
	return next, nil
}

// isSSETokenRoute reports whether ?token= is honoured for this path. Only the
// EventSource endpoints may use the query parameter (EventSource cannot set an
// Authorization header); every other route ignores it so a token can't leak
// into access logs / Referer headers on ordinary API calls.
func isSSETokenRoute(path string) bool {
	switch path {
	case "/api/logs/stream", "/api/update/stream", "/api/exploration/activity/stream":
		return true
	}
	const prefix = "/api/side-questions/"
	return strings.HasPrefix(path, prefix) && strings.HasSuffix(path, "/events")
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or (SSE routes only) ?token= query param.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if isSSETokenRoute(r.URL.Path) {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// /api/auth/*, /api/health, the Basic Auth gate check and the A2A endpoint
// (/a2a — a machine-to-machine peer-gateway call protected by its own Bearer
// token inside the A2A handler) are exempt from the browser JWT check.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" || p == "/api/basic-auth/check" || strings.HasPrefix(p, "/a2a") {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeProductError(w, 401, "unauthorized", "未授权", nil)
			return
		}
		if !verifyJWT(tok, s.jwtKey, s.currentAuthTokenVersion()) {
			writeProductError(w, 401, "token_expired", "token 无效或已过期", nil)
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// GET /api/auth/config — returns the configured admin login username (default
// "ARTEX") so the login page can render it without hardcoding. 仅返回用户名（非
// 敏感），/api/auth/* 已豁免鉴权，供登录前调用。
func (s *Server) authConfig(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	username, _, err := pg.GetSetting(authUserKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if username == "" {
		username = loginUsername
	}
	writeJSON(w, 200, map[string]any{"username": username})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	// 初始化接口在密码不存在时是唯一入口，攻击者用它反复试探可以枚举"是否已
	// 初始化"，也可以在自己抢先初始化后把管理员密码变成自己的。限流挡掉刷探测。
	ip := authClientIP(r)
	if lim := s.authLimiterOrDummy(); lim != nil {
		if ok, retry := lim.attempt(ip); !ok {
			lim.maybeWarn(ip, "/api/auth/init")
			denyRateLimited(w, retry)
			return
		}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if existing != "" {
		writeProductError(w, 403, "password_already_set", "密码已设置", nil)
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeProductError(w, 400, "password_required", "密码不能为空", nil)
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		code, params := passwordValidationCode(req.Password)
		writeProductError(w, 400, code, msg, params)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeProductError(w, 500, "password_hash_failed", "密码加密失败", nil)
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		// 不把底层错误回传：pgx 错误含表名 / SQLSTATE / SQL 片段。
		writeProductError(w, 500, "save_failed", "保存失败", nil)
		return
	}
	if !inserted {
		writeProductError(w, 403, "password_already_set", "密码已设置", nil)
		return
	}
	tok, err := signJWT(s.jwtKey, s.currentAuthTokenVersion())
	if err != nil {
		writeProductError(w, 500, "token_failed", "token 生成失败", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.jwtKey, s.currentAuthTokenVersion()) {
		writeProductError(w, 401, "unauthorized", "未授权", nil)
		return
	}
	// 限流放在 JWT 校验之后：无效令牌本来就被挡在门外，不必消耗窗口预算；
	// 这里限的是"持有效令牌反复猜旧密码"这一路——令牌可能已被盗用或过期，
	// 它不保证操作者就是管理员本人。
	{
		ip := authClientIP(r)
		if lim := s.authLimiterOrDummy(); lim != nil {
			if ok, retry := lim.attempt(ip); !ok {
				lim.maybeWarn(ip, "/api/auth/change-password")
				denyRateLimited(w, retry)
				return
			}
		}
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "请求格式错误", nil)
		return
	}
	if req.NewPassword == "" {
		writeProductError(w, 400, "new_password_required", "新密码不能为空", nil)
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		code, params := passwordValidationCode(req.NewPassword)
		writeProductError(w, 400, code, msg, params)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if !ok || hash == "" {
		writeProductError(w, 403, "password_not_initialized", "密码未初始化，请先设置密码", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		if lim := s.authLimiterOrDummy(); lim != nil {
			lim.recordFailure(authClientIP(r))
		}
		writeProductError(w, 401, "current_password_incorrect", "当前密码错误", nil)
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeProductError(w, 500, "password_hash_failed", "密码加密失败", nil)
		return
	}
	// 密码 hash 与 token_version 必须一起提交：只改 hash 的话，泄露的旧 token
	// 仍能再用 7 天。SetSettingsAtomic 保证两者要么都落库要么都不落库。
	newVer, err := s.commitPasswordChange(r.Context(), pg, string(newHash))
	if err != nil {
		writeProductError(w, 500, "save_failed", "保存失败", nil)
		return
	}
	// 旧 token 因版本递增已失效。立刻用新版本签发一个新 token 返回给前端，
	// 让用户改密后保持登录，而不是下一次请求被 401 登出（UX 突变）。
	// 旧 token 已无法使用——安全目标（止损泄露的 token）不受影响。
	fresh, err := signJWT(s.jwtKey, newVer)
	if err != nil {
		// 签发失败不应让"改密已成功"回退成错误；返回 ok 但不带新 token，
		// 前端会走正常 401 登出路径。
		writeJSON(w, 200, map[string]any{"ok": true})
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": fresh})
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	ip := authClientIP(r)
	if lim := s.authLimiterOrDummy(); lim != nil {
		if ok, retry := lim.attempt(ip); !ok {
			lim.maybeWarn(ip, "/api/auth/login")
			denyRateLimited(w, retry)
			return
		}
	}
	fail := func() {
		if lim := s.authLimiterOrDummy(); lim != nil {
			lim.recordFailure(ip)
		}
	}
	pg := s.pg(w)
	if pg == nil {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeProductError(w, 400, "invalid_request", "请求格式错误", nil)
		return
	}
	// 登录用户名可从 DB 覆盖（默认 ARTEX）。读一次，供正常路径与下方时序防护共用，
	// 避免两条路径比较不一致。
	username, _, err := pg.GetSetting(authUserKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if username == "" {
		username = loginUsername
	}
	if req.Username != username {
		// 时序侧信道防护：这条路径原本直接返回，跳过了 bcrypt，于是"用户名错"
		// 几十毫秒就回、"用户名对但密码错"要跑一遍 bcrypt（~100ms+）。攻击者按
		// 响应耗时就能把真实用户名枚举出来——而它本来只有一个可选值。这里补跑
		// 一次对固定 dummy 密文的比对，把两条路径拉平到同一耗时，枚举失效。
		// dummy 是任意值的合法 bcrypt 密文，比对必然失败，不泄露任何真实信息。
		_ = bcrypt.CompareHashAndPassword(bcryptDummyHash, []byte(req.Password))
		fail()
		writeProductError(w, 401, "invalid_credentials", "用户名或密码错误", nil)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeProductError(w, 503, "data_unavailable", errDataSourceUnavailable, nil)
		return
	}
	if !ok || hash == "" {
		writeProductError(w, 403, "password_not_initialized", "密码未初始化，请先设置密码", nil)
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		fail()
		writeProductError(w, 401, "invalid_credentials", "用户名或密码错误", nil)
		return
	}
	tok, err := signJWT(s.jwtKey, s.currentAuthTokenVersion())
	if err != nil {
		writeProductError(w, 500, "token_failed", "token 生成失败", nil)
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

func passwordValidationCode(password string) (string, map[string]any) {
	if utf8.RuneCountInString(password) < minPasswordRunes {
		return "password_too_short", map[string]any{"min": minPasswordRunes}
	}
	return "password_too_long", map[string]any{"max": maxPasswordBytes}
}
