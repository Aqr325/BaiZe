package guard

import (
	"encoding/json"
	"regexp"
	"strings"
	"sync"
)

// Fence 实现「允许清单 + 越界授权」（allow list + out-of-bounds authorization）。
//
// 升级点：旧的「deny 清单」在任务出现任何 deny 约束时，把所有工具调用无差别升级为
// 人工审批——边界只能靠自然语言人工裁决，过宽且审批疲劳。Fence 让操作员声明一个
// 可机器判定的允许范围（结构化 allow 规则），从而把审批收窄到真正越界的调用：
//
//   - 落在允许清单内（InScope）→ 自动放行，无需人工审批；
//   - 落在允许清单外（越界）→ 升级为「越界授权」人工审批；授权后按 surface 记忆，
//     相同越界目标不再重复询问（AuthzStore 持久化）；
//   - 命中禁止清单（Forbidden）→ 硬拦截（deny 最严，优先于 allow）。
//
// 无结构化 allow 规则时 Fence 不激活（Inactive），调用方回落到旧「deny 清单→全量
// 升级人工审批」行为，保持向后兼容。
type Fence struct {
	allow []FenceRule
	deny  []FenceRule
	authz AuthzStore
}

// FenceRule is one structured fence rule. Match 决定规则作用在哪个表面，Pattern 是
// 该表面上的 glob。Text 保留自由文本（仅提示词/展示用，不参与机器判定）。
type FenceRule struct {
	Kind    string `json:"kind"`    // allow | deny
	Match   string `json:"match"`   // tool|command|host|path|port|all
	Pattern string `json:"pattern"` // glob
	Text    string `json:"text,omitempty"`
}

// Verdict is the fence classification for one tool call.
type Verdict int

const (
	VerdictInactive    Verdict = iota // 无结构化 allow 规则 → Fence 未激活
	VerdictInScope                    // 命中允许清单 → 放行
	VerdictOutOfBounds                // 不在允许清单内 → 越界，需授权
	VerdictForbidden                  // 命中禁止清单 → 硬拦截
)

// AuthzStore persists 越界授权 records. ExplorationStore implements it.
type AuthzStore interface {
	// IsFenceAuthorized reports whether `surface` has a live (unexpired) 越界授权。
	IsFenceAuthorized(surface string) bool
	// AddFenceAuthz records a 越界授权; returns the record id.
	AddFenceAuthz(surface, tool, digest, grantedBy, note string) (int64, error)
}

// NewFence builds a Fence from structured rules + a persistence store.
// Rules are grouped: allow 规则组成允许清单，deny 规则组成禁止清单。
func NewFence(rules []FenceRule, authz AuthzStore) *Fence {
	f := &Fence{authz: authz}
	for _, r := range rules {
		switch r.Kind {
		case "allow":
			f.allow = append(f.allow, r)
		case "deny":
			f.deny = append(f.deny, r)
		}
	}
	return f
}

// Active reports whether the fence is enforcing deny-by-default (≥1 allow rule).
func (f *Fence) Active() bool { return f != nil && len(f.allow) > 0 }

// Classify returns the fence verdict for a tool call. deny 先判（最严），其次判定
// 是否落在允许清单内，其余为越界。
func (f *Fence) Classify(tool string, input []byte) Verdict {
	if !f.Active() {
		return VerdictInactive
	}
	ctx := callSurface{tool: tool, input: input}
	if f.matchAny(f.deny, ctx) {
		return VerdictForbidden
	}
	if f.inScope(ctx) {
		return VerdictInScope
	}
	return VerdictOutOfBounds
}

// inScope 判定调用是否落在允许清单内。允许清单是操作员声明的【作用域】：
//   - 对每个「被调用触碰、且操作员已声明」的表面（host/port/path/command/tool），
//     调用的该表面值必须全部命中对应 allow 规则，否则即越界（escape）。
//   - 调用必须至少「命中」一个声明表面，否则没有任何声明覆盖它（deny-by-default）。
//
// 例：仅声明 `allow host *.example.com` 时，`curl http://api.evil.org/` 越界（host 未命中），
// 而 `ls -la /data` 也越界（未触碰任何声明表面）；声明 `allow tool Bash` 只约束工具面。
func (f *Fence) inScope(ctx callSurface) bool {
	matched := false
	if hs := ctx.hosts(); len(hs) > 0 {
		if f.declared("host") {
			if !f.allMatch("host", hs) {
				return false
			}
			matched = true
		}
	}
	if ps := ctx.ports(); len(ps) > 0 {
		if f.declared("port") {
			if !f.allMatch("port", ps) {
				return false
			}
			matched = true
		}
	}
	if ps := ctx.paths(); len(ps) > 0 {
		if f.declared("path") {
			if !f.allMatch("path", ps) {
				return false
			}
			matched = true
		}
	}
	if cmd := ctx.command(); cmd != "" {
		if f.declared("command") {
			if !f.allMatch("command", []string{cmd}) {
				return false
			}
			matched = true
		}
	}
	if f.declared("tool") {
		if !f.allMatch("tool", []string{ctx.tool}) {
			return false
		}
		matched = true
	}
	return matched
}

// declared reports whether the operator declared an allow rule on `domain`
// (a rule whose Match is the domain or "all").
func (f *Fence) declared(domain string) bool {
	for _, r := range f.allow {
		if r.Match == domain || r.Match == "all" {
			return true
		}
	}
	return false
}

// allMatch reports whether every value in vals is covered by some allow rule on
// `domain` (Match==domain or Match=="all"). Empty vals → true (nothing to escape).
func (f *Fence) allMatch(domain string, vals []string) bool {
	for _, v := range vals {
		hit := false
		for _, r := range f.allow {
			if r.Match != domain && r.Match != "all" {
				continue
			}
			if globMatch(r.Pattern, v) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

// SurfaceFor returns the representative out-of-bounds surface of a call, used as the
// 越界授权 key. Preference: host > port > command(first-token) > tool. Returns ""
// when the call is actually in-scope (no authorization needed).
func (f *Fence) SurfaceFor(tool string, input []byte) string {
	if !f.Active() {
		return ""
	}
	ctx := callSurface{tool: tool, input: input}
	// 调用已在允许清单内 → 无需授权，无越界表面。
	if f.Classify(tool, input) != VerdictOutOfBounds {
		return ""
	}
	// 越界 host（未被任何 allow host/all 规则匹配）。
	if h := ctx.firstOOBHost(f.allow); h != "" {
		return "host:" + h
	}
	if p := ctx.firstOOBPort(f.allow); p != "" {
		return "port:" + p
	}
	// 命令表面（首 token）比 tool 更精确：授权 "command:ls" 而非 "tool:Bash"。
	if c := ctx.command(); c != "" {
		return "command:" + ctx.firstToken(c)
	}
	return "tool:" + tool
}

// IsAuthorized reports whether `surface` has a live 越界授权.
func (f *Fence) IsAuthorized(surface string) bool {
	if f == nil || f.authz == nil || surface == "" {
		return false
	}
	return f.authz.IsFenceAuthorized(surface)
}

// Authorize records a 越界授权 for `surface`. digest is a short sha256 of the input.
func (f *Fence) Authorize(surface, tool string, input []byte) error {
	if f == nil || f.authz == nil || surface == "" {
		return nil
	}
	_, err := f.authz.AddFenceAuthz(surface, tool, digestInput(input), "human", "")
	return err
}

// --- 规则匹配 ---

// matchAny reports whether any rule in rules matches the call surface.
func (f *Fence) matchAny(rules []FenceRule, c callSurface) bool {
	for _, r := range rules {
		if f.ruleMatches(r, c) {
			return true
		}
	}
	return false
}

// ruleMatches checks one rule against the call across the rule's domain.
func (f *Fence) ruleMatches(r FenceRule, c callSurface) bool {
	switch r.Match {
	case "tool":
		return globMatch(r.Pattern, c.tool)
	case "command":
		return globMatch(r.Pattern, c.command())
	case "host":
		return c.anyHost(func(h string) bool { return globMatch(r.Pattern, h) })
	case "path":
		return c.anyPath(func(p string) bool { return globMatch(r.Pattern, p) })
	case "port":
		return c.anyPort(func(p string) bool { return globMatch(r.Pattern, p) })
	case "all":
		// 通配：命令/工具/任一 host 命中即算命中。
		if globMatch(r.Pattern, c.command()) || globMatch(r.Pattern, c.tool) {
			return true
		}
		return c.anyHost(func(h string) bool { return globMatch(r.Pattern, h) })
	}
	return false
}

// callSurface extracts the matchable surfaces from a tool call.
type callSurface struct {
	tool  string
	input []byte
}

func (c callSurface) command() string {
	if c.tool != "Bash" && c.tool != "shell_open" && c.tool != "shell_send" {
		return ""
	}
	if len(c.input) == 0 {
		return ""
	}
	var in struct {
		Command string `json:"command"`
		Text    string `json:"text"`
	}
	if err := json.Unmarshal(c.input, &in); err != nil {
		return ""
	}
	if in.Command != "" {
		return in.Command
	}
	return in.Text
}

func (c callSurface) firstToken(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	// 去掉 shell 运算符前缀（管道/重定向/连接符），取第一个程序名。
	cmd = strings.TrimLeft(cmd, "|&;<>() \t\n")
	if i := strings.IndexAny(cmd, " \t\n|&;<>()"); i >= 0 {
		return cmd[:i]
	}
	return cmd
}

var reHost = regexp.MustCompile(`(?i)\b(?:https?|ftp)://([^/\s"'<>]+)`)
var reHostBare = regexp.MustCompile(`(?i)\b([a-z0-9.-]+\.[a-z]{2,}(?::\d{1,5})?)(?:[/\s"'<>]|$)`)
var reIPv4 = regexp.MustCompile(`\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d{1,5}))?\b`)
var rePort = regexp.MustCompile(`(?i):(\d{1,5})\b`)
var reFlagPort = regexp.MustCompile(`(?i)(?:--port=|-p\s+|--port\s+)(\d{1,5})\b`)
var reBarePath = regexp.MustCompile(`(?m)(^|\s)(/[^\s"'<>]+)`)

// networkTools 是已知把参数当主机名的工具。裸 host / IPv4 识别仅在这些工具的命令里
// 启用，避免把 `cat file.txt` 这类本地文件路径误判为 host 表面（否则仅声明
// `allow host *.example.com` 时，`curl http://api.example.com/ && cat file.txt`
// 会被错误判越界，且授权键退化为无意义的 `host:file.txt`）。scheme:// 主机不受此门控。
var networkTools = map[string]bool{
	"curl": true, "wget": true, "wget2": true, "aria2c": true,
	"nc": true, "netcat": true, "ncat": true, "socat": true,
	"ping": true, "ping6": true, "ssh": true, "scp": true, "sftp": true,
	"git": true, "dig": true, "host": true, "nslookup": true,
	"telnet": true, "ftp": true, "lftp": true, "rsync": true,
	"traceroute": true, "tracepath": true,
}

// shellWrappers 不改变「是否是网络工具」的判定：`sudo curl`、`env curl` 等仍按
// 其后第一个真实程序（curl）分类。
var shellWrappers = map[string]bool{
	"sudo": true, "env": true, "nohup": true, "timeout": true,
	"command": true, "nice": true, "ionice": true, "setsid": true, "stdbuf": true,
}

func (c callSurface) hosts() []string {
	cmd := c.command()
	if cmd == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(h string) {
		h = stripPort(h)
		h = strings.ToLower(h)
		if h != "" && !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	// scheme:// host：无条件提取（任何工具都算网络访问）。
	for _, m := range reHost.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	// 裸 host / IPv4：仅从「首 token 是网络工具」的命令段提取，避免把
	// `cat file.txt` 这类本地文件路径误判为 host（否则仅声明 `allow host *.example.com`
	// 时，`curl http://api.example.com/ && cat file.txt` 会被错误判越界，授权键退化
	// 为无意义的 host:file.txt）。
	for _, seg := range c.networkSegments() {
		for _, m := range reHostBare.FindAllStringSubmatch(seg, -1) {
			add(m[1])
		}
		for _, m := range reIPv4.FindAllStringSubmatch(seg, -1) {
			add(m[1])
		}
	}
	return out
}

// networkSegments 返回「首 token（跳过 shell 包装器）是网络工具」的命令段。
func (c callSurface) networkSegments() []string {
	segs := c.segments()
	out := make([]string, 0, len(segs))
	for _, seg := range segs {
		if networkTools[firstNonWrapper(seg)] {
			out = append(out, seg)
		}
	}
	return out
}

// segments 把 shell 命令按顶层分隔符切分为一次条调用。引号/子shell 内不做精确解析，
// 足够 Fence 表面判定使用（`curl ... && cat file.txt` → [curl段, cat段]）。
func (c callSurface) segments() []string {
	cmd := c.command()
	if cmd == "" {
		return nil
	}
	var segs []string
	cur := strings.Builder{}
	flush := func() {
		if strings.TrimSpace(cur.String()) != "" {
			segs = append(segs, cur.String())
		}
		cur.Reset()
	}
	for _, r := range cmd {
		switch r {
		case '&', '|', ';', '(', ')', '\n':
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return segs
}

// firstNonWrapper 返回段内第一个真实程序 token（跳过 sudo/env/nohup/... 包装器）。
func firstNonWrapper(seg string) string {
	for _, f := range strings.Fields(seg) {
		f = strings.Trim(f, "|&;<>()\"'`")
		if shellWrappers[f] {
			continue
		}
		return f
	}
	return ""
}

func (c callSurface) ports() []string {
	cmd := c.command()
	if cmd == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	add := func(p string) {
		if p != "" && !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	for _, m := range reFlagPort.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	for _, m := range rePort.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	return out
}

func (c callSurface) paths() []string {
	cmd := c.command()
	if cmd == "" {
		return nil
	}
	var out []string
	seen := map[string]bool{}
	// URL 路径 + 绝对路径。
	for _, m := range reHost.FindAllStringSubmatch(cmd, -1) {
		idx := strings.Index(cmd, m[0])
		if idx < 0 {
			continue
		}
		rest := cmd[idx+len(m[0]):]
		if i := strings.IndexAny(rest, " \t\n\"'<>"); i >= 0 {
			rest = rest[:i]
		}
		if rest == "" || rest[0] != '/' {
			continue
		}
		if !seen[rest] {
			seen[rest] = true
			out = append(out, rest)
		}
	}
	for _, m := range reBarePath.FindAllStringSubmatch(cmd, -1) {
		p := m[2]
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

func (c callSurface) anyHost(fn func(string) bool) bool { return anyMatch(c.hosts(), fn) }
func (c callSurface) anyPort(fn func(string) bool) bool { return anyMatch(c.ports(), fn) }
func (c callSurface) anyPath(fn func(string) bool) bool { return anyMatch(c.paths(), fn) }

func anyMatch(vals []string, fn func(string) bool) bool {
	for _, v := range vals {
		if fn(v) {
			return true
		}
	}
	return false
}

// firstOOBHost returns the first host not covered by any allow host/all rule.
func (c callSurface) firstOOBHost(allow []FenceRule) string {
	for _, h := range c.hosts() {
		covered := false
		for _, r := range allow {
			if r.Match == "host" || r.Match == "all" {
				if globMatch(r.Pattern, h) {
					covered = true
					break
				}
			}
		}
		if !covered {
			return h
		}
	}
	return ""
}

// firstOOBPort returns the first port not covered by any allow port/all rule.
func (c callSurface) firstOOBPort(allow []FenceRule) string {
	for _, p := range c.ports() {
		covered := false
		for _, r := range allow {
			if r.Match == "port" || r.Match == "all" {
				if globMatch(r.Pattern, p) {
					covered = true
					break
				}
			}
		}
		if !covered {
			return p
		}
	}
	return ""
}

func stripPort(h string) string {
	if i := strings.LastIndexByte(h, ':'); i >= 0 {
		if _, err := parsePort(h[i+1:]); err == nil {
			return h[:i]
		}
	}
	return h
}

func parsePort(s string) (int, error) {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0, errNotNum
		}
		n = n*10 + int(r-'0')
	}
	if n == 0 || n > 65535 {
		return 0, errNotNum
	}
	return n, nil
}

var errNotNum = &numError{}

type numError struct{}

func (*numError) Error() string { return "not a port" }

// --- glob → regex ---

// globMatch matches `s` against a glob pattern. `*`/`**` → 任意序列，`?` → 单个字符。
// 其余字符按字面量匹配。host 域名的 `*.domain` 额外匹配其 apex（`*.example.com`
// 同时命中 `example.com`）。
func globMatch(pattern, s string) bool {
	if pattern == "" {
		return s == ""
	}
	// 域名通配特例：`*.example.com` 也匹配 `example.com`（apex 含在通配下）。
	if strings.HasPrefix(pattern, "*.") && strings.Index(pattern, "/") < 0 {
		apex := pattern[2:]
		if apex != "" && strings.EqualFold(apex, s) {
			return true
		}
	}
	re := globToRegex(pattern)
	return re.MatchString(s)
}

// globRegexCache 缓存 pattern → 编译后的正则。live fence loader 每个工具调用都重建
// Fence，同一模式会被反复编译；规则集很小且 pattern 来自操作员声明，缓存有界。
var globRegexCache sync.Map // pattern string → *regexp.Regexp

func globToRegex(pattern string) *regexp.Regexp {
	if v, ok := globRegexCache.Load(pattern); ok {
		return v.(*regexp.Regexp)
	}
	re := compileGlob(pattern)
	globRegexCache.Store(pattern, re)
	return re
}

func compileGlob(pattern string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?i)^")
	for i := 0; i < len(pattern); i++ {
		ch := pattern[i]
		switch ch {
		case '*':
			// `**` 与 `*` 都匹配任意序列（不做跨目录区分，简单可预测）。
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			if strings.ContainsRune(`.+^$()[]{}|\`, rune(ch)) {
				b.WriteByte('\\')
			}
			b.WriteByte(ch)
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return regexp.MustCompile(`(?i)^` + regexp.QuoteMeta(pattern) + `$`)
	}
	return re
}

func digestInput(input []byte) string {
	// FNV-1a 短摘要（16 hex）仅用于授权记忆去重，不要求密码学强度。
	if len(input) == 0 {
		return ""
	}
	const hexdigits = "0123456789abcdef"
	// FNV-1a 短摘要即可用于授权记忆去重，不要求密码学强度。
	h := uint64(14695981039346656037)
	for _, b := range input {
		h ^= uint64(b)
		h *= 1099511628211
	}
	out := make([]byte, 8)
	for i := 0; i < 8; i++ {
		out[i] = hexdigits[(h>>uint(4*(7-i)))&0xf]
	}
	return string(out)
}
