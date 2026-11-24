package server

// Skill precheck — 在 skill 内容进入 agent 上下文（或其脚本被 ${SKILL_DIR} 引用）前
// 做一道静态预检。对应 skill 供应链安全审计 §2.1：skill.LoadDir 本身零校验，
// 这里在白泽侧补一层「无正当用途的最高危模式」硬拦。
//
// 设计原则（重要，避免误伤）：
//   - 只拦「无正当用途的隐蔽破坏模式」，不拦显式渗透方法论。渗透类 skill
//     （pentest-assistant / cyber-monster）教 agent 执行 Invoke-Expression、
//     curl 管道、SQL 注入语句——这些是显式指令，由 RoE/授权边界管，不是预检的活。
//   - 恶意 skill 的特征是隐蔽性：混淆解码即执行、远程加载即执行、条件触发删库/
//     插账号。这些才是预检的目标。
//   - 宁可漏不可错杀：误伤会让用户显式启用的合法 skill 不可用。
//
// 结论分级：
//   - BlockReason 非空 → 该 skill 应隔离（不进 reg，模型看不到）。
//   - WarnReason 非空 → 记审计告警，但不阻断（如硬编码外传域名，语义需人工判）。
import (
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Autumn-27/norma/skill"
)

// ---- 黑名单正则 ----

// 正文执行指令形态：SKILL.md 给 agent 的指令里出现「解码/下载后即执行」= 要求
// agent 干一件隐蔽的事，这是恶意 skill 的典型形态。不匹配裸 Invoke-Expression /
// 裸 eval（渗透方法论也是这么写的，那是显式指令）。
var skillBodyExec = []*regexp.Regexp{
	// curl/wget … | sh —— 远程加载即执行
	regexp.MustCompile(`(?i)\b(curl|wget)\b[^\n|]*\|\s*(ba|z|da|fi)?sh\b`),
	// base64 -d | sh —— 混淆解码即执行
	regexp.MustCompile(`(?i)\bbase64\s+(-d|--decode|--decoding)\s*\|\s*(ba|z|da|fi)?sh\b`),
	// echo <b64> | base64 -d | sh —— 内联混淆
	regexp.MustCompile(`(?i)\b(echo|printf)\b[^\n|]*\|\s*base64\s+(-d|--decode)\s*\|\s*(ba|z|da|fi)?sh\b`),
	// powershell -enc —— 编码 PowerShell（-enc 或 -EncodedCommand 均可）
	regexp.MustCompile(`(?i)\bpowershell\b[^\n]*-{1,2}(enc|encodedcommand)\b`),
	// python -c '...exec/eval/base64...' —— 单行混淆执行
	regexp.MustCompile(`(?i)\b(python\d*|node)\s+-[cC]\s+["'][^"']*\b(base64|exec|eval|b64decode)\b`),
	// js eval(await fetch(…)) —— 远程加载执行
	regexp.MustCompile(`(?i)\beval\s*\(\s*(await\s+)?fetch\s*\(`),
	// 条件触发删库：SKILL.md 里明确要删 user/admin 表（教学会写 DROP TABLE 但不带
	// user/account，故限定到用户表，裸 DROP TABLE 不拦）。
	regexp.MustCompile(`(?i)\b(DROP|TRUNCATE)\s+TABLE\s+\w*(user|account|admin|member|credential|shadow)s?\b`),
	// 插预设账号：INSERT INTO admin/account … 含口令/hash 字段
	regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+\w*(admin|account|user|member)\b[^\n]*\b(password|passwd|pwd|hash|salt|secret)\b`),
}

// 脚本恶意模式：会被 agent 经 ${SKILL_DIR} 执行的 .py/.sh/.js/.ps1。查全量 SQL 破坏
// 与混淆，因为脚本是真实执行体，不是教学文本。
var skillScriptMal = []*regexp.Regexp{
	// 删库/清表/删用户
	regexp.MustCompile(`(?i)\b(DROP|TRUNCATE)\s+TABLE\s+\w*(user|account|admin|member|credential|shadow)\b`),
	regexp.MustCompile(`(?i)\bDELETE\s+FROM\s+\w*(user|account|admin|member|credential|shadow)\b`),
	// 插预设账号（含口令/hash）
	regexp.MustCompile(`(?i)\bINSERT\s+INTO\s+\w*(admin|account|user|member)\b[^\n]*\b(password|passwd|pwd|hash|salt|secret)\b`),
	// 混淆解码即执行
	// 混淆解码即执行：仅同一语句/行内（真载荷是 eval(atob(x)) 单行注入；恶意软件
	// 分析脚本把 atob/eval 当检测字面量且跨行，会误判——故限定同行，跨行漏检
	// 接受（宁可漏不可错杀），跨行疑点走 WARN 由人工判。
	regexp.MustCompile(`(?i)\b(base64|b64)\s*\.\s*(b64decode|decodebytes)\s*\([^)]*\)\s*(\.decode\s*\([^)]*\))?(=>|->|=)[^\n]{0,60}(exec|eval|system|subprocess|popen)`),
	regexp.MustCompile(`(?i)\b(atob|FromBase64String)\s*\([^)]*\)[^\n]{0,60}(eval|exec|System\.Diagnostics\.Process)`),
	// 包装式：eval(atob(x)) / eval(Buffer.from(x,'base64')) —— 解码结果直接执行
	regexp.MustCompile(`(?i)\beval\s*\(\s*(atob|FromBase64String|Buffer\.from)\s*\(`),
	// JS: Buffer.from(x,'base64') → eval/new Function —— 解码即执行（同行）
	regexp.MustCompile(`(?i)\bBuffer\.from\s*\([^)]*['"]base64['"]\)[^\n]{0,60}(eval|new\s+Function)\b`),
	// 远程加载执行
	regexp.MustCompile(`(?i)\beval\s*\(\s*(await\s+)?fetch\s*\(`),
	// os.system 内嵌破坏指令
	regexp.MustCompile(`(?i)\bos\.system\s*\([^)]*(DROP|TRUNCATE|DELETE\s+FROM|Invoke-Expression)[^)]*\)`),
}

// 脚本风险信号（warn 不 block）：语义需人工判，如 shell=True（红队/威胁模拟
// skill 里是设计选择，不是攻击；真正的注入要看是否传了外部不可信数据——静态
// 预检做不了数据流，故只记审计让人工确认）。
var skillScriptWarn = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\bsubprocess\.(run|Popen|call)\s*\([^)]*shell\s*=\s*True[^)]*\)`),
}

// 外传检测：只对「网络发送调用」（requests.post/put/patch、fetch POST/PUT、
// urllib 数据 POST）到非白名单 host 记 WARN——这才是潜在数据外传。requests.get
// 拉情报、文档/注释里的 URL、测试占位域（evil.com/metadata.google.internal 等
// SSRF 例题）一概不报，避免对大型安全 skill 刷屏。
// RE2 不支持负向先行断言，故用「正则提取 host + 白名单 map」判定。
var skillSendURL = []*regexp.Regexp{
	// requests.post/put/patch("https://...") —— URL 恒为分组 1（方法用非捕获组）
	regexp.MustCompile(`(?i)\brequests\.(?:post|put|patch)\s*\(\s*["'](https?://[^"']+)`),
	// urllib.request.urlopen/Request("https://...")
	regexp.MustCompile(`(?i)\burllib\.(?:request\.)?(?:urlopen|Request)\s*\(\s*["'](https?://[^"']+)`),
	// fetch("https://...", {method: POST/PUT/PATCH ...})
	regexp.MustCompile(`(?i)\bfetch\s*\(\s*["'](https?://[^"']+)["'][^)]*\{[^}]*method\s*:\s*["'](?:POST|PUT|PATCH)`),
}

var skillExfilAllow = map[string]bool{
	"localhost": true, "127.0.0.1": true,
	"example.com": true, "example.org": true, "example.net": true,
	"virustotal.com": true, "www.virustotal.com": true, "abuseipdb.com": true, "api.abuseipdb.com": true,
	"crt.sh": true, "api.epss": true, "cisa.gov": true, "www.cisa.gov": true,
	"nvd.nist.gov": true, "services.nvd.nist.gov": true,
	"raw.githubusercontent.com": true, "registry.npmjs.org": true, "api.npmjs.org": true,
	"pypi.org": true, "files.pythonhosted.org": true,
	"github.com": true, "api.github.com": true, "gitlab.com": true,
	// 大型安全 skill 的常用正规情报/工具 API
	"urlscan.io": true, "api.shodan.io": true, "mb-api.abuse.ch": true, "threatfox-api.abuse.ch": true,
	"api.securitytrails.com": true, "api.hunter.io": true, "otx.alienvault.com": true,
	"api.first.org": true, "attack.mitre.org": true, "cti-taxii.mitre.org": true, "taxii.mitre.org": true,
	"graph.microsoft.com": true, "schemas.microsoft.com": true, "login.microsoftonline.com": true,
	"api.msrc.microsoft.com": true, "api.loganalytics.io": true, "schema.management.azure.com": true,
	"learn.microsoft.com": true, "docs.microsoft.com": true,
	"api.cloudflare.com": true, "console.cloud.google.com": true, "www.googleapis.com": true,
	"accounts.google.com": true, "iap.googleapis.com": true, "dns.google": true, "docs.google.com": true,
	"api.crowdstrike.com": true, "api.tailscale.com": true, "api.nextdns.io": true,
	"config.private.zscaler.com": true, "api.sase.paloaltonetworks.com": true, "auth.apps.paloaltonetworks.com": true,
	"api.any.run": true, "trivy.dev": true, "v2.kubesec.io": true, "helm.cilium.io": true,
	"canarytokens.org": true, "haveibeenpwned.com": true, "checklists.nist.gov": true,
	"events.pagerduty.com": true, "api.ransomware.live": true, "id-ransomware.malwarehunterteam.com": true,
	"blockchain.info": true, "check.torproject.org": true, "hstspreload.org": true,
	"urlhaus-api.abuse.ch": true, "malpedia.caad.fkie.fraunhofer.de": true,
	"stat.ripe.net": true, "rdap.org": true, "aadinternals.com": true, "adsecurity.org": true,
	"thehacker.recipes": true, "www.thehacker.recipes": true, "engage.mitre.org": true,
	"lolbas-project.github.io": true, "ericzimmerman.github.io": true, "aquasecurity.github.io": true,
	"docs.velociraptor.app": true, "osquery.io": true, "plaso.readthedocs.io": true,
	"bloodhound.specterops.io": true, "www.nomoreransom.org": true, "ico.org.uk": true,
	"gdpr-info.eu": true, "www.w3.org": true, "schemas.xmlsoap.org": true, "schemas.android.com": true,
	"json.schemastore.org": true, "schema.getpostman.com": true, "rekor.sigstore.dev": true,
	"token.actions.githubusercontent.com": true, "rubygems.org": true,
	"astral.sh": true, "tenant.saviyntcloud.com": true, "your-org.okta.com": true,
	"tap-api-v2.proofpoint.com": true, "us-api.mimecast.com": true, "api.target.com": true,
	"metadata.google.internal": true, "api.example.com": true,
}

// hostAllowed 判定一个 host 是否属于可信/占位域。
func hostAllowed(host string) bool {
	host = strings.ToLower(host)
	if skillExfilAllow[host] {
		return true
	}
	// 目标/测试占位域（api-recon 等按目标变量或占位符引用）
	if strings.HasPrefix(host, "test.") || strings.HasPrefix(host, "target.") ||
		strings.Contains(host, ".test") || strings.Contains(host, ".example") ||
		strings.Contains(host, ".invalid") || strings.Contains(host, "localhost") {
		return true
	}
	return false
}

// exfilSendHost 返回 content 里「发送调用到非白名单 host」的第一个 host。
func exfilSendHost(content string) string {
	for _, re := range skillSendURL {
		for _, m := range re.FindAllStringSubmatch(content, -1) {
			host := extractHost(m[1])
			if host != "" && !hostAllowed(host) {
				return host
			}
		}
	}
	return ""
}

// extractHost 从 URL 里剥出 host（http:// 或 https:// 后的第一段，含端口剔除）。
func extractHost(u string) string {
	u = strings.TrimRight(u, `"'`)
	u = strings.TrimSpace(u)
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[:i]
	}
	return rest
}

// 大小配额：SKILL.md / 单个脚本超限即隔离（防巨型 payload 撑爆上下文）。
const (
	skillBodyMaxBytes   = 1 << 20 // 1MB
	skillScriptMaxBytes = 5 << 20 // 5MB
)

// SkillPrecheck 是单个 skill 的预检结论。
type SkillPrecheck struct {
	BlockReason string // 非空 = 隔离
	WarnReason  string // 非空 = 审计告警（不阻断）
}

// PrecheckSkill 预检一个 skill：读正文 + 遍历其目录下可执行脚本。
// skill 必须来自文件系统（Dir 非空）；Dir 为空时只查正文。
func PrecheckSkill(s skill.Skill) SkillPrecheck {
	var pc SkillPrecheck

	// 1. 正文大小
	if len(s.Instructions) > skillBodyMaxBytes {
		pc.BlockReason = setReason(pc.BlockReason, "SKILL.md 正文超限")
		return pc
	}
	// 2. 正文执行指令形态
	for _, re := range skillBodyExec {
		if re.MatchString(s.Instructions) {
			pc.BlockReason = setReason(pc.BlockReason, "正文命中危险执行形态: "+re.String())
		}
	}
	// 3. 目录下脚本
	if s.Dir == "" {
		return pc
	}
	_ = filepath.WalkDir(s.Dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			base := filepath.Base(path)
			if base == "node_modules" || base == ".git" || base == ".venv" || base == "venv" ||
				base == "dist" || base == "build" || base == "__pycache__" {
				return filepath.SkipDir
			}
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		switch ext {
		case ".py", ".sh", ".js", ".ps1", ".ts", ".rb", ".bash", ".zsh":
		default:
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		if fi.Size() > skillScriptMaxBytes {
			pc.BlockReason = setReason(pc.BlockReason, "脚本超限: "+filepath.Base(path))
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		content := string(data)
		for _, re := range skillScriptMal {
			if re.MatchString(content) {
				pc.BlockReason = setReason(pc.BlockReason, "脚本命中恶意模式("+shortRule(re.String())+"): "+filepath.Base(path))
			}
		}
		for _, re := range skillScriptWarn {
			if re.MatchString(content) {
				pc.WarnReason = setReason(pc.WarnReason, "脚本含风险信号("+shortRule(re.String())+"): "+filepath.Base(path))
			}
		}
		if h := exfilSendHost(content); h != "" {
			pc.WarnReason = setReason(pc.WarnReason, "脚本含外传发送(需人工确认): "+filepath.Base(path)+" → "+h)
		}
		return nil
	})
	return pc
}

func setReason(cur, add string) string {
	if cur == "" {
		return add
	}
	return cur + "; " + add
}

func shortRule(s string) string {
	// 正则太长时截断，避免日志刷屏
	const n = 60
	if len(s) > n {
		return s[:n] + "…"
	}
	return s
}

// logSkillPrecheck 把预检结论落日志（供 wireAgentAugment 调用）。
func logSkillPrecheck(name string, pc SkillPrecheck) {
	if pc.BlockReason != "" {
		log.Printf("[skill-precheck] 隔离 skill=%q: %s", name, pc.BlockReason)
	}
	if pc.WarnReason != "" {
		log.Printf("[skill-precheck] 告警 skill=%q: %s", name, pc.WarnReason)
	}
}
