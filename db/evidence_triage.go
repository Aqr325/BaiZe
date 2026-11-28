package db

// evidence_triage.go
//
// 证据驱动分类/分级核心 —— 借鉴「Today Security」（r0eXpeR/today_security）的
// 证据驱动情报方法论，落到白泽的证据链上。全部为纯函数（无副作用、可单测），
// 供 db 存储、agent 准入守卫、server 头条引擎共用。输入一律为字符串，
// 输出为确定的枚举/分数，绝不臆造。
//
// 核心思路：用一套确定性规则把「模型上报的原始字段」折算成可解释的
// 危害原语 + 资产分层 + 五档处置分级 + SSVC 式头条分，替代人工拍脑袋。
// 与 ModelEvidenceGrade 一脉相承：预测性/未证实措辞只能降级，不能升级。

import (
	"fmt"
	"math"
	"regexp"
	"strings"
)

// ── 危害原语（harm primitive）───────────────────────────────────────────────
// 参照 Today Security：按漏洞的「本质危害」而非仅 CVSS 分数分类，驱动 triage。
const (
	HarmRCE          = "rce"                  // 远程代码执行/命令执行/接管/反序列化/内存破坏
	HarmAuthBypass   = "auth_bypass"          // 认证绕过/硬编码凭据/默认口令
	HarmPrivEsc      = "privilege_escalation" // 内核提权/沙箱/容器逃逸
	HarmUnauthorized = "unauthorized"         // 未授权/无认证访问
	HarmFileWrite    = "file_write"           // 任意文件写/上传/任意文件读
	HarmInjection    = "injection"            // SQL/命令/模板注入、XSS、CSRF
	HarmSSRF         = "ssrf"                 // 服务端请求伪造
	HarmInfoLeak     = "info_leak"            // 信息/数据泄露
	HarmDoS          = "dos"                  // 拒绝服务
	HarmOther        = "other"                // 其他/未分类
)

// harmPrimitiveRules 是「关键词 → 危害原语」的确定性规则（小写匹配）。
// 顺序即优先级：越靠前的原语越严重，命中即返回（如「远程代码执行」优先于「注入」）。
var harmPrimitiveRules = []struct {
	keywords  []string
	primitive string
}{
	{[]string{"remote code execution", "rce", "远程代码执行", "命令执行", "任意代码", "code execution", "反序列化", "deserialization", "内存破坏", "memory corruption", "接管", "takeover"}, HarmRCE},
	{[]string{"认证绕过", "绕过认证", "auth bypass", "authentication bypass", "硬编码凭据", "hardcoded credential", "默认口令", "default credential", "弱口令", "weak password"}, HarmAuthBypass},
	{[]string{"提权", "权限提升", "privilege escalation", "沙箱逃逸", "sandbox escape", "容器逃逸", "container escape", "内核", "kernel", "本地提权"}, HarmPrivEsc},
	{[]string{"未授权", "无认证", "未经认证", "unauthorized", "no auth", "无需认证", "免认证"}, HarmUnauthorized},
	{[]string{"任意文件写", "arbitrary file write", "任意文件读", "arbitrary file read", "文件上传", "file upload", "目录遍历", "path traversal", "任意文件"}, HarmFileWrite},
	{[]string{"sql注入", "sql injection", "命令注入", "command injection", "模板注入", "template injection", "注入", "injection", "xss", "跨站", "csrf"}, HarmInjection},
	{[]string{"ssrf", "服务端请求伪造", "server-side request forgery"}, HarmSSRF},
	{[]string{"信息泄露", "数据泄露", "信息泄漏", "敏感信息", "信息暴露", "info leak", "information disclosure", "数据暴露"}, HarmInfoLeak},
	{[]string{"拒绝服务", "dos", "denial of service"}, HarmDoS},
}

// HarmPrimitive 从漏洞名称/摘要/类别的拼接文本中确定危害原语。
// 未命中任何规则返回 HarmOther。
func HarmPrimitive(text string) string {
	low := strings.ToLower(text)
	for _, r := range harmPrimitiveRules {
		for _, kw := range r.keywords {
			if strings.Contains(low, kw) {
				return r.primitive
			}
		}
	}
	return HarmOther
}

// HarmPrimitiveLabel 返回危害原语的中文可读名（前端展示用）。
func HarmPrimitiveLabel(p string) string {
	switch p {
	case HarmRCE:
		return "远程代码执行"
	case HarmAuthBypass:
		return "认证绕过"
	case HarmPrivEsc:
		return "提权/逃逸"
	case HarmUnauthorized:
		return "未授权访问"
	case HarmFileWrite:
		return "任意文件写/读"
	case HarmInjection:
		return "注入/跨站"
	case HarmSSRF:
		return "SSRF"
	case HarmInfoLeak:
		return "信息泄露"
	case HarmDoS:
		return "拒绝服务"
	default:
		return "其他"
	}
}

// ── 否定/将来时投机措辞检测（防误判）──────────────────────────────────────
// 参照 Today Security：识别「尚未发现在野利用」「暂无公开 PoC」「预计可能出现」
// 等措辞，不把辟谣/预警/预测当既成利用事实。白泽侧用于证据链准入守卫：
// 命中投机措辞的发现不得升级证据等级或严重度（只能降、不能升）。

// speculativeMarkers 是触发投机/未证实降级的措辞（小写匹配，含中文）。
var speculativeMarkers = []string{
	"尚未发现在野利用", "未发现在野利用", "尚未发现", "暂无公开poc", "暂无poc", "暂无公开",
	"尚未公开", "预计可能出现", "预计将", "预计", "可能被", "或将", "将来时",
	"推测", "疑似", "可能", "或许", "也许", "大概", "说不定", "不排除",
	"尚未证实", "未确认", "未验证", "待验证", "待补充", "待确认", "存疑",
	"暂未见", "暂无证据", "尚无证据", "未发现", "不清楚", "未知",
}

// SpeculativeMarkers 返回命中投机/未证实措辞的原文子串（去重、按原文顺序）。
// 空切片表示文本没有投机措辞。
func SpeculativeMarkers(text string) []string {
	low := strings.ToLower(text)
	var out []string
	seen := map[string]bool{}
	for _, m := range speculativeMarkers {
		if strings.Contains(low, m) && !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	return out
}

// IsSpeculative 报告文本是否含投机/未证实措辞。
func IsSpeculative(text string) bool { return len(SpeculativeMarkers(text)) > 0 }

// ── 抗串烧/信号传染隔离（多 CVE 综述）─────────────────────────────────────
// 参照 Today Security：多漏洞综述（补丁日综述、多厂商 KEV 合集、安全周报）绝不
// 作为合并不同 CVE 的依据；已有专题报道时，未点名本漏洞的汇总报道不得贡献
// 「在野利用」信号。白泽侧：若上报文本是「多 CVE 综述」且未明确点名单个漏洞，
// 禁止其把 remote/「在野」信号传染给具体 finding。

var cvePattern = regexp.MustCompile(`(?i)CVE-\d{4}-\d{4,}`)

// summaryMarkers 是「综述/汇总」特征词（小写匹配）。
var summaryMarkers = []string{
	"综述", "汇总", "合集", "周报", "盘点", "盘点", "多家厂商", "多厂商",
	"kev合集", "kev 合集", "漏洞合集", "多漏洞", "批量", "多个cve", "多cve",
	"security week", "roundup", "汇总报告", "批量通告",
}

// IsMultiCVESummary 报告文本是否为「多 CVE 综述/汇总」。
// 判定：同时命中 (a) ≥2 个不同 CVE 编号，且 (b) 含综述特征词。
func IsMultiCVESummary(text string) bool {
	low := strings.ToLower(text)
	hasSummaryWord := false
	for _, m := range summaryMarkers {
		if strings.Contains(low, m) {
			hasSummaryWord = true
			break
		}
	}
	if !hasSummaryWord {
		return false
	}
	matches := cvePattern.FindAllString(text, -1)
	distinct := map[string]bool{}
	for _, c := range matches {
		distinct[strings.ToUpper(c)] = true
	}
	return len(distinct) >= 2
}

// ── 资产分层（asset tier）────────────────────────────────────────────────
// 参照 Today Security Tier S/A：真实攻防视角的核心资产分层。
//   - s：公网边界设备（防火墙/VPN/网关）、高频中间件与 Web 框架、虚拟化/容器、
//     企业核心软件、国内主流政企 OA
//   - a：内核、主流开发运行时、AI/Agent 基础设施
//   - b：一般业务应用/服务/端点
//   - c：低价值/内部低敏
const (
	AssetTierS = "s"
	AssetTierA = "a"
	AssetTierB = "b"
	AssetTierC = "c"
)

var assetTierSRules = []string{
	"firewall", "防火墙", "vpn", "网关", "gateway", "负载均衡", "load balancer",
	"nginx", "apache", "tomcat", "iis", "spring", "struts", "weblogic", "websphere",
	"jenkins", "gitlab", "docker", "k8s", "kubernetes", "vmware", "esxi", "kvm",
	// 国内主流政企 OA（按厂商点名，避免裸 "oa" 误匹配 road/approach/load）。
	"泛微", "致远", "用友", "金蝶", "蓝凌", "协同办公", "oa系统", "oa办公", "erp", "crm",
}

// 注意：刻意不用裸 "ai"/"rag"/"oa"——它们会误命中 subdomain(mai)/storage/road 等。
var assetTierARules = []string{
	"内核", "kernel", "运行时", "runtime", "jdk", "python", "node", "golang", "go runtime",
	"llm", "大模型", "agent服务", "mcp服务", "mcp server", "推理服务", "embedding",
	"向量库", "向量检索", "model service", "模型服务", "ai网关", "ai gateway",
}

// AssetTier 从资产的描述文本推导分层（s > a > b > c）。
// 资产表无独立 zone/kind 列，故由调用方把资产的实际描述字段
// （type/app_name/service_name/technologies/category/domain）拼接成 text 传入。
// 规则：边界/中间件/容器/政企 OA → s；内核/运行时/AI-Agent 基建 → a；
// 公网域名/IP/子域 → b；其余 → c。
func AssetTier(text string) string {
	low := strings.ToLower(text)
	if containsAny(low, assetTierSRules) {
		return AssetTierS
	}
	if containsAny(low, assetTierARules) {
		return AssetTierA
	}
	if strings.Contains(low, "root_domain") || strings.Contains(low, "subdomain") ||
		strings.Contains(low, "internal") || strings.Contains(low, "private") ||
		strings.Contains(low, "内网") || strings.Contains(low, "私有") ||
		strings.HasPrefix(low, "ip") {
		return AssetTierB
	}
	return AssetTierC
}

// MaxAssetTier 返回一组资产分层中的最高优先级（s > a > b > c）。
// 空列表返回 AssetTierC（无资产 → 按低敏对待）。
func MaxAssetTier(tiers []string) string {
	best := AssetTierC
	for _, t := range tiers {
		switch t {
		case AssetTierS:
			return AssetTierS
		case AssetTierA:
			if best != AssetTierS {
				best = AssetTierA
			}
		case AssetTierB:
			if best != AssetTierS && best != AssetTierA {
				best = AssetTierB
			}
		}
	}
	return best
}

func containsAny(text string, rules []string) bool {
	for _, r := range rules {
		if strings.Contains(text, r) {
			return true
		}
	}
	return false
}

// AssetTierLabel 返回资产分层中文名。
func AssetTierLabel(t string) string {
	switch t {
	case AssetTierS:
		return "Tier S（核心资产）"
	case AssetTierA:
		return "Tier A（高价值基建）"
	case AssetTierB:
		return "Tier B（一般业务）"
	default:
		return "Tier C（低敏）"
	}
}

// ── 五档「需要尽快处置」稳定分级（含防抖语义）────────────────────────────
// 参照 Today Security 五档优先清单。triage_tier 越小越优先。防抖由调用方实现：
// 排序时按「证据首次出现时间（created_at）」做稳定 tiebreak，普通后续报道不
// 打乱顺序，只有出现新证据（grade 升级/severity 升级）才升档。

const (
	TriageTier1 = 1 // 在野利用·未见修复（remote_verified + 高危）
	TriageTier2 = 2 // 在野利用（remote_verified）
	TriageTier3 = 3 // 在野利用·已有修复（remote_verified + 已修复）
	TriageTier4 = 4 // 高危 PoC 公开·未见修复（RCE/认证绕过/逃逸，未授权或核心组件或已修复前）
	TriageTier5 = 5 // 核心资产严重预警（Tier S/A + 未授权 RCE/认证绕过）
	TriageTier6 = 6 // 其余（跟踪）
)

// TriageTier 计算五档处置分级（1 最优先 → 6 跟踪）。
// severity/evidenceGrade/harmPrimitive/assetTier/status 均为枚举字符串。
// 与证据链对齐：self_claim（模型仅自述、无独立验证）按「待验证线索」对待，
// 不挤进高危确认档（Tier1-4）；但核心资产（S/A）+ 高危严重自述仍进 Tier5
// 预警（提前提示排查暴露面）。local_effect/remote_verified 才是「已独立验证」。
func TriageTier(severity, evidenceGrade, harmPrimitive, assetTier, status string) int {
	hi := severity == "critical" || severity == "high"
	remote := evidenceGrade == EvidenceGradeRemoteVerified
	local := evidenceGrade == EvidenceGradeLocalEffect
	resolved := status == "fixed" || status == "resolved" || status == "risk_accepted"
	coreAsset := assetTier == AssetTierS || assetTier == AssetTierA
	serious := harmPrimitive == HarmRCE || harmPrimitive == HarmAuthBypass || harmPrimitive == HarmPrivEsc

	switch {
	case remote && hi && !resolved:
		return TriageTier1
	case remote && resolved:
		return TriageTier3
	case remote:
		return TriageTier2
	case coreAsset && hi && serious:
		return TriageTier5 // 核心资产严重预警（含自述线索也提前提示排查暴露面）
	case local && serious && hi && !resolved:
		return TriageTier4 // 高危 PoC 公开·未见修复（本地独立验证）
	default:
		return TriageTier6
	}
}

// TriageTierLabel 返回分级中文名。
func TriageTierLabel(t int) string {
	switch t {
	case TriageTier1:
		return "在野利用·未见修复"
	case TriageTier2:
		return "在野利用"
	case TriageTier3:
		return "在野利用·已有修复"
	case TriageTier4:
		return "高危 PoC 公开·未见修复"
	case TriageTier5:
		return "核心资产严重预警"
	default:
		return "跟踪"
	}
}

// ── SSVC 式头条决策（可解释）─────────────────────────────────────────────
// 参照 Today Security SSVC 头条引擎：回答「此刻全网最该处理哪个」。
// 白泽侧为确定性可解释打分：分数越高越该优先。rationale 逐条说明贡献理由，
// 与证据链的「透明性」一致——每条都给出「为什么排这里」。

// HeadlineRank 计算头条优先级分（0–100）与逐条理由。
// ageHours 为发现年龄（小时），用于时间衰减；halfLifeHours 控制衰减速率。
func HeadlineRank(severity, evidenceGrade, harmPrimitive, assetTier, status string, ageHours, halfLifeHours float64) (float64, []string) {
	tier := TriageTier(severity, evidenceGrade, harmPrimitive, assetTier, status)
	var score float64
	var rationale []string

	// 基准：分级越高分越高。
	base := map[int]float64{
		TriageTier1: 90, TriageTier2: 78, TriageTier3: 66,
		TriageTier4: 54, TriageTier5: 42, TriageTier6: 20,
	}[tier]
	score += base
	rationale = append(rationale, "基准分级 "+TriageTierLabel(tier))

	// 危害原语加成。
	if harmPrimitive == HarmRCE || harmPrimitive == HarmPrivEsc {
		score += 6
		rationale = append(rationale, "危害原语 "+HarmPrimitiveLabel(harmPrimitive))
	} else if harmPrimitive == HarmAuthBypass || harmPrimitive == HarmUnauthorized {
		score += 3
		rationale = append(rationale, "危害原语 "+HarmPrimitiveLabel(harmPrimitive))
	}

	// 核心资产加成。
	if assetTier == AssetTierS {
		score += 6
		rationale = append(rationale, "核心资产 Tier S")
	} else if assetTier == AssetTierA {
		score += 3
		rationale = append(rationale, "高价值资产 Tier A")
	}

	// 时间衰减：越新越优先，防止老漏洞长期霸屏。
	if halfLifeHours <= 0 {
		halfLifeHours = 48
	}
	decay := GravityDecay(ageHours, halfLifeHours)
	score += 10 * decay
	rationale = append(rationale, "时间衰减 x"+formatDecay(decay))

	if score > 100 {
		score = 100
	}
	return score, rationale
}

// GravityDecay 重力衰减：0.5^(age/halfLife)。age=0 → 1.0（全新），
// age=halfLife → 0.5，age→∞ → 0。
func GravityDecay(ageHours, halfLifeHours float64) float64 {
	if halfLifeHours <= 0 {
		return 1
	}
	if ageHours <= 0 {
		return 1
	}
	return math.Pow(0.5, ageHours/halfLifeHours)
}

func formatDecay(d float64) string {
	return fmt.Sprintf("%.2f", d)
}
