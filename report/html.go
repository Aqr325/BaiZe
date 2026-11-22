package report

import (
	"fmt"
	"html"
	"strings"
)

// severity 展示顺序与中文标签（报告面向客户，用中文等级名）。
var sevOrder = []string{"critical", "high", "medium", "low", "info"}

var sevLabel = map[string]string{
	"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "信息",
}

var sevColor = map[string]string{
	"critical": "#7f1d1d", "high": "#b91c1c", "medium": "#b45309", "low": "#1d4ed8", "info": "#475569",
}

// Remediations 给单个 finding 返回修复建议。vulnclass/name 自由文本，按关键词匹配。
func Remediations(vulnClass, name string) []string {
	k := strings.ToLower(vulnClass + " " + name)
	var out []string
	add := func(s ...string) { out = append(out, s...) }
	switch {
	case strings.Contains(k, "sqli") || strings.Contains(k, "sql注入") || strings.Contains(k, "sql 注入"):
		add("全部 SQL 语句改为参数化查询/预编译语句，禁止字符串拼接；", "数据库账号遵循最小权限，禁用 root/sa 直连业务；", "上线前用 sqlmap 等工具对参数面做回归验证。")
	case strings.Contains(k, "xss") || strings.Contains(k, "跨站"):
		add("对输出到 HTML/属性/JS 上下文的用户输入做上下文感知转义；", "引入 Content-Security-Policy 响应头收敛脚本来源；", "富文本场景改用白名单 sanitizer（如 DOMPurify）。")
	case strings.Contains(k, "ssrf"):
		add("服务端请求目标走白名单校验，禁止用户输入直连内网地址；", "解析域名后再校验解析结果 IP（防 DNS rebinding），屏蔽内网网段；", "出网请求统一经代理并禁用 file/gopher 等危险协议。")
	case strings.Contains(k, "rce") || strings.Contains(k, "命令注入") || strings.Contains(k, "命令执行") || strings.Contains(k, "代码执行"):
		add("避免调用系统命令拼接用户输入，改用库函数/参数化 API；", "必须调用时对输入做严格白名单校验并转义 shell 元字符；", "应用进程降权运行并限制可执行目录。")
	case strings.Contains(k, "弱口令") || strings.Contains(k, "默认密码") || strings.Contains(k, "口令"):
		add("立即修改相关账号口令，排查同口令横向使用；", "启用强密码策略与登录失败锁定；", "关键系统接入 MFA 多因素认证。")
	case strings.Contains(k, "未授权") || strings.Contains(k, "越权"):
		add("接口统一接入鉴权中间件，拒绝匿名访问敏感端点；", "水平越权：资源归属校验（owner/session 绑定）；", "补充自动化用例覆盖「未登录/低权用户」访问矩阵。")
	case strings.Contains(k, "泄露") || strings.Contains(k, "敏感信息") || strings.Contains(k, "信息泄露"):
		add("下线泄露源并轮换已暴露的密钥/凭据；", "生产环境关闭调试输出与详细报错回显；", "代码仓库/网盘/日志面做敏感信息扫描清理。")
	case strings.Contains(k, "目录遍历") || strings.Contains(k, "路径穿越") || strings.Contains(k, "traversal"):
		add("文件路径处理统一走白名单根目录 + filepath.Clean 规范化；", "禁用 .. 序列与绝对路径输入；", "文件服务进程降权并限制可读目录范围。")
	case strings.Contains(k, "上传"):
		add("上传文件类型走服务端魔数校验而非仅前端扩展名；", "存储目录禁用执行权限，重命名落盘；", "与 Web 服务物理隔离静态资源域。")
	case strings.Contains(k, "反序列化"):
		add("升级受影响组件至修复版本；", "反序列化入口增加类型白名单校验；", "避免接收不可信来源的序列化数据。")
	case strings.Contains(k, "组件") || strings.Contains(k, "版本") || strings.Contains(k, "cve") || strings.Contains(k, "漏洞编号"):
		add("按公告升级组件至官方修复版本；", "无法升级时启用官方缓解措施或虚拟补丁；", "纳入组件版本基线，定期做 SCA 扫描。")
	case strings.Contains(k, "配置") || strings.Contains(k, "中间件") || strings.Contains(k, "管理后台"):
		add("按安全基线收敛中间件配置（最小化默认开放项）；", "管理后台收敛访问来源并强认证；", "关闭示例应用与默认账号。")
	default:
		add("复核该漏洞影响面，按最小权限与输入校验原则加固；", "修复后在测试环境复验，确认利用条件已消除。")
	}
	return out
}

// HTML 渲染专业渗透测试报告（可打印 A4 版式）。
func HTML(in Input) string {
	fs := make([]findingView, 0, len(in.Findings))
	counts := map[string]int{}
	for _, n := range in.Findings {
		f := parseFinding(n)
		s := nz(f.Severity, "info")
		if _, ok := sevLabel[s]; !ok {
			s = "info"
		}
		counts[s]++
		fs = append(fs, f)
	}
	sortFindings(fs)

	var sb strings.Builder
	writeHead(&sb, in)
	writeCover(&sb, in)
	writeSummary(&sb, in, counts)
	writeFindings(&sb, fs)
	sb.WriteString("</main></body></html>")
	return sb.String()
}

func writeHead(sb *strings.Builder, in Input) {
	title := html.EscapeString(nz(in.Title, "渗透测试报告"))
	fmt.Fprintf(sb, `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">
<title>%s</title><style>
@page{size:A4;margin:18mm}
*{box-sizing:border-box}
body{font-family:"Microsoft YaHei","PingFang SC",sans-serif;color:#1e293b;margin:0;font-size:14px;line-height:1.7}
main{max-width:800px;margin:0 auto;padding:32px}
.cover{border-bottom:3px solid #0f172a;padding:48px 0 24px;text-align:center}
.cover h1{font-size:26px;margin:0 0 12px}
.cover .meta{color:#475569;font-size:13px}
.meta-grid{display:table;width:100%%;margin:24px 0;border:1px solid #e2e8f0;border-radius:8px}
.meta-grid .row{display:table-row}
.meta-grid .cell{display:table-cell;padding:10px 16px;border-bottom:1px solid #e2e8f0;font-size:13px}
.meta-grid .cell:first-child{width:110px;color:#64748b;background:#f8fafc}
h2{font-size:19px;border-left:4px solid #0f172a;padding-left:10px;margin:36px 0 14px}
table.stats{width:100%%;border-collapse:collapse;margin:12px 0}
table.stats th,table.stats td{border:1px solid #e2e8f0;padding:8px 12px;text-align:center;font-size:13px}
table.stats th{background:#f8fafc;color:#475569}
.badge{display:inline-block;color:#fff;font-size:12px;padding:2px 10px;border-radius:10px}
.finding{border:1px solid #e2e8f0;border-radius:8px;margin:16px 0;overflow:hidden}
.finding .hd{padding:10px 16px;background:#f8fafc;border-bottom:1px solid #e2e8f0;display:flex;gap:10px;align-items:center}
.finding .hd .nm{font-weight:700;font-size:15px}
.finding .bd{padding:12px 16px}
.finding pre{background:#0f172a;color:#e2e8f0;padding:12px;border-radius:6px;overflow-x:auto;font-size:12px}
.remediation{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:6px;padding:10px 14px;margin-top:10px;font-size:13px}
.remediation ol{margin:6px 0 0;padding-left:20px}
.foot{margin-top:40px;color:#94a3b8;font-size:12px;text-align:center;border-top:1px solid #e2e8f0;padding-top:14px}
@media print{.finding{break-inside:avoid}}
</style></head><body><main>`, title)
}

func writeCover(sb *strings.Builder, in Input) {
	fmt.Fprintf(sb, `<div class="cover"><h1>渗透测试报告</h1><div class="meta">%s</div></div>
<div class="meta-grid">
<div class="row"><div class="cell">任务名称</div><div class="cell">%s</div></div>
<div class="row"><div class="cell">测试目标</div><div class="cell">%s</div></div>
<div class="row"><div class="cell">任务状态</div><div class="cell">%s</div></div>
<div class="row"><div class="cell">报告生成</div><div class="cell">%s</div></div>
</div>`,
		html.EscapeString(nz(in.Title, "未命名任务")),
		html.EscapeString(nz(in.Title, "未命名任务")),
		html.EscapeString(nz(in.Goal, "（未指定）")),
		html.EscapeString(nz(in.Status, "—")),
		in.GeneratedAt.Format("2006-01-02 15:04:05"))
}

func writeSummary(sb *strings.Builder, in Input, counts map[string]int) {
	fmt.Fprintf(sb, `<h2>一、执行摘要</h2>
<p>本次测试共确认 <b>%d</b> 个漏洞发现。等级分布：</p>
<table class="stats"><tr><th>严重</th><th>高危</th><th>中危</th><th>低危</th><th>信息</th><th>合计</th></tr><tr>`,
		len(in.Findings))
	for _, s := range sevOrder {
		fmt.Fprintf(sb, `<td style="color:%s;font-weight:700">%d</td>`, sevColor[s], counts[s])
	}
	fmt.Fprintf(sb, `<td><b>%d</b></td></tr></table>`, len(in.Findings))
	if in.Summary != "" {
		fmt.Fprintf(sb, "<p>%s</p>", html.EscapeString(in.Summary))
	}
	// 资产统计
	if len(in.AssetCounts) > 0 {
		var types []string
		for t := range in.AssetCounts {
			types = append(types, t)
		}
		sortStrings(types)
		var parts []string
		for _, t := range types {
			parts = append(parts, fmt.Sprintf("%s %d", html.EscapeString(t), in.AssetCounts[t]))
		}
		fmt.Fprintf(sb, "<p>资产覆盖：%s。</p>", strings.Join(parts, "、"))
	}
}

func writeFindings(sb *strings.Builder, fs []findingView) {
	sb.WriteString("<h2>二、漏洞详情</h2>")
	if len(fs) == 0 {
		sb.WriteString(`<p style="color:#475569">本次测试未确认漏洞。</p>`)
		return
	}
	for i, f := range fs {
		s := nz(f.Severity, "info")
		label, color := sevLabel[s], sevColor[s]
		if label == "" {
			label, color = sevLabel["info"], sevColor["info"]
		}
		fmt.Fprintf(sb, `<div class="finding"><div class="hd"><span class="badge" style="background:%s">%s</span>
<span class="nm">%d. %s</span>%s</div><div class="bd">`,
			color, label, i+1,
			html.EscapeString(nz(f.Name, nz(f.VulnClass, "未分类漏洞"))),
			func() string {
				if f.VulnClass != "" && f.VulnClass != f.Name {
					return `<span style="color:#64748b;font-size:12px">分类：` + html.EscapeString(f.VulnClass) + `</span>`
				}
				return ""
			}())
		if f.Summary != "" {
			fmt.Fprintf(sb, "<p>%s</p>", html.EscapeString(f.Summary))
		}
		if f.PoC != "" {
			sb.WriteString(`<b>PoC / 证据：</b><pre>` + html.EscapeString(f.PoC) + `</pre>`)
		}
		sb.WriteString(`<div class="remediation"><b>修复建议：</b><ol>`)
		for _, r := range Remediations(f.VulnClass, f.Name) {
			sb.WriteString("<li>" + html.EscapeString(r) + "</li>")
		}
		sb.WriteString("</ol></div></div></div>")
	}
}

func sortFindings(fs []findingView) {
	for i := 1; i < len(fs); i++ {
		for j := i; j > 0 && sevRank[nz(fs[j].Severity, "info")] < sevRank[nz(fs[j-1].Severity, "info")]; j-- {
			fs[j], fs[j-1] = fs[j-1], fs[j]
		}
	}
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
