package guard

import (
	"regexp"
	"strings"
)

// ActionTier 是《AI 渗透测试智能体·被测环境安全》§5「动作分级与爆炸半径」
// 中的五级动作风险等级。等级由两个客观维度(影响面 × 可恢复性)交叉决定,
// 在平台层(非 LLM)计算——不接受模型自评,也不接受"我觉得这个很安全"。
type ActionTier int

const (
	// TierA0 只读观测：被动流量分析、版本识别、公开信息核对。
	TierA0 ActionTier = iota
	// TierA1 低影响探测：单请求指纹、限速枚举、非破坏性配置核查。
	TierA1
	// TierA2 有状态写入：测试账号、无害样本、非关键配置变更。
	TierA2
	// TierA3 高风险动作：提权利用、横向移动、数据导出验证。
	TierA3
	// TierA4 禁止动作：破坏性删除、勒索模拟、批量外传、影响第三方。
	TierA4
)

func (t ActionTier) String() string {
	switch t {
	case TierA0:
		return "A0"
	case TierA1:
		return "A1"
	case TierA2:
		return "A2"
	case TierA3:
		return "A3"
	case TierA4:
		return "A4"
	}
	return "A?"
}

// tierPattern 是一条确定性分级规则:正则命中即归该等级。
// tierPatterns 按「就高不就低」排序(A4→A3→A2→A1),先命中高者返回。
type tierPattern struct {
	tier ActionTier
	re   *regexp.Regexp
}

// tierPatterns 是内置动作分级启发式。这是可工程化的起点,不是完备分类:
// 覆盖绝大多数真实破坏/失控模式(删除、外传、勒索、提权、横向、写入);
// 脚本注入(如 python -c)等不可判定的边界默认落 A0,由后续规则集扩展。
// 判定原则(§5.2):就高不就低(同时命中按高执行)、按影响不按意图(看最坏情况)。
var tierPatterns = []tierPattern{
	// ---- A4 禁止：不可逆破坏 / 影响第三方 / 勒索模拟 / 批量删除 ----
	{TierA4, regexp.MustCompile(`(?i)\brm\s+-[a-zA-Z]*r[a-zA-Z]*\b`)},                // rm -r / -rf 递归删除
	{TierA4, regexp.MustCompile(`(?i)\b(del|erase)\s+/[a-zA-Z]*[sq]`)},               // cmd del /S /Q
	{TierA4, regexp.MustCompile(`(?i)\brmdir\s+/[a-zA-Z]*[sq]`)},                     // cmd rmdir /S /Q
	{TierA4, regexp.MustCompile(`(?i)\bRemove-Item\b`)},                              // PowerShell
	{TierA4, regexp.MustCompile(`(?i)\bDROP\s+(TABLE|DATABASE|SCHEMA)\b`)},           // 库表删除
	{TierA4, regexp.MustCompile(`(?i)\bTRUNCATE\b`)},                                 // 清表
	{TierA4, regexp.MustCompile(`(?i)\b(mkfs|mkfs\.\w+|fdisk|parted)\b`)},            // 磁盘格式化
	{TierA4, regexp.MustCompile(`(?i)\bformat\s+[a-z]:`)},                            // Windows format
	{TierA4, regexp.MustCompile(`(?i)\bdd\b[^|;]*\bof=/dev/(sd|hd|vd|nvme|mmcblk)`)}, // 覆写磁盘
	{TierA4, regexp.MustCompile(`(?i)\b(shutdown|reboot|poweroff|halt)\b`)},          // 影响第三方
	{TierA4, regexp.MustCompile(`(?i)\bnc\b[^|;]*\s+-e\b`)},                          // 反弹 shell
	{TierA4, regexp.MustCompile(`(?i)\bsocat\b.*\b(EXEC|SYSTEM)\b`)},                 // 反弹/系统执行
	{TierA4, regexp.MustCompile(`(?i)\b(msfvenom|msfconsole|meterpreter)\b`)},        // 攻击框架
	{TierA4, regexp.MustCompile(`(?i)\bfind\b[^|;]*\s-delete\b`)},                    // find -delete

	// ---- A3 高风险：提权 / 横向移动 / 数据导出验证 / 系统级影响 ----
	{TierA3, regexp.MustCompile(`(?i)\b(sudo|pkexec|setuid)\b`)},
	{TierA3, regexp.MustCompile(`(?i)\bsu\s+-`)},
	{TierA3, regexp.MustCompile(`(?i)(?:^|\s)(chmod|chown|usermod|passwd)(?:\s|$)`)}, // 命令名，防 /etc/passwd 误判
	{TierA3, regexp.MustCompile(`(?i)\b(ssh|sshuttle|socat|scp|rsync)\b`)},
	{TierA3, regexp.MustCompile(`(?i)\b(mysqldump|pg_dump|mongodump)\b`)},                    // 数据导出
	{TierA3, regexp.MustCompile(`(?i)\bcurl\b[^|;]*(?:--data-binary|--data-urlencode)\s*@`)}, // 从文件外传
	{TierA3, regexp.MustCompile(`(?i)\bcurl\b[^|;]*\s-d\s*@`)},                               // -d @file 外传
	{TierA3, regexp.MustCompile(`(?i)\bwget\b[^|;]*--post-(data|file)\s*=`)},                 // 外传
	{TierA3, regexp.MustCompile(`(?i)\b(kill|pkill|killall)\b`)},                             // 进程终止
	{TierA3, regexp.MustCompile(`(?i)\bsystemctl\s+(stop|restart|disable|mask)\b`)},          // 服务停
	{TierA3, regexp.MustCompile(`(?i)\b(sysctl|iptables|ip6tables|route|firewall-cmd)\b`)},   // 系统网络配置

	// ---- A2 有状态写入：写文件 / 创建账号 / 非关键配置变更 / 单文件删除 ----
	{TierA2, regexp.MustCompile(`(?i)\b(tee|touch|mkdir|mv|cp|ln|chattr)\b`)},
	{TierA2, regexp.MustCompile(`(?i)\bsed\s+-i\b`)},
	{TierA2, regexp.MustCompile(`(?i)\b(echo|printf)\b.*[>»]`)},
	{TierA2, regexp.MustCompile(`(?m)(?:^|\s)(>>?)\s*[^\s]`)},                              // 重定向(>file / >>file)
	{TierA2, regexp.MustCompile(`(?i)(?:^|\s)(useradd|adduser|groupadd|crontab)(?:\s|$)`)}, // 命令名，防 /etc/crontab 误判
	{TierA2, regexp.MustCompile(`(?i)\bsystemctl\s+(enable|start)\b|\bservice\s+\w+\s+(start|restart)\b`)},
	{TierA2, regexp.MustCompile(`(?i)\bcurl\b[^|;]*(?:-o|--output)\s`)}, // curl 写文件
	{TierA2, regexp.MustCompile(`(?i)\brm\b`)},                          // 单文件删除(rm 不带 r)
	{TierA2, regexp.MustCompile(`(?i)\b(del|erase)\b`)},                 // 单文件 del
	{TierA2, regexp.MustCompile(`(?i)\b(unzip|tar\s+-x|gunzip|gzip\s+-d)\b`)},
	{TierA2, regexp.MustCompile(`(?i)(?:^|\s)git\s+push\b`)}, // 推送远端（命令名）

	// ---- A1 低影响探测：网络单请求 / 枚举 / 指纹 ----
	{TierA1, regexp.MustCompile(`(?i)\b(curl|wget|nmap|masscan|nuclei|httpx|katana|ffuf|gobuster|dirsearch|dig|nslookup|host|ping|traceroute|tracepath)\b`)},
	{TierA1, regexp.MustCompile(`(?i)(?:^|\s)git(?:\s|$|\.)`)}, // 其他 git(拉取/克隆)，命令名
}

// ClassifyAction 把一个工具调用分类到动作等级。确定性、非 LLM(§5):
// 判据只看命令/参数的可判定特征,不看模型自评、不看"意图"。先命中高等级者返回
// (就高不就低)。A0 是兜底(只读观测)。
//
// 匹配对象是【解析出的命令文本】而非原始 JSON——json.Marshal 会把 `>` 转义成
// \u003e,直接匹配 JSON 会让重定向类 A2 判据全部落空。非 shell 工具按工具名分级:
// 写类(Write/Edit/...)归 A2(有状态写入),读类(Read/Grep/...)归 A0。
func ClassifyAction(tool string, input []byte) ActionTier {
	switch strings.ToLower(tool) {
	case "write", "edit", "insert", "update":
		return TierA2
	case "read", "glob", "grep":
		return TierA0
	}
	cs := callSurface{tool: tool, input: input}
	cmd := cs.command()
	if cmd == "" {
		return TierA0
	}
	for _, p := range tierPatterns {
		if p.re.MatchString(cmd) {
			return p.tier
		}
	}
	return TierA0
}

// ActionFingerprint 计算一个动作的指纹 hash(目标 + 动作类型 + 关键参数),
// 供死循环检测(§7.2)使用:同一指纹在窗口内多次出现即判定循环。
// 目标取首个 host(或空),动作类型取首 token,关键参数为命令去掉首 token 的余部。
// 返回 "" 表示无可判定表面(非 Bash/交互 shell,跳过检测)。
func ActionFingerprint(tool string, input []byte) string {
	cs := callSurface{tool: tool, input: input}
	cmd := cs.command()
	if cmd == "" {
		return ""
	}
	act := cs.firstToken(cmd)
	hosts := cs.hosts()
	target := ""
	if len(hosts) > 0 {
		target = hosts[0]
	}
	params := strings.TrimSpace(strings.TrimPrefix(cmd, act))
	return digestInput([]byte(act + "\x00" + target + "\x00" + params))
}
