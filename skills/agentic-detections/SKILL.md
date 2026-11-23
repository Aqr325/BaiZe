---
name: agentic-detections
description: >
  检测 agentic 攻击框架（ARTEX/Cairn/PentAGI/HexStrike/CyberStrikeAI/Strix/
  Hermes/Agent Zero/RedAmon/Xalgorix/Pentest Swarm）的部署与流量。基于
  ThreatDefence/agentic-attack-detections（MIT，572 个受源指标 + KQL/Sigma/
  Suricata/YARA/Zeek/STIX 2.1 规则）。蓝队/IR 侧：按框架与格式引用规则做威胁
  检测与狩猎。注意：本库的 artex 规则可检测 ARTEX 家族部署——包括白泽自身
  （白泽是 ARTEX 的 fork，仍保留登录名 ARTEX、MCP clientInfo、工具函数名等
  指纹，详见 docs/ 审计）。所有相对路径基准 = ${SKILL_DIR}，用 Read
  <${SKILL_DIR}>/<相对路径> 访问，不跑脚本、不改文件。
---

# agentic-detections — Agentic 攻击框架检测规则库

来源：[ThreatDefence/agentic-attack-detections](https://github.com/ThreatDefence/agentic-attack-detections)（MIT）。
一个注册根技能，路由到 **11 个框架** 的检测规则 + **共享行为** + **572 个受源指标**。

## 文件基准

所有相对路径以 `${SKILL_DIR}`（本技能目录）为基准。示例：

- 读规则：`Read <${SKILL_DIR}>/frameworks/artex/suricata/artex.rules`
- 读指标：`Read <${SKILL_DIR}>/iocs/indicators.csv`
- 读框架说明：`Read <${SKILL_DIR}>/frameworks/<framework>/README.md`

不要用 shell 跑工具、不要修改任何文件——本库是只读规则/指标参考。

## 覆盖的框架

| 框架 | 说明 | 规则位置 |
|---|---|---|
| **artex** | Go planner/worker + Web 控制台；白泽是它的 fork | `frameworks/artex/`（KQL 31/Sentinel 7/Sigma 36/Suricata 43/YARA 4/Zeek + 246 IOC） |
| cairn | Python 引擎驱动 Claude/Codex/Pi 在 Kali 容器 | `frameworks/cairn/` |
| pentagi | Go 多 agent 平台，每任务一个 Kali 容器 | `frameworks/pentagi/` |
| hexstrike | Python MCP server 给 AI 约 150 安全工具（白泽已接入该 MCP） | `frameworks/hexstrike/` |
| cyberstrikeai | Go 操作台，约 90 工具 + 植入 + C2 + webshell | `frameworks/cyberstrikeai/` |
| strix | Python AI 渗透 agent，Kali 沙箱跑 agent 团队 | `frameworks/strix/` |
| hermes | 通用 agent 变攻击台（关审批/捆绑 jailbreak skill） | `frameworks/hermes/` |
| agent-zero | 通用 agent + Kali + 内置黑客档案 + 开放 Web UI | `frameworks/agent-zero/` |
| redamon | 自托管渗透平台（Web 台 + recon + Metasploit agent） | `frameworks/redamon/` |
| xalgorix | Go 二进制，web 台 + 免审批重利用的 agent | `frameworks/xalgorix/` |
| pentestswarm | Go CLI，recon/exploit/report agent 约 40 工具 | `frameworks/pentestswarm/` |

## 规则格式与用途

| 格式 | 位置 | 用途 |
|---|---|---|
| KQL | `frameworks/*/sentinel/hunting/` | Microsoft Sentinel / Defender XDR 高级狩猎 |
| Sentinel 分析 | `frameworks/*/sentinel/analytics/` | Sentinel 分析规则 |
| Sigma | `frameworks/*/sigma/` + `behaviors/sigma/` | 任意支持 Sigma 的 SIEM |
| Suricata | `frameworks/*/suricata/` + `behaviors/suricata/` | 网络 IDS（HTTP 需明文/解密；DNS/TLS SNI 可加密） |
| YARA | `frameworks/*/yara/` | 容器层/主目录//tmp/web 根扫描 |
| Zeek | `frameworks/*/zeek/` + `behaviors/zeek/` | 网络行为 + Intel 框架 |
| 指标 | `iocs/indicators.csv`（572）、`feeds/`（STIX 2.1/Sentinel watchlist/plain lists） | 威胁情报导入 |
| WAF | `waf/` | Cloudflare/AWS WAF/Azure WAF 边缘阻断 |
| 转换 | `generated/` | Sigma→Splunk/Sentinel/Defender/Elastic 预转换 |

## 共享行为（不依赖单一框架）

`behaviors/`：AI agent CLI 下起攻击工具（进程树）、服务器调 AI 模型 API、agent
页面阅读器伴攻击流量、旋转代理探一个站点、配置/备份窃取与 WSUS 探测、
Kerberos 枚举与 SMB/WinRM 扇出、服务器回调探测地址、AWS 凭据机器速度使用、
OOB 测试域查询（interactsh/Burp Collaborator/dnslog.cn）。

## 置信度

- **High**：框架/行动专属（UA、命令行、路径、提示串、探针产物、报告 C2/窃码域、哈希）→ 告警
- **Medium**：可变更/共享（报告地址、通用 agent UA、共享提示文本）→ 基线后告警或狩猎
- **Low**：常见/合法（AI 模型 API、请求收集服务、agent CLI UA、托管 ASN、代理商）→ 仅作其他发现的上下文

云/VPS 地址会被重分配；每个地址有 `review_by` 日期（报告后 180 天），过期地址
留在 CSV/STIX 作历史，退出 plain lists/Zeek/Suricata。阻断前先核对。

## 使用提示

1. 先 `Read <${SKILL_DIR}>/frameworks/<framework>/README.md` 确定该框架的规则结构与狩猎顺序。
2. 蓝队检测：按目标环境（Sentinel/Suricata/Zeek/YARA）选对应格式，`Read` 规则内容后交给分析引擎或人工落地。
3. 白泽自身：本库的 artex 规则可检测 ARTEX 家族部署——白泽是 ARTEX fork，保留登录名 `ARTEX`、MCP `clientInfo{"name":"artex"}`、工具函数名（record_fact/list_findings/insert_assets 等）、默认 `:8787`、`/api/health` 豁免、CORS `*` 分支。评估自身暴露面时以 `frameworks/artex/source-code-signals.md` 为基准。
4. 规则是实验性的：无规则经过捕获的入侵实测，落地前先跑在自己的数据上。
