# 阶段 7 · C2 与基础设施

> **授权边界**：C2 基础设施（域名、重定向器、证书）一旦上线就具备真实的指挥控制能力。演练中必须使用专用域名与隔离环境，结束后立即下线并保留操作记录。

## C2 框架

| 项目 | 说明 | 链接 |
|---|---|---|
| **Metasploit** | 最广泛使用的渗透测试框架，模块化 exploit/payload | https://github.com/rapid7/metasploit-framework |
| **Sliver** | 开源通用植入框架，支持 mTLS / HTTP(S) / DNS | https://github.com/BishopFox/sliver |
| **Covenant** | .NET C2 框架，面向 .NET 攻击面 | https://github.com/cobbr/Covenant |
| **PoshC2** | 代理感知的 PowerShell C2 框架 | https://github.com/nettitude/PoshC2 |
| **Empire** | PowerShell 后渗透框架（历史经典） | https://github.com/EmpireProject/Empire |
| **SILENTTRINITY** | Python/IronPython/C# 异步后渗透框架 | https://github.com/byt3bl33d3r/SILENTTRINITY |
| **Pupy** | 跨平台远程管理与后渗透 | https://github.com/n1nj4sec/pupy |
| **Koadic** | COM 驱动的小型后渗透框架（原仓库已下架） | https://github.com/offsecginger/koadic |
| **Merlin** | Go 编写的 HTTP/2 C2 | https://github.com/Ne0nd0g/merlin |
| **FactionC2** | WebSocket API 驱动的 C2 框架（GitHub 仓库已下架，仅存第三方 agent 实现，作历史参考） | https://github.com/pfussell/Corsair |
| **dnscat2** | DNS 隧道 C2 | https://github.com/iagox86/dnscat2 |
| **TrevorC2** | 基于合法网站浏览的隐蔽通道 | https://github.com/trustedsec/trevorc2 |
| **Quasar** | C# 远程管理工具 | https://github.com/quasar/QuasarRAT |
| **EvilOSX** | macOS 远程管理（历史） | https://github.com/Marten4n6/EvilOSX |
| **EggShell** | Python 后渗透监控工具 | https://github.com/neoneggplant/EggShell |
| **Gcat** | 以邮箱为通道的隐蔽后门（历史） | https://github.com/byt3bl33d3r/gcat |
| **Cobalt Strike** | 商业对抗模拟平台（需授权购买） | https://www.cobaltstrike.com/ |

## 基础设施编排

- **RAI (Rapid Attack Infrastructure)** — 红队基础设施快速搭建（团队服务器/重定向器/钓鱼） · https://github.com/obscuritylabs/RAI
- **Red-Baron** — Terraform 驱动的弹性红队基础设施（原仓库已下架，可参考同类 Terraform 方案）
- **RedTeam-Automation** — 自动化基础设施部署（原仓库已下架，仅作历史参考）
- **redi** — Cobalt Strike 重定向器自动部署（nginx + Let's Encrypt） · https://github.com/taherio/redi
- **ycsm** — 弹性重定向器快速安装 · https://github.com/infosecn1nja/ycsm
- **DomainFrontDiscover / DomainFrontingLists** — 域前置可行性调研（多数云厂商已封堵） · https://github.com/peewpw/DomainFrontDiscover
- **FindFrontableDomains** — 可前置域名发现 · https://github.com/rvrsh3ll/FindFrontableDomains
- **domainhunter** — 过期域名与信誉评估（选 C2 域名） · https://github.com/threatexpress/domainhunter
- **CatMyFish** — 已分类域名的筛选（白名单域策略评估） · https://github.com/Mr-Un1k0d3r/CatMyFish
- **Chameleon** — 代理分类规避研究（原仓库已下架，MDSec 已清空该仓库）
- **EvilURL** — IDN 同形域名生成与检测（**仿冒监控也用**） · https://github.com/UndeadSec/EvilURL
- **Postfix-Server-Setup** — 邮件服务器快速搭建（钓鱼演练） · https://github.com/n0pe-sled/Postfix-Server-Setup
- **Apache2-Mod-Rewrite-Setup** — 重定向规则快速部署 · https://github.com/n0pe-sled/Apache2-Mod-Rewrite-Setup
- **mkhtaccess_red** — 按沙箱来源自动分流访问 · https://github.com/violentlydave/mkhtaccess_red
- **RedFile** — 条件化载荷投递服务 · https://github.com/outflanknl/RedFile
- **keyserver** — HTTP/DNS 密钥分发保护载荷 · https://github.com/leoloobeek/keyserver
- **cat-sites** — 域名分类站点库 · https://github.com/audrummer15/cat-sites

## C2 Profile 与流量塑形

- **Malleable-C2-Profiles** — Cobalt Strike 流量配置集 · https://github.com/rsmudge/Malleable-C2-Profiles
- **Malleable-C2-Randomizer** — 流量配置随机化（降签名命中） · https://github.com/bluscreenofjeff/Malleable-C2-Randomizer
- **cs2modrewrite / e2modrewrite** — 将 C2 配置转为 mod_rewrite 规则 · https://github.com/threatexpress/cs2modrewrite
- **ExternalC2 / external_c2_framework** — 扩展 C2 通道的接口与框架 · https://github.com/ryhanson/ExternalC2
- **DoHC2** — DNS over HTTPS 承载 External C2 · https://github.com/SpiderLabs/DoHC2
- **CobaltStrike-ToolKit** — Cobalt Strike 辅助脚本集 · https://github.com/killswitch-GUI/CobaltStrike-ToolKit
- **meek** — 抗封锁传输（Tor 插件，历史参考） · https://github.com/arlolra/meek
- **HTran** — 连接转发器（历史） · https://github.com/HiwinCN/HTran
- **PowerDNS** — 纯 DNS 执行通道研究（原仓库已下架，MDSec 已清空该仓库）

## 隧道与代理（Pivoting）

- **chisel** — HTTP 隧道，支持 SOCKS5（最常用） · https://github.com/jpillora/chisel
- **ligolo** — TUN 接口式隧道，路由透明 · https://github.com/sysdream/ligolo
- **pingtunnel** — ICMP 隧道 · https://github.com/esrrhs/pingtunnel
- **reGeorg / reGeorg-Weblogic** — Web shell 隧道代理 · https://github.com/sensepost/reGeorg
- **ABPTTS** — 加密 HTTP 隧道（历史） · https://github.com/nccgroup/ABPTTS
- **PivotSuite** — 网络 pivoting 工具集 · https://github.com/RedTeamOperations/PivotSuite
- **mssqlproxy** — 通过 MSSQL 建立代理通道 · https://github.com/blackarrowsec/mssqlproxy
- **SocksOverRDP** — 基于 RDP 的 SOCKS 代理 · https://github.com/nccgroup/SocksOverRDP
- **SharpChisel** — chisel 的 C# 实现 · https://github.com/shantanu561993/SharpChisel
- **Invoke-SocksProxy** — PowerShell SOCKS 代理 · https://github.com/p3nt4/Invoke-SocksProxy
- **ssf** — 安全 socket 隧道 · https://github.com/securesocketfunneling/ssf
- **VPNPivot** — VPN 式网络 pivoting · https://github.com/0x36/VPNPivot
- **egressbuster** — 出口可用性批量探测 · https://github.com/trustedsec/egressbuster

## 防守方视角

- C2 检测不要只靠特征串：**JA3/JARM 指纹、心跳周期性、DNS 查询熵**这三类行为信号，比任何 profile 都难规避。
- 域前置（Domain Fronting）已被主流云厂商封堵，清单里的相关项目**多数只剩历史参考价值**，评估时不要当作当前有效威胁。
- 隧道工具（chisel/ligolo）的检测点是**长连接 + 异常端口 + 非业务进程的网络行为**，出口侧的 NetFlow 比主机日志更早发现。
- 防守方最有效的措施是**出口白名单 + 强制代理**，它能一次性让大部分 C2 与隧道手段失效。
- 基础设施类项目在演练结束后必须**确认域名、证书、服务器全部下线**，遗留资产是真实的安全隐患。
