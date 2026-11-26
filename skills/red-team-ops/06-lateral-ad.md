# 阶段 6 · 横向移动与域环境

> **授权边界**：横向移动会触及**多台主机甚至域控**。授权范围必须明确列出可横向的网段与主机清单，越界即事故。

## 横向执行通道

- **CrackMapExec** — 多协议批量横向验证（SMB/WinRM/LDAP） · https://github.com/byt3bl33d3r/CrackMapExec
- **evil-winrm** — WinRM 交互式会话 · https://github.com/Hackplayers/evil-winrm
- **WSMan-WinRM** — 无 WinRM 客户端的 WinRM 调用 · https://github.com/bohops/WSMan-WinRM
- **WMIcmd / WMIHACKER** — WMI 远程执行 · https://github.com/nccgroup/WMIcmd
- **SCShell** — 服务控制管理器远程执行 · https://github.com/Mr-Un1k0d3r/SCShell
- **CSExec** — 服务创建式远程执行 · https://github.com/malcomvetter/CSExec
- **SharpRDP** — RDP 会话驱动远程执行 · https://github.com/0xthirteen/SharpRDP
- **SharpMove** — 多种横向移动手法合集 · https://github.com/0xthirteen/SharpMove
- **MoveKit** — 横向移动工具集 · https://github.com/0xthirteen/MoveKit
- **SharpCOM** — COM 对象远程执行 · https://github.com/rvrsh3ll/SharpCOM
- **SharpMapExec** — CrackMapExec 的 C# 对应实现 · https://github.com/cube0x0/SharpMapExec
- **DeathStar** — 自动化域内提权与横向编排 · https://github.com/byt3bl33d3r/DeathStar
- **icebreaker / apt2 / portia / Vegile** — 内网横向辅助工具 · https://github.com/DanMcInerney/icebreaker
- **nextnet** — 内网存活主机与网段发现 · https://github.com/hdm/nextnet
- **IOXIDResolver** — 通过 OXID 解析定位主机网卡信息 · https://github.com/mubix/IOXIDResolver
- **ADCollector** — 域内快速信息收集 · https://github.com/dev-2null/ADCollector
- **MiscTools** — 横向移动杂项工具集 · https://github.com/rasta-mouse/MiscTools
- **hunter** — 域内主机与用户枚举（原仓库已下架，仅作历史参考）
- **rpc2socks** — RPC 通道转 SOCKS 代理 · https://github.com/lexfo/rpc2socks
- **sshiva** — SSH 会话相关横向研究 · https://github.com/checkymander/sshiva

## 强制认证与中继面

- **SpoolSample / SpoolSamplerNET** — 打印服务强制认证（PetitPotam 类）验证 · https://github.com/leechristensen/SpoolSample
- **krbrelayx** — Kerberos 中继工具集 · https://github.com/dirkjanm/krbrelayx
- **GMSAPasswordReader** — gMSA 密码读取（权限验证） · https://github.com/rvazarkar/GMSAPasswordReader
- **NetNTLMtoSilverTicket** — NetNTLM 到银票的转换研究 · https://github.com/NotMedic/NetNTLMtoSilverTicket

## 域内关系与权限分析

- **BloodHound** — 域内权限关系图分析（**防守方也用来看自己的暴露面**） · https://github.com/BloodHoundAD/BloodHound
- **SharpHound3** — BloodHound 数据采集器 · https://github.com/BloodHoundAD/SharpHound3
- **awesome-bloodhound** — BloodHound 查询与使用资源 · https://github.com/chryzsh/awesome-bloodhound
- **Bloodhound-Custom-Queries / BloodHoundQueries** — 自定义查询集 · https://github.com/CompassSecurity/BloodHoundQueries
- **pingcastle** — AD 安全健康度评分（**防守方首选**） · https://github.com/vletoux/pingcastle
- **ACLight** — 特权账户暴露面分析 · https://github.com/cyberark/ACLight
- **ADACLScanner** — ACL 权限差异比对 · https://github.com/canix1/ADACLScanner
- **Invoke-ACLPwn** — ACL 滥用路径验证 · https://github.com/fox-it/Invoke-ACLPwn
- **SharpGPOAbuse** — GPO 滥用路径验证 · https://github.com/mwrlabs/SharpGPOAbuse
- **rbcd_permissions** — 基于资源的约束委派配置检查 · https://github.com/NinjaStyle82/rbcd_permissions
- **ldapdomaindump** — LDAP 域信息导出 · https://github.com/dirkjanm/ldapdomaindump
- **ADRecon** — AD 环境全量信息汇总 · https://github.com/adrecon/ADRecon

## 防守方视角

- **横向移动的核心检测点是认证异常**：同一账户在短时间内从多台主机登录、NTLM 与 Kerberos 混用、非常规时段访问域控，这三类信号比任何工具特征都可靠。
- **BloodHound 是双刃剑**：它列出的每条攻击路径，对防守方就是一张待修清单。评估报告中应把最高价值的 3-5 条路径转成具体加固项（如移除多余 ACL、关闭不必要的委派）。
- 强制认证类（SpoolSample/PetitPotam）的根治手段是**关闭相关服务并启用 SMB/LDAP 签名**，单靠打补丁不够。
- 横向工具普遍依赖 SMB/WinRM/WMI，**主机防火墙分段与特权访问工作站（PAW）** 能让大部分横向路径直接失效。
- CrackMapExec 类工具的批量扫描会在域内产生大量失败登录（4625），是最容易触发告警的行为之一。
