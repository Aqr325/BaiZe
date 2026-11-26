# 阶段 3 · 执行与载荷

> **授权边界**：本章涉及脚本执行与免杀研究。免杀相关条目**仅用于检测能力验证（紫队/EDR 调优）与授权对抗演练**，不提供可用的绕过实现。

## PowerShell 工具集

- **PowerSploit** — PowerShell 后渗透模块集（历史经典，多模块已被检测） · https://github.com/PowerShellMafia/PowerSploit
- **nishang** — PowerShell 攻防脚本与载荷合集 · https://github.com/samratashok/nishang
- **PowerTools** — PowerShell 渗透工具集 · https://github.com/PowerShellEmpire/PowerTools
- **PowerShell-Suite** — PowerShell 工具合集 · https://github.com/FuzzySecurity/PowerShell-Suite
- **WinPwn** — Windows 侦察与提权辅助框架 · https://github.com/S3cur3Th1sSh1t/WinPwn
- **GhostPack** — C# 后渗透工具集（Seatbelt/SharpUp/Rubeus 等） · https://github.com/GhostPack
- **NetSPI PowerShell** — PowerShell 渗透脚本集 · https://github.com/NetSPI/PowerShell
- **PowerUpSQL** — SQL Server 攻击面审计 · https://github.com/NetSPI/PowerUpSQL
- **MailSniper** — Exchange / OWA 邮件检索审计 · https://github.com/dafthack/MailSniper
- **DomainPasswordSpray** — 域口令强度审计（低速率） · https://github.com/dafthack/DomainPasswordSpray
- **SharpSpray** — 域口令喷洒（C# 实现） · https://github.com/jnqpblc/SharpSpray
- **SessionGopher** — 会话与保存凭据定位 · https://github.com/Arvanaghi/SessionGopher
- **mimikittenz** — 进程内存凭据提取（研究用） · https://github.com/putterpanda/mimikittenz
- **Inveigh** — 内网名称解析欺骗检测 · https://github.com/Kevin-Robertson/Inveigh
- **Powermad** — 机器账户与域对象操作 · https://github.com/Kevin-Robertson/Powermad
- **DSInternals** — 目录服务数据结构分析 · https://github.com/MichaelGrafnetter/DSInternals
- **ADRecon** — AD 环境信息汇总 · https://github.com/sense-of-security/ADRecon
- **Grouper / Grouper2** — 组策略配置审计 · https://github.com/l0ss/Grouper2
- **LAPSToolkit / LAPSDumper** — LAPS 配置审计 · https://github.com/leoloobeek/LAPSToolkit
- **Invoke-Phant0m** — 日志服务相关研究（检测验证用） · https://github.com/hlldz/Invoke-Phant0m
- **PowerOPS / PowerMemory** — 无 PowerShell 环境的执行与内存分析研究（原仓库已下架，仅作历史参考）

## 免杀与执行绕过（仅检测验证）

> 这批项目的正确用法：**拿它们的产物去测自己的 EDR 是否告警**，而不是拿去打真实目标。

- **Amsi-Bypass-Powershell** — AMSI 绕过手法合集（检测规则参考） · https://github.com/S3cur3Th1sSh1t/Amsi-Bypass-Powershell
- **AMSITrigger** — 定位脚本中触发 AMSI 的片段（**防守方最实用**） · https://github.com/RythmStick/AMSITrigger
- **AMSI.fail** — AMSI 绕过样本生成（检测验证） · https://github.com/Flangvik/AMSI.fail
- **Invisi-Shell** — PowerShell 日志与审计规避研究 · https://github.com/OmerYa/Invisi-Shell
- **PowerLessShell** — 无 powershell.exe 进程的脚本执行研究 · https://github.com/Mr-Un1k0d3r/PowerLessShell
- **nopowershell** — 非 PowerShell 进程执行 .NET · https://github.com/bitsadmin/nopowershell
- **InsecurePowerShell** — 去除安全特性的 PowerShell 构建（研究用） · https://github.com/cobbr/InsecurePowerShell
- **MSBuildShell / NoMSBuild** — MSBuild 侧载执行研究 · https://github.com/Cn33liz/MSBuildShell
- **VBA-RunPE** — VBA 加载 PE 执行研究 · https://github.com/itm4n/VBA-RunPE
- **PowerShellArmoury** — 免杀脚本生成框架（检测验证） · https://github.com/cfalta/PowerShellArmoury
- **Stracciatella** — PowerShell 混淆与规避研究 · https://github.com/mgeeky/Stracciatella
- **herpaderping** — 进程映像篡改技术研究 · https://github.com/jxy-s/herpaderping
- **UltimateWDACBypassList** — WDAC 绕过手法汇总（策略评估参考） · https://github.com/bohops/UltimateWDACBypassList
- **SpaceRunner / PSByPassCLM / PSByPassCLM 同类** — 受限语言模式绕过研究 · https://github.com/Mr-B0b/SpaceRunner
- **Salsa-tools** — PowerShell 工具集（历史） · https://github.com/Hackplayers/Salsa-tools

## 载荷托管

- **pwndrop** — 自建载荷分发服务（含访问控制） · https://github.com/kgretzky/pwndrop
- **updog** — 简易 HTTP/S 文件服务，支持上传下载 · https://github.com/sc0tfree/updog

## 反弹 shell 与执行通道

- **pwncat** — 反弹 shell 管理与后渗透会话框架 · https://github.com/cytopia/pwncat
- **xc** — 反向 shell 命令生成 · https://github.com/xct/xc
- **LOLBITS** — 基于 BITS 的 C2 通道研究 · https://github.com/Kudaes/LOLBITS

## 工具包装与内存加载

- **GhostBuild** — MSBuild 载荷构建 · https://github.com/bohops/GhostBuild
- **PowerSharpPack** — PowerShell 包装 C# 工具集 · https://github.com/S3cur3Th1sSh1t/PowerSharpPack
- **Rubeus-Rundll32** — rundll32 加载 Rubeus 研究 · https://github.com/rvrsh3ll/Rubeus-Rundll32
- **Zolom** — PE 内存加载研究 · https://github.com/checkymander/Zolom

## 防守方视角

- **PDB / 字符串特征**是免杀绕不过去的坎：几乎所有公开工具都能被基于字符串与行为链的规则命中，看到"某工具绕过成功"先怀疑测试环境没开完整防护。
- PowerShell 类活动应重点看 **Script Block Logging（4104）** 与 **Module Logging（4103）**，多数"无文件"手法在这两个通道留痕。
- 载荷托管服务（pwndrop/updog）会在 TLS 证书与 JA3 指纹上暴露，代理日志里比主机日志更容易抓到。
- 免杀研究条目在本技能中的定位是**红蓝对抗验证**：结论应写成"该防护在 X 条件下未告警"，而不是"获得了绕过能力"。
