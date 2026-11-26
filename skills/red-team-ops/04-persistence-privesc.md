# 阶段 4 · 持久化与提权

> **授权边界**：持久化类操作会**在目标系统留下实际改动**。在客户环境中执行前必须书面确认允许的持久化形式与清理时限，测试结束后逐项清除并留痕。

## Windows 提权审计（先枚举，再决定是否需要提权）

- **winPEAS** — Windows 提权面自动枚举（输出友好） · https://github.com/carlospolop/PEASS-ng
- **PrivescCheck** — 提权配置检查（PowerShell） · https://github.com/itm4n/PrivescCheck
- **Seatbelt** — 主机安全配置与提权线索收集 · https://github.com/GhostPack/Seatbelt
- **SharpUp** — 提权配置审计（C#） · https://github.com/GhostPack/SharpUp
- **HostRecon** — 主机侦察脚本 · https://github.com/dafthack/HostRecon
- **JAWS** — PowerShell 提权枚举 · https://github.com/411Hall/JAWS
- **WINspect** — 主机信息与配置检查 · https://github.com/A-mIn3/WINspect
- **BeRoot** — Windows/Linux 提权检查 · https://github.com/AlessandroZ/BeRoot
- **Watson** — 缺失补丁与已知提权漏洞匹配 · https://github.com/rasta-mouse/Watson
- **wesng** — Windows Exploit Suggester 新一代 · https://github.com/bitsadmin/wesng
- **windows-kernel-exploits** — 内核提权漏洞索引 · https://github.com/SecWiki/windows-kernel-exploits
- **WindowsExploits / Exploits** — 提权漏洞 PoC 归档（历史参考） · https://github.com/abatchy17/WindowsExploits
- **siofra** — DLL 劫持面扫描 · https://github.com/Cybereason/siofra
- **rattler** — 可预加载 DLL 自动发现 · https://github.com/sensepost/rattler
- **ADAPE-Script** — 自动化提权枚举 · https://github.com/hausec/ADAPE-Script
- **Robber** — DLL 劫持 PoC 生成 · https://github.com/MojtabaTajik/Robber

## Windows 权限滥用

- **UACME** — UAC 绕过手法索引（检测规则参考） · https://github.com/hfiref0x/UACME
- **WinPwnage** — UAC 与提权手法合集 · https://github.com/rootm0s/WinPwnage
- **Priv2Admin** — Windows 特权到管理员映射 · https://github.com/gtworek/Priv2Admin
- **Tokenvator** — 令牌操作与权限提升研究 · https://github.com/0xbadjuju/Tokenvator
- **PrintSpoofer** — 打印服务模拟特权滥用（研究） · https://github.com/itm4n/PrintSpoofer
- **RoguePotato / Lovely-Potato / BadPotato** — 服务账户到 SYSTEM 的本地提权研究 · https://github.com/antonioCoco/RoguePotato
- **RogueWinRM** — 服务账户提权研究 · https://github.com/antonioCoco/RogueWinRM
- **FullPowers** — 恢复服务账户默认权限集 · https://github.com/itm4n/FullPowers
- **UsoDllLoader** — DLL 加载路径滥用研究 · https://github.com/itm4n/UsoDllLoader
- **Sherlock** — 旧版提权漏洞检测（历史参考） · https://github.com/rasta-mouse/Sherlock

## Linux 提权审计

- **linPEAS** — Linux 提权面自动枚举 · https://github.com/carlospolop/PEASS-ng
- **linux-smart-enumeration** — 分级输出的提权枚举 · https://github.com/diego-treitos/linux-smart-enumeration
- **LinEnum** — 传统枚举脚本 · https://github.com/rebootuser/LinEnum
- **linux-exploit-suggester / -2** — 内核漏洞匹配 · https://github.com/mzet-/linux-exploit-suggester
- **linux-soft-exploit-suggester** — 已装软件漏洞匹配 · https://github.com/belane/linux-soft-exploit-suggester
- **SUDO_KILLER** — sudo 配置滥用检测 · https://github.com/TH3xACE/SUDO_KILLER
- **SUID3NUM** — SUID 二进制枚举并对照 GTFOBins · https://github.com/Anon-Exploiter/SUID3NUM
- **GTFOBLookup** — 离线 GTFOBins 查询 · https://github.com/nccgroup/GTFOBLookup
- **pspy** — 无 root 权限监控进程与定时任务 · https://github.com/DominicBreuker/pspy
- **lynis** — 系统安全基线审计 · https://github.com/CISOfy/lynis
- **unix-privesc-check** — 通用提权检查 · https://github.com/inquisb/unix-privesc-check
- **linuxprivchecker** — 提权检查脚本 · https://github.com/sleventyeleven/linuxprivchecker
- **swap_digger** — Swap 分区敏感信息提取（研究） · https://github.com/sevagas/swap_digger
- **modDetective** — 按文件 mtime 梳理时间线、排查近期系统活动（原仓库已下架）
- **KeyTabExtract** — keytab 文件凭据提取（研究） · https://github.com/sosdave/KeyTabExtract
- **dirty_sock** — snapd 提权漏洞 · https://github.com/initstring/dirty_sock
- **uptux** — systemd 相关提权检测 · https://github.com/initstring/uptux
- **linux-kernel-exploits** — 内核提权漏洞索引 · https://github.com/SecWiki/linux-kernel-exploits
- **tickey** — Linux 内核票据提取（研究） · https://github.com/TarlogicSecurity/tickey
- **static-binaries** — 静态编译工具集（便于在受限环境审计） · https://github.com/andrew-d/static-binaries

## 持久化

- **SharPersist** — Windows 持久化技术验证框架 · https://github.com/fireeye/SharPersist
- **SharpHide** — 注册表隐藏项研究 · https://github.com/outflanknl/SharpHide
- **DAMP** — 域内 ACL 持久化研究 · https://github.com/HarmJ0y/DAMP

## 后门与异常驻留检测

- **Sticky-Keys-Slayer** — 粘滞键后门检测 · https://github.com/linuz/Sticky-Keys-Slayer
- **sticky_keys_hunter** — 同类后门检测 · https://github.com/ztgrace/sticky_keys_hunter
- **doublepulsar-detection-script** — DoublePulsar 后门检测（历史） · https://github.com/countercept/doublepulsar-detection-script

## 缓冲区溢出与漏洞开发

- **pwntools** — 漏洞开发框架 · https://github.com/Gallopsled/pwntools
- **awesome-exploit-development** — 漏洞开发资源索引 · https://github.com/FabioBaroni/awesome-exploit-development
- **Buffer-Overflow-Labs** — 溢出实验环境 · https://github.com/CyberSecurityUP/Buffer-Overflow-Labs
- **Buffer_Overflow** — 溢出练习与讲义 · https://github.com/gh0x0st/Buffer_Overflow
- **Buffer-Overflow-Guide** — 溢出利用指南 · https://github.com/johnjhacking/Buffer-Overflow-Guide
- **OSCP-Buffer-Overflow** — OSCP 风格溢出练习 · https://github.com/V1n1v131r4/OSCP-Buffer-Overflow
- **Exploit-Challenges** — 漏洞利用挑战集 · https://github.com/Billy-Ellis/Exploit-Challenges
- **linux-exploit-development-tutorial** — Linux 漏洞开发教程 · https://github.com/hardenedlinux/linux-exploit-development-tutorial

## 防守方视角

- 提权枚举脚本（winPEAS/linPEAS）**行为特征极其明显**：短时间内大量系统信息查询，EDR 行为链规则基本必中。
- 真正的提权风险来自**配置缺陷**（服务权限过宽、SUID 滥用、补丁缺失、sudo 配置错误），报告应落到具体配置项与修复命令，而非"成功提权"。
- 持久化是**改动生产环境**的行为，也是审计中最敏感的部分：每加一项必须记录位置、时间、清理状态。
- UAC 绕过与权限滥用类研究的价值在**验证防护策略是否生效**，不是提供绕过能力。

## 使用提醒

Windows 提权凭据与权限滥用条目在公开清单中占比很高，但**绝大多数已被现代 EDR 覆盖**。评估时才用，且优先看 `Priv2Admin` 这类"特权映射表"来判断风险敞口，而不是直接上 PoC。
