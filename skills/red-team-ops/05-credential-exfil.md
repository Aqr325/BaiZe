# 阶段 5 · 凭据收集与外渗

> **授权边界**：凭据提取类工具涉及**真实的账号密码与票据**。授权测试中应约定：仅证明"可读取"即止，不落地保存明文、不外传样本，测试结束立即销毁并出具销毁记录。

## Windows 凭据面

- **mimikatz** — 内存凭据与票据提取（研究/检测验证基准） · https://github.com/gentilkiwi/mimikatz
- **SafetyKatz** — mimikatz 的隐蔽调用包装（检测验证） · https://github.com/GhostPack/SafetyKatz
- **BetterSafetyKatz** — 动态拉取最新 mimikatz 的包装 · https://github.com/Flangvik/BetterSafetyKatz
- **SharpKatz** — mimikatz 核心功能的 C# 移植 · https://github.com/b4rtik/SharpKatz
- **Rubeus** — Kerberos 票据操作与攻击面验证 · https://github.com/GhostPack/Rubeus
- **SharpDPAPI** — DPAPI 保护数据解密（研究） · https://github.com/GhostPack/SharpDPAPI
- **SharpSecDump** — 远程 SAM/LSA 导出（impacket 的 C# 版） · https://github.com/G0ldenGunSec/SharpSecDump
- **Dumpert / SharpMiniDump / ATPMiniDump** — LSASS 内存导出技术研究 · https://github.com/outflanknl/Dumpert
- **lsassy** — 远程 LSASS 转储与解析 · https://github.com/Hackndo/lsassy
- **spraykatz** — 批量远程转储与解析 · https://github.com/aas-n/spraykatz
- **SharpHandler** — 复用句柄读取 LSASS 研究 · https://github.com/jfmaes/SharpHandler
- **Internal-Monologue** — 无 LSASS 触达的凭据提取研究 · https://github.com/eladshamir/Internal-Monologue
- **Invoke-WCMDump** — 凭据管理器导出 · https://github.com/peewpw/Invoke-WCMDump
- **DecryptAutoLogon** — 自动登录凭据解密 · https://github.com/securesean/DecryptAutoLogon
- **sAINT** — 凭据收集框架 · https://github.com/tiagorlampert/sAINT
- **LaZagneForensic** — 远程本地密码恢复 · https://github.com/AlessandroZ/LaZagneForensic
- **SessionGopher** — 会话配置中的保存凭据定位 · https://github.com/Arvanaghi/SessionGopher

## 浏览器与客户端数据

- **HackBrowserData** — 浏览器密码/Cookie/历史导出（评估本地数据保护） · https://github.com/moonD4rk/HackBrowserData
- **SharpWeb** — 浏览器凭据收集 · https://github.com/djhohnstein/SharpWeb
- **SharpChromium** — Chromium 系浏览器数据提取 · https://github.com/djhohnstein/SharpChromium
- **SharpClipHistory** — 剪贴板历史读取（研究） · https://github.com/mwrlabs/SharpClipHistory
- **SharpScribbles** — 记事本/Thunderbird/Firefox 凭据提取 · https://github.com/V1V1/SharpScribbles
- **SharpCloud** — 云厂商凭据文件存在性检查 · https://github.com/chrismaddalena/SharpCloud
- **RdpThief** — RDP 会话中的明文凭据截取（研究） · https://github.com/0x09AL/RdpThief
- **Gopher** — 低垂果实式的会话/凭据定位 · https://github.com/EncodeGroup/Gopher

## Linux 凭据面

- **mimipenguin** — Linux 内存凭据提取（研究） · https://github.com/huntergregal/mimipenguin
- **mimipy** — 进程内存凭据提取 · https://github.com/n1nj4sec/mimipy
- **3snake** — SSH/Sudo/SU 凭据截取（研究） · https://github.com/blendin/3snake
- **sshLooterC** — SSH 凭据收集（研究） · https://github.com/mthbernardes/sshLooterC
- **gimmecredz** — 常见位置凭据收集 · https://github.com/0xmitsurugi/gimmecredz
- **tickey** — 内核密钥环中的 Kerberos 票据提取 · https://github.com/TarlogicSecurity/tickey

## 隧道与外渗通道

- **dnscat2** — DNS 隧道 C2 通道 · https://github.com/iagox86/dnscat2
- **DNSExfiltrator** — DNS 数据外带验证 · https://github.com/Arno0x/DNSExfiltrator
- **DNSlivery** — 基于 DNS 的文件投递 · https://github.com/no0be/DNSlivery
- **icmptunnel** — ICMP 隧道 · https://github.com/DhavalKapil/icmptunnel
- **Tunna** — 通过 HTTP 封装 TCP 的隧道 · https://github.com/SECFORCE/Tunna
- **chashell** — HTTP 隧道 shell · https://github.com/sysdream/chashell
- **Egress-Assess** — 出口策略与外带能力评估（**防守方也用**） · https://github.com/FortyNorthSecurity/Egress-Assess
- **Invoke-TmpDavFS** — WebDAV 挂载式外带 · https://github.com/p3nt4/Invoke-TmpDavFS
- **FlyingCarpet** — 无线直连文件传输（隔离网场景） · https://github.com/spieglt/FlyingCarpet

## 钓鱼与凭据诱导（高度敏感）

> 仅在被授权的**社会工程学演练**范围内使用，且必须事先取得书面同意与员工告知豁免。多数合规框架对社会工程测试有额外审批要求。

- **gophish** — 钓鱼演练平台（开源，含报表） · https://github.com/gophish/gophish
- **CredsLeaker** — 凭据诱导验证（演练用） · https://github.com/Dviros/CredsLeaker
- **fakelogonscreen** — 伪造登录界面（演练用） · https://github.com/bitsadmin/fakelogonscreen
- **pickl3** — 凭据诱导载荷研究 · https://github.com/hlldz/pickl3
- **SharpLoginPrompt** — 登录框诱导研究 · https://github.com/shantanu561993/SharpLoginPrompt
- **PinSwipe** — 设备 PIN 相关研究 · https://github.com/CCob/PinSwipe

## 防守方视角

- **LSASS 访问是最强的检测信号**：任何非白名单进程打开 lsass 句柄，在开启 Credential Guard / LSA 保护的机器上都会产生高置信告警。
- 凭据保护的真正抓手是**架构而非工具**：Credential Guard、禁止域管登录工作站、LAPS、分层管理模型，任何一项生效都会让上述工具大面积失效。
- 浏览器数据导出（HackBrowserData 类）的防护点是**终端 DLP 与应用隔离**，而不是杀软特征。
- 外渗能力评估（Egress-Assess）本质是**出口策略体检**：应报告"哪些协议/端口未被限制"，这是防守方最需要的结论。
- 所有凭据类发现，报告里**只写"可读取某类凭据"与影响面**，绝不复述明文。
