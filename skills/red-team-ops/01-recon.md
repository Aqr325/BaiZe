# 阶段 1 · 侦察与资产测绘

> **授权边界**：仅用于已授权目标的资产梳理。端口/子域名基础扫描请配合 `pentest-assistant` 技能使用，本章只收录框架识别、目录发现、共享扫描、API 审计类工具。

## 框架与指纹识别

- **CMSeeK** — 多 CMS 指纹识别与版本/插件枚举 · https://github.com/Tuhinshubhra/CMSeeK
- **CMSmap** — WordPress / Joomla / Drupal 专项扫描 · https://github.com/Dionach/CMSmap
- **wpscan** — WordPress 漏洞与配置扫描 · https://github.com/wpscanteam/wpscan
- **WhatWaf** — WAF 识别与绕过可行性评估 · https://github.com/Ekultek/WhatWaf
- **KingOfBugbountyTips** — 众测实战技巧合集（侦察向） · https://github.com/KingOfBugbounty/KingOfBugbountyTips

## 目录 / 文件 / 参数发现

- **gobuster** — 目录、DNS、虚拟主机枚举 · https://github.com/OJ/gobuster
- **dirsearch** — 目录与文件扫描（字典驱动） · https://github.com/maurosoria/dirsearch
- **dirble** — 快速目录枚举，支持递归 · https://github.com/nccgroup/dirble
- **turbosearch** — 高并发目录扫描 · https://github.com/helviojunior/turbosearch
- **Arjun** — HTTP 参数发现 · https://github.com/s0md3v/Arjun
- **parameth** — 参数暴力枚举 · https://github.com/maK-/parameth
- **ParamSpider** — 从 Web Archive 挖掘历史参数 · https://github.com/devanshbatham/ParamSpider
- **dirscraper** — 从 JS 文件中提取接口与目录线索 · https://github.com/Cillian-Collins/dirscraper
- **snallygaster** — 敏感文件与配置暴露扫描 · https://github.com/hannob/snallygaster
- **Breacher** — 后台管理面板发现 · https://github.com/s0md3v/Breacher
- **server-status_PWN** — Apache server-status 信息泄露检测 · https://github.com/mazen160/server-status_PWN

## 网络共享与主机面

- **Snaffler** — 域内共享文件敏感信息定向搜寻 · https://github.com/SnaffCon/Snaffler
- **SharpShares** — 共享枚举（C# 实现） · https://github.com/djhohnstein/SharpShares
- **SauronEye** — 按内容特征搜索文件 · https://github.com/vivami/SauronEye
- **VmdkReader** — 离线读取 VMDK 磁盘镜像 · https://github.com/leftp/VmdkReader

## API 审计

- **RESTler** — 有状态 REST API 模糊测试（微软） · https://github.com/microsoft/restler-fuzzer
- **Astra** — REST API 自动化安全测试 · https://github.com/flipkart-incubator/astra

## 防守方视角（报告时成对写出）

- 目录爆破是**最容易被发现**的阶段：WAF 与访问日志里会出现成片 404，告警阈值通常很低。
- `.git` / 备份文件 / `server-status` 这类发现，本质是**配置缺陷**，应作为暴露面问题写进报告，而不是当作攻击成果。
- 共享目录扫描（Snaffler 类工具）对应 Windows 安全日志的**文件共享访问审计（5145）**，量大时极易被 SIEM 规则命中。
- 参数挖掘类工具会产生大量畸形请求，建议在授权范围内限制速率，避免与服务可用性要求冲突。
