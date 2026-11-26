# 阶段 8 · 对抗模拟与检测验证

> **这一章是整份索引里防守价值最高的部分。** 对抗模拟的目的不是"打进去"，而是**在可控条件下验证防护是否生效**，属于紫队（Purple Team）工作。

## 对抗模拟框架

- **MITRE CALDERA** — 自动化对抗行为模拟平台，内置 ATT&CK 插件 · https://github.com/mitre/caldera
- **Atomic Red Team** — 按 ATT&CK 技术编号组织的最小化检测测试集（**最实用的检测验证工具**） · https://github.com/redcanaryco/atomic-red-team
- **APTSimulator** — 模拟被入侵主机的痕迹特征 · https://github.com/NextronSystems/APTSimulator
- **RTA (Red Team Automation)** — 面向蓝队的检测能力测试脚本集 · https://github.com/endgameinc/RTA
- **Metta** — 对抗模拟与安全准备度评估 · https://github.com/uber-common/metta
- **flightsim (Network Flight Simulator)** — 生成恶意流量特征，验证网络检测与可见性 · https://github.com/alphasoc/flightsim

## 检测工程与日志

- **sysmon-config** — Sysmon 配置基线（SwiftOnSecurity），定义"防守方采集什么" · https://github.com/SwiftOnSecurity/sysmon-config
- **agentic-detections** — 本仓库同级技能，Agent 行为检测规则集（见 `skills/agentic-detections`）
- **awesome-malware-analysis** — 恶意样本分析资源大全 · https://github.com/rshipp/awesome-malware-analysis
- **malware-analysis-detection-engineering** — 检测工程实践 · https://github.com/Apress/malware-analysis-detection-engineering
- **SpiderLabs malware-analysis** — 样本分析工具与笔记 · https://github.com/SpiderLabs/malware-analysis

## 样本与逆向

- **theZoo** — 公开恶意样本库（隔离环境使用） · https://github.com/ytisf/theZoo
- **malzoo** — 样本收集与初步分析 · https://github.com/nheijmans/malzoo
- **PracticalMalwareAnalysis-Labs** — 《恶意代码分析实战》实验环境 · https://github.com/mikesiko/PracticalMalwareAnalysis-Labs
- **SSMA** — 简易静态恶意代码分析 · https://github.com/secrary/SSMA
- **aleph** — 样本自动化分析环境 · https://github.com/merces/aleph
- **retoolkit** — 逆向与样本分析工具集 · https://github.com/mentebinaria/retoolkit
- **Ghidra** — NSA 开源逆向分析框架 · https://github.com/NationalSecurityAgency/ghidra
- **Reverse-Engineering / awesome-reversing** — 逆向学习资源索引 · https://github.com/mytechnotalent/Reverse-Engineering
- **Z0FCourse_ReverseEngineering** — 逆向入门课程 · https://github.com/0xZ0F/Z0FCourse_ReverseEngineering

## 怎么用这一章（紫队四步）

1. **选技术**：从 Atomic Red Team 里挑与本次评估范围对应的 ATT&CK 技术编号。
2. **跑测试**：在隔离终端执行，记录 EDR/SIEM 是否告警、告警延迟多少。
3. **补规则**：未告警的项，转成具体检测规则需求（数据源 + 逻辑 + 阈值）。
4. **复测**：改完规则再跑一遍，形成闭环——**这才是"检测能力"的证据**。

## 防守方视角

- 对抗模拟的输出应是一张**"技术 × 是否检出 × 检测延迟"**的矩阵，而不是工具执行记录。
- **未检出不等于工具强**，多数情况是数据源缺失（没开 Script Block Logging、没部署 Sysmon、日志没进 SIEM）。先补数据源，再谈规则。
- `flightsim` 与 `Egress-Assess` 这类"流量生成器"的价值常被低估：它们能直接证明网络侧到底看不看得见异常流量。
- 恶意样本只在**隔离环境**运行，且要有快照回滚；这一步没有任何捷径。
