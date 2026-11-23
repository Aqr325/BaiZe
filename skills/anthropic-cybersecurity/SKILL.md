---
name: anthropic-cybersecurity
description: >
  818 个结构化网络安全技能库（Anthropic-Cybersecurity-Skills，Apache-2.0）。
  覆盖 29 个安全域，映射 6 大框架：MITRE ATT&CK、NIST CSF 2.0、MITRE ATLAS、
  D3FEND、NIST AI RMF、MITRE F3(Fight Fraud)。agentskills.io 标准，兼容
  Claude Code / Copilot / Codex / Cursor / Gemini 等。每个子技能一个 SKILL.md，
  单读即用：含 IF/THEN 决策规则、对照、误报陷阱、输出契约，可跨技能链式执行。
  由 GitHub mukul975/Anthropic-Cybersecurity-Skills 落位，Apache-2.0（可公开分发）。
---

# Anthropic Cybersecurity Skills（818 个子技能）

一个注册根技能，路由到 **818 个自包含子技能**（`skills/<子技能名>/SKILL.md`）。
每个子技能解决单一技术点，一次读取即可用——含 IF/THEN 决策规则、worked contrasts、
误报陷阱、反幻觉禁令与严格输出契约，跨阶段/跨层可与其他子技能或对应方链式衔接。

> **文件基准目录 = `${SKILL_DIR}`**（白泽会把 `${SKILL_DIR}` 替换为技能目录的绝对路径）。
> 所有相对路径均以 `${SKILL_DIR}` 为根。用 `Read "${SKILL_DIR}/<相对路径>"` 读取，
> 不要跑脚本——本技能库是「读文件」协议，不是「执行」协议。

## 选择与链式协议（严格遵循）

1. **定位子技能**：优先用全量索引 `Read "${SKILL_DIR}/index.json"`（818 条，含
   name/description/domain/path）按关键词过滤；也可直接 `Glob "${SKILL_DIR}/skills/*/SKILL.md"`。
2. **读取细节**：命中后 `Read "${SKILL_DIR}/skills/<name>/SKILL.md"`（name = 目录名）。
3. **执行**：按该 SKILL.md 的 IF/THEN 规则与输出契约执行，勿凭空补步骤。
4. **链式**：任务跨阶段时，按子技能 frontmatter 的 `tags`/`subdomain` 衔接同级或对应方子技能。
5. **框架映射**：需要攻击覆盖/合规定位时读 `mappings/mitre-attack/`、`mappings/nist-csf/`、
   `mappings/owasp/`、`mappings/attack-navigator-layer.json`、`docs/mitre-f3-mapping.md`。

## 授权与边界（硬约束）

- 仅限**授权测试**：有书面授权的渗透/红队、在范围内且符合规则的赏金、CTF 教学、自有资产研究。
- 禁止对未授权系统实施扫描/利用/提权/横向。
- 涉及凭据/数据的步骤，仅对已获授权目标执行，且遵循最小必要原则。

## 已知范围

- 子技能目录名 = 技能名（`skills/<name>/SKILL.md`），共 **818** 个，覆盖 29 域（红队/蓝队/DFIR/云/移动/合规等）。
- 索引：`index.json`（version 1.1.0，generated 2026-08-24）。
- 来源仓库：https://github.com/mukul975/Anthropic-Cybersecurity-Skills （Apache-2.0）。
