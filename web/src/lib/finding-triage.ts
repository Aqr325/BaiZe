import type { Tone } from "./status";

// 证据驱动分类/分级展示（借 Today Security 方法论，与 db/evidence_triage.go 对齐）。
// 复核队列卡与 findings 主列表共用同一套标签与色调，避免两处文案漂移。
export const HARM_LABEL: Record<string, string> = {
  rce: "远程代码执行",
  auth_bypass: "认证绕过",
  privilege_escalation: "提权/逃逸",
  unauthorized: "未授权访问",
  file_write: "任意文件写/读",
  injection: "注入/跨站",
  ssrf: "SSRF",
  info_leak: "信息泄露",
  dos: "拒绝服务",
  other: "其他",
};

export const TRIAGE_LABEL: Record<number, string> = {
  1: "在野利用·未见修复",
  2: "在野利用",
  3: "在野利用·已有修复",
  4: "高危 PoC 公开·未见修复",
  5: "核心资产严重预警",
  6: "跟踪",
};

// 分级色调：1-3 在野利用最紧急（red），4 高危 PoC（amber），
// 5 核心资产预警（amber），6 跟踪（slate）。
export const TRIAGE_TONE: Record<number, Tone> = {
  1: "red",
  2: "red",
  3: "red",
  4: "amber",
  5: "amber",
  6: "slate",
};

export function harmLabel(p?: string): string {
  return (p && HARM_LABEL[p]) || "其他";
}

export function triageLabel(t?: number): string {
  return (t && TRIAGE_LABEL[t]) || "跟踪";
}

export function triageTone(t?: number): Tone {
  return (t && TRIAGE_TONE[t]) || "slate";
}
