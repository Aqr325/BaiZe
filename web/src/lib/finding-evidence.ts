import type { Tone } from "./status";

// 证据来源分级(反蜜罐「外部自述/本地效果/远端独立验证」三分)。
// 与后端 db.ValidEvidenceGrade / ModelEvidenceGrade 对应:模型记录最多
// local_effect,remote_verified 只能由复测/人工确认,模型不可自证。
export type EvidenceGrade = "self_claim" | "local_effect" | "remote_verified";

export function evidenceGradeOf(grade?: string): EvidenceGrade {
  if (grade === "remote_verified" || grade === "local_effect") return grade;
  return "self_claim";
}

export interface EvidenceGradeMeta {
  grade: EvidenceGrade;
  label: string;
  tone: Tone;
  description: string;
}

// 中文默认文案;传入 translate 时改走 i18n key,与 lib/status.ts 的 statusMeta
// 同构(那里也是「中文兜底 + translate(`status.domain.key`)」)。
const evidence: Record<EvidenceGrade, Pick<EvidenceGradeMeta, "tone" | "label" | "description">> = {
  remote_verified: {
    tone: "green",
    label: "远端独立验证",
    description: "经远端独立复现/复测确认，可作为已独立验证结论",
  },
  local_effect: {
    tone: "amber",
    label: "本地效果",
    description: "本地可复现效果，但未经远端独立验证",
  },
  self_claim: {
    tone: "slate",
    label: "外部自述",
    description: "页面/日志自述，未经独立验证，需人工确认",
  },
};

export function evidenceGradeMeta(grade?: string, translate?: (key: string) => string): EvidenceGradeMeta {
  const g = evidenceGradeOf(grade);
  const meta = evidence[g];
  return {
    grade: g,
    tone: meta.tone,
    label: translate ? translate(`status.evidenceGrade.${g}`) : meta.label,
    description: translate ? translate(`evidenceGradeDescription.${g}`) : meta.description,
  };
}
