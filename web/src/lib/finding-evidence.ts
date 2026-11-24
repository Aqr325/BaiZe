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

export function evidenceGradeMeta(grade?: string): EvidenceGradeMeta {
  const g = evidenceGradeOf(grade);
  switch (g) {
    case "remote_verified":
      return {
        grade: g,
        label: "远端独立验证",
        tone: "green",
        description: "经远端独立复现/复测确认，可作为已独立验证结论",
      };
    case "local_effect":
      return {
        grade: g,
        label: "本地效果",
        tone: "amber",
        description: "本地可复现效果，但未经远端独立验证",
      };
    default:
      return {
        grade: g,
        label: "外部自述",
        tone: "slate",
        description: "页面/日志自述，未经独立验证，需人工确认",
      };
  }
}
