"use client";

import { evidenceGradeMeta } from "@/lib/finding-evidence";
import { toneClasses, toneDot } from "@/lib/status";
import { cn } from "@/lib/utils";

export function EvidenceGradeBadge({
  grade,
  dot = false,
  className,
}: {
  grade?: string;
  dot?: boolean;
  className?: string;
}) {
  const meta = evidenceGradeMeta(grade);
  return (
    <span
      title={meta.description}
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap",
        toneClasses[meta.tone],
        className,
      )}
    >
      {dot && <span className={cn("size-1.5 rounded-full", toneDot[meta.tone])} />}
      {meta.label}
    </span>
  );
}
