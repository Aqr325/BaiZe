"use client";
import * as React from "react";

import { GitCompareArrowsIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { useUITranslation } from "@/i18n/use-ui-translation";

import { countDiff, type DiffLine, diffLines, prettyBody } from "./repeater-diff";
import type { RepeaterHistoryEntry, RepeaterTab } from "./repeater-state";

function statusClass(status: number) {
  if (status >= 500) return "border-rose-300 text-rose-600";
  if (status >= 400) return "border-amber-300 text-amber-600";
  if (status >= 300) return "border-sky-300 text-sky-600";
  return "border-emerald-300 text-emerald-600";
}

function shortUrl(url: string) {
  try {
    const u = new URL(url);
    return `${u.host}${u.pathname}${u.search}`;
  } catch {
    return url || "(空)";
  }
}

function entryLabel(entry: RepeaterHistoryEntry) {
  const time = new Date(entry.at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  return `${entry.method} ${entry.response.status} ${shortUrl(entry.url)} · ${time}`;
}

function diffLineClass(kind: DiffLine["kind"]) {
  if (kind === "add") return "bg-emerald-500/10 text-emerald-700 dark:text-emerald-300";
  if (kind === "remove") return "bg-rose-500/10 text-rose-700 dark:text-rose-300";
  return "text-muted-foreground";
}

export function RepeaterResponseDiffDialog({
  open,
  onOpenChange,
  tab,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  tab: RepeaterTab;
}) {
  const { ui } = useUITranslation();
  const entries = tab.history; // 最新在前
  const [baseId, setBaseId] = React.useState("");
  const [targetId, setTargetId] = React.useState("");

  React.useEffect(() => {
    if (open) {
      // 默认对比「最近一次 vs 上一次」；不足两次则置空由空态提示。
      setBaseId(entries[1]?.id ?? "");
      setTargetId(entries[0]?.id ?? "");
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, tab.id]);

  const base = entries.find((entry) => entry.id === baseId);
  const target = entries.find((entry) => entry.id === targetId);

  const canCompare = base && target && base.id !== target.id;

  let diff: DiffLine[] = [];
  let added = 0;
  let removed = 0;
  let same = 0;
  if (canCompare) {
    diff = diffLines(prettyBody(base.response.body), prettyBody(target.response.body));
    const stats = countDiff(diff);
    added = stats.added;
    removed = stats.removed;
    same = stats.same;
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[85vh] overflow-hidden sm:max-w-3xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <GitCompareArrowsIcon data-icon="inline-start" className="size-4" />
            {ui("screen.repeaterCompareTitle")}
          </DialogTitle>
          <DialogDescription>{ui("screen.repeaterCompareSubtitle")}</DialogDescription>
        </DialogHeader>

        {entries.length < 2 ? (
          <p className="text-muted-foreground py-6 text-center text-sm">{ui("screen.repeaterCompareEmpty")}</p>
        ) : (
          <div className="flex min-h-0 flex-col gap-3">
            {/* 选择基线 / 目标 */}
            <div className="grid gap-2 sm:grid-cols-2">
              <Select value={baseId} onValueChange={setBaseId}>
                <SelectTrigger className="text-xs">
                  <SelectValue placeholder={ui("screen.repeaterCompareBaseline")} />
                </SelectTrigger>
                <SelectContent>
                  {entries.map((entry) => (
                    <SelectItem key={entry.id} value={entry.id} className="font-mono text-xs">
                      {entryLabel(entry)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={targetId} onValueChange={setTargetId}>
                <SelectTrigger className="text-xs">
                  <SelectValue placeholder={ui("screen.repeaterCompareTarget")} />
                </SelectTrigger>
                <SelectContent>
                  {entries.map((entry) => (
                    <SelectItem key={entry.id} value={entry.id} className="font-mono text-xs">
                      {entryLabel(entry)}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* 两侧摘要 */}
            <div className="grid gap-2 sm:grid-cols-2">
              {[base, target].map((entry, idx) => (
                <div key={idx} className="rounded-md border p-2 text-xs">
                  <div className="text-muted-foreground mb-1 font-medium">
                    {idx === 0 ? ui("screen.repeaterCompareBaseline") : ui("screen.repeaterCompareTarget")}
                  </div>
                  {entry ? (
                    <div className="flex flex-wrap items-center gap-2">
                      <Badge variant="outline" className={statusClass(entry.response.status)}>
                        {entry.response.status} {entry.response.status_text}
                      </Badge>
                      <span className="text-muted-foreground">{entry.response.elapsed_ms} ms</span>
                      <span className="text-muted-foreground">{entry.response.body_bytes.toLocaleString()} B</span>
                    </div>
                  ) : (
                    <span className="text-muted-foreground">—</span>
                  )}
                </div>
              ))}
            </div>

            {canCompare ? (
              <>
                <div className="flex items-center gap-2 text-xs">
                  <Badge variant="outline" className="border-emerald-300/60 text-emerald-700">
                    +{added}
                  </Badge>
                  <Badge variant="outline" className="border-rose-300/60 text-rose-700">
                    -{removed}
                  </Badge>
                  <span className="text-muted-foreground">{same} 行相同</span>
                </div>
                <div className="max-h-[45vh] min-h-0 flex-1 overflow-auto rounded-md border font-mono text-[11px] leading-5">
                  {diff.map((line, idx) => (
                    <div key={idx} className={`flex ${diffLineClass(line.kind)}`}>
                      <span className="w-5 shrink-0 select-none text-right pr-1 text-muted-foreground/60">
                        {line.kind === "add" ? "+" : line.kind === "remove" ? "-" : " "}
                      </span>
                      <span className="min-w-0 flex-1 whitespace-pre-wrap break-all pr-2">{line.text || " "}</span>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <p className="text-muted-foreground text-center text-xs">{ui("screen.repeaterComparePickTwo")}</p>
            )}
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}

export function CompareButton({ tab }: { tab: RepeaterTab }) {
  const { ui } = useUITranslation();
  const [open, setOpen] = React.useState(false);
  const hasTwo = tab.history.length >= 2;
  return (
    <>
      <Button variant="outline" size="sm" disabled={!hasTwo} onClick={() => setOpen(true)}>
        <GitCompareArrowsIcon data-icon="inline-start" />
        {ui("screen.repeaterCompare")}
      </Button>
      <RepeaterResponseDiffDialog open={open} onOpenChange={setOpen} tab={tab} />
    </>
  );
}
