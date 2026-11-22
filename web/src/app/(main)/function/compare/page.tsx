"use client";
import * as React from "react";

import { ArrowRightLeftIcon, Loader2Icon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { Task, TaskCompareFinding, TaskCompareResult } from "@/lib/types";

const SEV_STYLE: Record<string, string> = {
  critical: "bg-red-950 text-red-100",
  high: "bg-red-100 text-red-800",
  medium: "bg-amber-100 text-amber-800",
  low: "bg-blue-100 text-blue-800",
  info: "bg-zinc-100 text-zinc-600",
};

function taskLabel(t: Task | undefined) {
  if (!t) return "";
  return t.name || t.description;
}

function FindingList({
  items,
  ui,
  emptyText,
  tone,
}: {
  items: TaskCompareFinding[];
  ui: UITranslate;
  emptyText: string;
  tone: "fixed" | "new" | "persistent";
}) {
  if (items.length === 0) {
    return <p className="text-muted-foreground py-6 text-center text-sm">{emptyText}</p>;
  }
  return (
    <ul className="flex flex-col gap-2">
      {items.map((f) => (
        <li key={f.id} className="rounded-md border px-3 py-2">
          <div className="flex flex-wrap items-center gap-2">
            <Badge className={SEV_STYLE[f.severity] ?? SEV_STYLE.info} variant="secondary">
              {ui(`screen.compare.sev.${f.severity || "info"}`)}
            </Badge>
            <span className="text-sm font-medium">{f.name}</span>
            {f.vulnclass ? <span className="text-muted-foreground text-xs">{f.vulnclass}</span> : null}
            {tone !== "new" ? (
              <Badge variant="outline" className="text-xs">
                {ui("screen.compare.statusPrefix")}
                {ui(`screen.compare.status.${f.status || "pending"}`)}
              </Badge>
            ) : null}
          </div>
          {f.summary ? <p className="text-muted-foreground mt-1 line-clamp-2 text-xs">{f.summary}</p> : null}
        </li>
      ))}
    </ul>
  );
}

export default function TaskComparePage() {
  const { ui } = useUITranslation();
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [a, setA] = React.useState("");
  const [b, setB] = React.useState("");
  const [result, setResult] = React.useState<TaskCompareResult | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [error, setError] = React.useState("");

  React.useEffect(() => {
    api
      .tasks()
      .then((r) => setTasks(r.tasks))
      .catch(() => setTasks([]));
  }, []);

  const run = React.useCallback(async () => {
    if (!a || !b || a === b) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      setResult(await api.tasksCompare(a, b));
    } catch (e) {
      setError(ui("screen.compare.loadFailed", { v0: String(e) }));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [a, b]);

  const options = tasks.map((t) => ({ id: t.id, label: taskLabel(t) || ui("screen.compare.untitled") }));

  return (
    <div className="flex flex-col gap-4 p-6">
      <div>
        <h1 className="text-xl font-bold">{ui("screen.compare.title")}</h1>
        <p className="text-muted-foreground mt-1 text-sm">
          {ui("screen.compare.subtitle")}
        </p>
      </div>

      <Card className="flex flex-wrap items-end gap-3 p-4">
        <div className="flex min-w-[220px] flex-1 flex-col gap-1">
          <span className="text-muted-foreground text-xs">{ui("screen.compare.baseline")}</span>
          <Select value={a} onValueChange={setA}>
            <SelectTrigger>
              <SelectValue placeholder={ui("screen.compare.pickTask")} />
            </SelectTrigger>
            <SelectContent>
              {options.map((o) => (
                <SelectItem key={o.id} value={o.id}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <ArrowRightLeftIcon className="text-muted-foreground mb-2 h-4 w-4 shrink-0" />
        <div className="flex min-w-[220px] flex-1 flex-col gap-1">
          <span className="text-muted-foreground text-xs">{ui("screen.compare.retest")}</span>
          <Select value={b} onValueChange={setB}>
            <SelectTrigger>
              <SelectValue placeholder={ui("screen.compare.pickTask")} />
            </SelectTrigger>
            <SelectContent>
              {options.map((o) => (
                <SelectItem key={o.id} value={o.id}>
                  {o.label}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        </div>
        <Button className="mb-0.5" onClick={() => void run()} disabled={loading || !a || !b || a === b}>
          {loading ? <Loader2Icon className="h-4 w-4 animate-spin" /> : null}
          {ui("screen.compare.run")}
        </Button>
      </Card>

      {error ? <div className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">{error}</div> : null}

      {result ? (
        <>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
            {(
              [
                { key: "fixed", tone: "fixed" as const, list: result.fixed, color: "text-emerald-600" },
                { key: "new", tone: "new" as const, list: result.new, color: "text-red-600" },
                { key: "persistent", tone: "persistent" as const, list: result.persistent, color: "text-amber-600" },
              ]
            ).map(({ key, tone, list, color }) => (
              <Card key={key} className="p-4">
                <div className="mb-3 flex items-center justify-between">
                  <h2 className="text-sm font-semibold">{ui(`screen.compare.${key}`)}</h2>
                  <span className={`text-lg font-bold tabular-nums ${color}`}>{list.length}</span>
                </div>
                <FindingList
                  items={list}
                  ui={ui}
                  tone={tone}
                  emptyText={ui(`screen.compare.empty.${key}`)}
                />
              </Card>
            ))}
          </div>
        </>
      ) : null}
    </div>
  );
}
