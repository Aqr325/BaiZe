"use client";
import * as React from "react";

import { FileTextIcon, Loader2Icon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { Task } from "@/lib/types";

const STATUS_BADGE: Record<string, string> = {
  running: "bg-emerald-100 text-emerald-800",
  done: "bg-sky-100 text-sky-800",
  failed: "bg-red-100 text-red-800",
  timeout: "bg-amber-100 text-amber-800",
  paused: "bg-zinc-200 text-zinc-700",
  queued: "bg-violet-100 text-violet-800",
  created: "bg-zinc-100 text-zinc-600",
};

const STATUS_KEY: Record<string, string> = {
  created: "screen.pentestReports.statusCreated",
  queued: "screen.pentestReports.statusQueued",
  running: "screen.pentestReports.statusRunning",
  paused: "screen.pentestReports.statusPaused",
  done: "screen.pentestReports.statusDone",
  failed: "screen.pentestReports.statusFailed",
  timeout: "screen.pentestReports.statusTimeout",
};

function fmtDate(ts: string, ui: UITranslate) {
  if (!ts) return "—";
  return new Date(ts).toLocaleString(ui("screen.pentestReports.locale"), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export default function PentestReportsPage() {
  const { ui } = useUITranslation();
  const [tasks, setTasks] = React.useState<Task[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busyId, setBusyId] = React.useState<string>("");
  const [error, setError] = React.useState<string>("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const r = await api.tasks();
      setTasks(r.tasks);
    } catch (e) {
      setError(ui("screen.pentestReports.loadFailed", { v0: String(e) }));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const download = React.useCallback(
    async (task: Task, format: "html" | "md") => {
      setBusyId(task.id + format);
      setError("");
      try {
        await api.pentestReport(task.id, format);
      } catch (e) {
        setError(ui("screen.pentestReports.downloadFailed", { v0: String(e) }));
      } finally {
        setBusyId("");
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">{ui("screen.pentestReports.title")}</h1>
          <p className="text-muted-foreground mt-1 text-sm">{ui("screen.pentestReports.subtitle")}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="h-4 w-4 animate-spin" /> : <RefreshCwIcon className="h-4 w-4" />}
          {ui("common.retry")}
        </Button>
      </div>

      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">{error}</div>
      ) : null}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{ui("screen.pentestReports.colTask")}</TableHead>
              <TableHead>{ui("screen.pentestReports.colStatus")}</TableHead>
              <TableHead>{ui("screen.pentestReports.colCreated")}</TableHead>
              <TableHead className="text-right">{ui("screen.pentestReports.colActions")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && tasks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-muted-foreground py-8 text-center">
                  <Loader2Icon className="mr-2 inline h-4 w-4 animate-spin" />
                  {ui("common.loading")}
                </TableCell>
              </TableRow>
            ) : tasks.length === 0 ? (
              <TableRow>
                <TableCell colSpan={4} className="text-muted-foreground py-8 text-center">
                  {ui("screen.pentestReports.empty")}
                </TableCell>
              </TableRow>
            ) : (
              tasks.map((t) => {
                const name = t.name || t.description || ui("screen.pentestReports.untitled");
                const status = STATUS_KEY[t.status] ? ui(STATUS_KEY[t.status]) : t.status;
                return (
                  <TableRow key={t.id}>
                    <TableCell className="max-w-[380px]">
                      <div className="flex items-center gap-2">
                        <FileTextIcon className="text-muted-foreground h-4 w-4 shrink-0" />
                        <div className="min-w-0">
                          <div className="truncate font-medium">{name}</div>
                          {t.goal ? <div className="text-muted-foreground truncate text-xs">{t.goal}</div> : null}
                        </div>
                      </div>
                    </TableCell>
                    <TableCell>
                      <Badge className={STATUS_BADGE[t.status] ?? "bg-zinc-100 text-zinc-600"} variant="secondary">
                        {status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">{fmtDate(t.created_at, ui)}</TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busyId !== ""}
                          onClick={() => void download(t, "html")}
                        >
                          {busyId === t.id + "html" ? <Loader2Icon className="h-3 w-3 animate-spin" /> : null}
                          {ui("screen.pentestReports.downloadHtml")}
                        </Button>
                        <Button
                          size="sm"
                          variant="outline"
                          disabled={busyId !== ""}
                          onClick={() => void download(t, "md")}
                        >
                          {busyId === t.id + "md" ? <Loader2Icon className="h-3 w-3 animate-spin" /> : null}
                          {ui("screen.pentestReports.downloadMd")}
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })
            )}
          </TableBody>
        </Table>
      </Card>
    </div>
  );
}
