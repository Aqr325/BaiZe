"use client";
import * as React from "react";

import { Loader2Icon, RefreshCwIcon, SquareIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { SubagentRun } from "@/lib/types";

const STATE_BADGE: Record<string, string> = {
  PENDING: "bg-zinc-100 text-zinc-600",
  STARTING: "bg-sky-100 text-sky-800",
  RUNNING: "bg-emerald-100 text-emerald-800",
  SUCCEEDED: "bg-teal-100 text-teal-800",
  FAILED: "bg-red-100 text-red-800",
  INTERRUPTED: "bg-amber-100 text-amber-800",
  CANCELLED: "bg-zinc-200 text-zinc-700",
  CANCEL_REQUESTED: "bg-violet-100 text-violet-800",
  UNKNOWN: "bg-zinc-200 text-zinc-600",
};

const STATE_KEY: Record<string, string> = {
  PENDING: "screen.subagents.statePending",
  STARTING: "screen.subagents.stateStarting",
  RUNNING: "screen.subagents.stateRunning",
  SUCCEEDED: "screen.subagents.stateSucceeded",
  FAILED: "screen.subagents.stateFailed",
  INTERRUPTED: "screen.subagents.stateInterrupted",
  CANCELLED: "screen.subagents.stateCancelled",
  CANCEL_REQUESTED: "screen.subagents.stateCancelRequested",
  UNKNOWN: "screen.subagents.stateUnknown",
};

function fmtDate(ts: string | undefined, ui: UITranslate) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(ui("screen.pentestReports.locale"), {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function roleLabel(role: string, ui: UITranslate) {
  if (role === "orchestrator") return ui("screen.subagents.roleOrchestrator");
  if (role === "leaf") return ui("screen.subagents.roleLeaf");
  return role || "—";
}

export default function SubagentsPage() {
  const { ui } = useUITranslation();
  const [items, setItems] = React.useState<SubagentRun[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [busyId, setBusyId] = React.useState<string>("");
  const [error, setError] = React.useState<string>("");

  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const r = await api.subagents();
      setItems(r.items);
    } catch (e) {
      setError(ui("screen.subagents.error") + "：" + String(e));
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  const cancel = React.useCallback(
    async (sub: SubagentRun) => {
      setBusyId(sub.subagent_id);
      setError("");
      try {
        const r = await api.cancelSubagent(sub.subagent_id);
        if (r.unknown_handle) {
          setError(ui("screen.subagents.cancelUnknown"));
        } else if (r.already_terminal) {
          setError(ui("screen.subagents.cancelTerminal"));
        } else if (r.unsupported) {
          setError(ui("screen.subagents.cancelUnsupported"));
        } else if (r.accepted) {
          // Accepted: refresh the row shortly to reflect CANCEL_REQUESTED.
          setTimeout(() => void load(), 400);
        }
      } catch (e) {
        setError(ui("screen.subagents.error") + "：" + String(e));
      } finally {
        setBusyId("");
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  const terminal = (st: string) => st === "SUCCEEDED" || st === "FAILED" || st === "INTERRUPTED" || st === "CANCELLED";

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">{ui("screen.subagents.title")}</h1>
          <p className="text-muted-foreground mt-1 text-sm">{ui("screen.subagents.subtitle")}</p>
        </div>
        <Button variant="outline" size="sm" onClick={() => void load()} disabled={loading}>
          {loading ? <Loader2Icon className="h-4 w-4 animate-spin" /> : <RefreshCwIcon className="h-4 w-4" />}
          {ui("screen.subagents.refresh")}
        </Button>
      </div>

      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">{error}</div>
      ) : null}

      <Card>
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>{ui("screen.subagents.colSubagent")}</TableHead>
              <TableHead>{ui("screen.subagents.colParent")}</TableHead>
              <TableHead>{ui("screen.subagents.colTask")}</TableHead>
              <TableHead>{ui("screen.subagents.colRole")}</TableHead>
              <TableHead>{ui("screen.subagents.colModel")}</TableHead>
              <TableHead>{ui("screen.subagents.colState")}</TableHead>
              <TableHead>{ui("screen.subagents.colCreated")}</TableHead>
              <TableHead>{ui("screen.subagents.colSummary")}</TableHead>
              <TableHead>{ui("screen.subagents.colActions")}</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {loading && items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-muted-foreground py-8 text-center">
                  <Loader2Icon className="mr-2 inline h-4 w-4 animate-spin" />
                  {ui("screen.subagents.loading")}
                </TableCell>
              </TableRow>
            ) : items.length === 0 ? (
              <TableRow>
                <TableCell colSpan={9} className="text-muted-foreground py-8 text-center">
                  {ui("screen.subagents.empty")}
                </TableCell>
              </TableRow>
            ) : (
              items.map((s) => {
                const st = STATE_KEY[s.state] ? ui(STATE_KEY[s.state]) : s.state;
                return (
                  <TableRow key={s.subagent_id}>
                    <TableCell className="max-w-[220px]">
                      <div className="font-mono text-xs text-zinc-600">{s.subagent_id}</div>
                      {s.result_hash ? (
                        <div className="text-muted-foreground mt-0.5 font-mono text-[10px]">
                          {s.result_hash.slice(0, 12)}…
                        </div>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-muted-foreground max-w-[160px]">
                      <div className="truncate font-mono text-xs">{s.parent_session_id || "—"}</div>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">
                      {s.parent_task_id > 0 ? s.parent_task_id : "—"}
                    </TableCell>
                    <TableCell className="text-sm">{roleLabel(s.role, ui)}</TableCell>
                    <TableCell className="text-muted-foreground text-sm">{s.model || "—"}</TableCell>
                    <TableCell>
                      <Badge className={STATE_BADGE[s.state] ?? "bg-zinc-100 text-zinc-600"} variant="secondary">
                        {st}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-muted-foreground text-sm">{fmtDate(s.created_at, ui)}</TableCell>
                    <TableCell className="max-w-[260px]">
                      <div className="truncate text-sm" title={s.summary}>
                        {s.summary || "—"}
                      </div>
                      {s.error_message ? (
                        <div className="text-muted-foreground truncate text-xs" title={s.error_message}>
                          {s.error_message}
                        </div>
                      ) : null}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        disabled={busyId !== "" || terminal(s.state)}
                        onClick={() => void cancel(s)}
                        title={ui("screen.subagents.cancel")}
                      >
                        {busyId === s.subagent_id ? (
                          <Loader2Icon className="h-3 w-3 animate-spin" />
                        ) : (
                          <SquareIcon className="h-3 w-3" />
                        )}
                        {ui("screen.subagents.cancel")}
                      </Button>
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
