"use client";

import * as React from "react";
import { useTranslation } from "react-i18next";
import { CheckIcon, RefreshCwIcon, ShieldAlertIcon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { api, type McpPinQuarantine, type McpSecurityEvent } from "@/lib/api";

function fmtTime(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// Panel surfacing assembly-time MCP supply-chain signals and the quarantine
// approval workflow. Empty state is intentionally quiet: a healthy deployment
// shows no events and no quarantined tools.
export function McpSecurityCard() {
  const { t } = useTranslation();
  const [events, setEvents] = React.useState<McpSecurityEvent[]>([]);
  const [quarantine, setQuarantine] = React.useState<McpPinQuarantine[]>([]);
  const [enforce, setEnforce] = React.useState(true);
  const [loading, setLoading] = React.useState(false);
  const [approving, setApproving] = React.useState<string | null>(null);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      const [ev, q] = await Promise.all([api.mcpSecurityEvents(100), api.mcpPinQuarantine()]);
      setEvents(ev);
      setQuarantine(q.items ?? []);
      setEnforce(q.enforce !== false);
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  async function toggleEnforce(next: boolean) {
    setEnforce(next);
    try {
      await api.mcpPinSetConfig(next);
      toast.success(next ? t("mcpSecurity.toast.enforceOn") : t("mcpSecurity.toast.enforceOff"));
    } catch {
      setEnforce(!next);
      toast.error(t("mcpSecurity.toast.enforceError"));
    }
  }

  async function approve(item: McpPinQuarantine) {
    const key = `${item.server_name}:${item.tool_name}`;
    setApproving(key);
    try {
      await api.mcpPinApprove(item.server_name, item.tool_name, item.new_hash);
      toast.success(t("mcpSecurity.toast.approved"));
      await load();
    } catch {
      toast.error(t("mcpSecurity.toast.approveError"));
    } finally {
      setApproving(null);
    }
  }

  const kindLabel = (kind: McpSecurityEvent["kind"]) =>
    kind === "pin" ? t("mcpSecurity.kind.pin") : kind === "shadow" ? t("mcpSecurity.kind.shadow") : kind;

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlertIcon className="size-4 text-amber-500" />
          <div>
            <CardTitle className="text-base">{t("mcpSecurity.title")}</CardTitle>
            <CardDescription>{t("mcpSecurity.description")}</CardDescription>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-3.5 animate-spin" : "size-3.5"} />
          {t("mcpSecurity.refresh")}
        </Button>
      </CardHeader>
      <CardContent className="flex flex-col gap-4">
        <div className="flex items-center justify-between gap-3 rounded-md border bg-muted/30 px-3 py-2">
          <div className="flex flex-col gap-0.5">
            <Label htmlFor="mcp-pin-enforce" className="text-sm">{t("mcpSecurity.enforceLabel")}</Label>
            <span className="text-xs text-muted-foreground">{t("mcpSecurity.enforceHint")}</span>
          </div>
          <Switch id="mcp-pin-enforce" checked={enforce} onCheckedChange={(v) => void toggleEnforce(v)} />
        </div>

        {quarantine.length > 0 && (
          <div className="flex flex-col gap-2">
            <div className="flex items-center gap-2 text-sm font-medium text-red-600 dark:text-red-400">
              <ShieldAlertIcon className="size-4" />
              {t("mcpSecurity.quarantinedCount", { count: quarantine.length })}
            </div>
            <div className="divide-y rounded-md border border-red-300 dark:border-red-800">
              {quarantine.map((q) => {
                const key = `${q.server_name}:${q.tool_name}`;
                return (
                  <div key={key} className="flex flex-col gap-1.5 px-3 py-2 text-sm sm:flex-row sm:items-center sm:gap-3">
                    <Badge variant="destructive" className="w-fit shrink-0">{t("mcpSecurity.quarantined")}</Badge>
                    <span className="min-w-0 truncate font-mono text-xs">
                      {q.server_name} / {q.tool_name}
                    </span>
                    <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                      {q.old_hash.slice(0, 12)} → {q.new_hash.slice(0, 12)}
                    </span>
                    <span className="min-w-0 flex-1 break-words text-xs text-muted-foreground">{fmtTime(q.detected_at)}</span>
                    <Button
                      size="sm"
                      variant="outline"
                      className="h-7 shrink-0"
                      disabled={approving === key}
                      onClick={() => void approve(q)}
                    >
                      <CheckIcon className="size-3.5" />
                      {t("mcpSecurity.approve")}
                    </Button>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        <div className="flex flex-col gap-2">
          <div className="text-sm font-medium">{t("mcpSecurity.eventsTitle")}</div>
          {events.length === 0 ? (
            <p className="py-4 text-center text-sm text-muted-foreground">{t("mcpSecurity.noEvents")}</p>
          ) : (
            <div className="divide-y rounded-md border">
              {events.map((e) => (
                <div key={e.id} className="flex flex-col gap-1 px-3 py-2 text-sm sm:flex-row sm:items-center sm:gap-3">
                  <Badge variant={e.kind === "pin" ? "destructive" : "secondary"} className="w-fit shrink-0">
                    {kindLabel(e.kind)}
                  </Badge>
                  <span className="shrink-0 font-mono text-xs text-muted-foreground">{fmtTime(e.created_at)}</span>
                  <span className="min-w-0 truncate font-mono text-xs">
                    {e.server_name} / {e.tool_name}
                  </span>
                  <span className="min-w-0 flex-1 break-words text-xs text-muted-foreground">{e.detail}</span>
                </div>
              ))}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
