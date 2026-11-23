"use client";

import * as React from "react";

import { RefreshCwIcon, ShieldAlertIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type McpSecurityEvent } from "@/lib/api";

const KIND_LABEL: Record<McpSecurityEvent["kind"], string> = {
  pin: "描述变更",
  shadow: "名称冲突",
};

function fmtTime(ts: string) {
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return ts;
  const p = (n: number) => String(n).padStart(2, "0");
  return `${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

// Read-only panel surfacing assembly-time MCP supply-chain signals. Empty state
// is intentionally quiet: a healthy deployment should show no events at all.
export function McpSecurityCard() {
  const [events, setEvents] = React.useState<McpSecurityEvent[]>([]);
  const [loading, setLoading] = React.useState(false);

  const load = React.useCallback(async () => {
    setLoading(true);
    try {
      setEvents(await api.mcpSecurityEvents(100));
    } catch {
      setEvents([]);
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
  }, [load]);

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlertIcon className="size-4 text-amber-500" />
          <div>
            <CardTitle className="text-base">MCP 安全事件</CardTitle>
            <CardDescription>工具描述变更（疑似投毒）与工具名冲突（跨服务遮蔽）</CardDescription>
          </div>
        </div>
        <Button size="sm" variant="outline" onClick={() => void load()} disabled={loading}>
          <RefreshCwIcon className={loading ? "size-3.5 animate-spin" : "size-3.5"} />
          刷新
        </Button>
      </CardHeader>
      <CardContent>
        {events.length === 0 ? (
          <p className="py-4 text-center text-sm text-muted-foreground">暂无安全事件</p>
        ) : (
          <div className="divide-y rounded-md border">
            {events.map((e) => (
              <div key={e.id} className="flex flex-col gap-1 px-3 py-2 text-sm sm:flex-row sm:items-center sm:gap-3">
                <Badge variant={e.kind === "pin" ? "destructive" : "secondary"} className="w-fit shrink-0">
                  {KIND_LABEL[e.kind] ?? e.kind}
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
      </CardContent>
    </Card>
  );
}
