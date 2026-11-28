"use client";
import * as React from "react";

import { Loader2Icon, RefreshCwIcon } from "lucide-react";
import {
  Area,
  AreaChart,
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  XAxis,
  YAxis,
} from "recharts";

import { Button } from "@/components/ui/button";
import { Card } from "@/components/ui/card";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import { harmLabel, triageLabel, triageTone } from "@/lib/finding-triage";
import { toneDot } from "@/lib/status";

interface InsightsData {
  days: number;
  tasks_by_day?: { date: string; created: number; done: number; failed: number }[];
  findings_by_day?: { date: string; critical: number; high: number; medium: number; low: number; info: number }[];
  tokens_by_day?: { date: string; input: number; output: number }[];
  severity_now?: { critical: number; high: number; medium: number; low: number; info: number };
  triage_distribution?: {
    harm_primitive?: Record<string, number>;
    asset_tier?: Record<string, number>;
    triage_tier?: Record<string, number>;
  };
}

const SEV_COLORS: Record<string, string> = {
  critical: "#7f1d1d",
  high: "#dc2626",
  medium: "#d97706",
  low: "#2563eb",
  info: "#64748b",
};

const DAY_OPTIONS = [7, 30, 90] as const;

function shortDate(d: string) {
  return d.slice(5); // MM-DD
}

// 资产分层标签（与 db/evidence_triage.go 的 AssetTier 语义对齐）。
const ASSET_LABEL: Record<string, string> = {
  s: "S 级 · 边界/中间件/容器/政企OA",
  a: "A 级 · 内核/运行时/AI-Agent",
  b: "B 级 · 一般业务/端点",
  c: "C 级 · 低价值/低敏",
};

interface TriageRow {
  label: string;
  count: number;
  barClass: string;
}

// 横向条形行：label + 比例条 + 计数，供分级分布三块复用。
function TriageBarRows({ rows, empty, max }: { rows: TriageRow[]; empty: string; max: number }) {
  if (rows.length === 0) {
    return <div className="text-muted-foreground py-4 text-center text-xs">{empty}</div>;
  }
  return (
    <div className="flex flex-col gap-2">
      {rows.map((r) => {
        const pct = max > 0 ? Math.max(2, (r.count / max) * 100) : 0;
        return (
          <div key={r.label} className="flex items-center gap-2 text-xs">
            <span className="text-muted-foreground w-40 shrink-0 truncate" title={r.label}>
              {r.label}
            </span>
            <div className="bg-muted h-2 flex-1 overflow-hidden rounded-full">
              <div className={`h-full rounded-full ${r.barClass}`} style={{ width: `${pct}%` }} />
            </div>
            <span className="w-8 shrink-0 text-right tabular-nums">{r.count}</span>
          </div>
        );
      })}
    </div>
  );
}

export default function InsightsPage() {
  const { ui } = useUITranslation();
  const [days, setDays] = React.useState<number>(30);
  const [data, setData] = React.useState<InsightsData | null>(null);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");

  const load = React.useCallback(
    async (d: number) => {
      setLoading(true);
      setError("");
      try {
        setData(await api.insights(d));
      } catch (e) {
        setError(ui("screen.insights.loadFailed", { v0: String(e) }));
      } finally {
        setLoading(false);
      }
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [],
  );

  React.useEffect(() => {
    void load(days);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [days]);

  const sev = data?.severity_now;
  const sevTotal = sev ? Object.values(sev).reduce((a, b) => a + b, 0) : 0;

  // 证据驱动分级分布：从 triage_distribution 组装三块条形数据。
  const tri = data?.triage_distribution;
  const tierDist = tri?.triage_tier ?? {};
  const tierMax = Math.max(1, ...Object.values(tierDist));
  const tierRows: TriageRow[] = [1, 2, 3, 4, 5, 6]
    .map((t) => ({
      label: triageLabel(t),
      count: tierDist[String(t)] ?? 0,
      barClass: toneDot[triageTone(t)],
    }))
    .filter((r) => r.count > 0);

  const harmDist = tri?.harm_primitive ?? {};
  const harmMax = Math.max(1, ...Object.values(harmDist));
  const harmRows: TriageRow[] = Object.entries(harmDist)
    .map(([k, v]) => ({ label: harmLabel(k), count: v, barClass: "bg-violet-500" }))
    .sort((a, b) => b.count - a.count);

  const assetDist = tri?.asset_tier ?? {};
  const assetMax = Math.max(1, ...Object.values(assetDist));
  const assetRows: TriageRow[] = ["s", "a", "b", "c"]
    .map((k) => ({ label: ASSET_LABEL[k] ?? k, count: assetDist[k] ?? 0, barClass: "bg-blue-500" }))
    .filter((r) => r.count > 0);

  return (
    <div className="flex flex-col gap-4 p-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold">{ui("screen.insights.title")}</h1>
          <p className="text-muted-foreground mt-1 text-sm">{ui("screen.insights.subtitle")}</p>
        </div>
        <div className="flex items-center gap-2">
          {DAY_OPTIONS.map((d) => (
            <Button key={d} size="sm" variant={days === d ? "default" : "outline"} onClick={() => setDays(d)}>
              {ui("screen.insights.lastNDays", { v0: d })}
            </Button>
          ))}
          <Button variant="outline" size="sm" onClick={() => void load(days)} disabled={loading}>
            {loading ? <Loader2Icon className="h-4 w-4 animate-spin" /> : <RefreshCwIcon className="h-4 w-4" />}
          </Button>
        </div>
      </div>

      {error ? (
        <div className="rounded-md border border-red-200 bg-red-50 px-4 py-2 text-sm text-red-700">{error}</div>
      ) : null}

      {/* 当前严重等级分布 */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-5">
        {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
          <Card key={k} className="p-4">
            <div className="text-muted-foreground text-xs">{ui(`screen.insights.sev.${k}`)}</div>
            <div className="mt-1 text-2xl font-bold tabular-nums" style={{ color: SEV_COLORS[k] }}>
              {loading ? "—" : (sev?.[k] ?? 0)}
            </div>
          </Card>
        ))}
      </div>
      <p className="text-muted-foreground text-xs">{ui("screen.insights.sevTotal", { v0: sevTotal })}</p>

      {/* 证据驱动分级分布：危害原语 / 资产分层 / 处置优先级 */}
      <Card className="p-4">
        <h2 className="mb-1 text-sm font-semibold">{ui("screen.insights.triageTitle")}</h2>
        <p className="text-muted-foreground mb-4 text-xs">{ui("screen.insights.triageSubtitle")}</p>
        <div className="grid gap-6 md:grid-cols-3">
          <div>
            <div className="text-muted-foreground mb-2 text-xs font-medium">{ui("screen.insights.triageTier")}</div>
            <TriageBarRows rows={tierRows} empty={ui("screen.insights.triageEmpty")} max={tierMax} />
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-xs font-medium">{ui("screen.insights.triageHarm")}</div>
            <TriageBarRows rows={harmRows} empty={ui("screen.insights.triageEmpty")} max={harmMax} />
          </div>
          <div>
            <div className="text-muted-foreground mb-2 text-xs font-medium">{ui("screen.insights.triageAsset")}</div>
            <TriageBarRows rows={assetRows} empty={ui("screen.insights.triageEmpty")} max={assetMax} />
          </div>
        </div>
      </Card>

      {/* 任务趋势 */}
      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">{ui("screen.insights.tasksTrend")}</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data?.tasks_by_day ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tickFormatter={shortDate} fontSize={11} />
              <YAxis allowDecimals={false} fontSize={11} />
              <RechartsTooltip />
              <Legend />
              <Bar dataKey="created" name={ui("screen.insights.tasksCreated")} fill="#6366f1" stackId="a" />
              <Bar dataKey="done" name={ui("screen.insights.tasksDone")} fill="#10b981" stackId="b" />
              <Bar dataKey="failed" name={ui("screen.insights.tasksFailed")} fill="#ef4444" stackId="b" />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      {/* 发现趋势 */}
      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">{ui("screen.insights.findingsTrend")}</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={data?.findings_by_day ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tickFormatter={shortDate} fontSize={11} />
              <YAxis allowDecimals={false} fontSize={11} />
              <RechartsTooltip />
              <Legend />
              {(["critical", "high", "medium", "low", "info"] as const).map((k) => (
                <Bar key={k} dataKey={k} stackId="a" fill={SEV_COLORS[k]} name={ui(`screen.insights.sev.${k}`)} />
              ))}
            </BarChart>
          </ResponsiveContainer>
        </div>
      </Card>

      {/* Token 用量 */}
      <Card className="p-4">
        <h2 className="mb-3 text-sm font-semibold">{ui("screen.insights.tokensTrend")}</h2>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={data?.tokens_by_day ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
              <XAxis dataKey="date" tickFormatter={shortDate} fontSize={11} />
              <YAxis
                fontSize={11}
                tickFormatter={(v: number) =>
                  v >= 1_000_000
                    ? `${(v / 1_000_000).toFixed(1)}M`
                    : v >= 1000
                      ? `${(v / 1000).toFixed(0)}K`
                      : String(v)
                }
              />
              <RechartsTooltip />
              <Legend />
              <Area
                dataKey="input"
                name={ui("screen.insights.tokensInput")}
                stroke="#3b82f6"
                fill="#93c5fd"
                fillOpacity={0.4}
              />
              <Area
                dataKey="output"
                name={ui("screen.insights.tokensOutput")}
                stroke="#8b5cf6"
                fill="#c4b5fd"
                fillOpacity={0.4}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </Card>
    </div>
  );
}
