"use client";
import * as React from "react";

import Link from "next/link";

import { FlameIcon, ShieldAlertIcon } from "lucide-react";

import { EvidenceGradeBadge } from "@/components/evidence-grade-badge";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { api } from "@/lib/api";
import type { Finding, FindingStatus } from "@/lib/types";

// 防守视角：AI 报出的误报/自述不是垃圾，是「看起来像漏洞的代码味道」——
// 高频误报点就是人工 review 该重点看的地方。这里把 evidence_grade=self_claim
// （模型仅自述、无独立验证）与 status=false_positive 汇聚成「待人工复核」队列，
// 作为复核与回喂团队规则的入口。人与 AI 用同一套证据链标准（skills/evidence-chain）。

// 证据驱动分类/分级展示：标签映射抽到 lib/finding-triage，与 findings 主列表共用。
import { harmLabel, triageLabel } from "@/lib/finding-triage";

// 防抖排序：triage_tier 升序（越优先越靠前）；同档按 ts 升序（证据首次出现时间
// 固定，普通后续报道不打乱顺序——只有新证据升档才上移）。见 db/evidence_triage.go。
function debounceSort(a: Finding, b: Finding) {
  const ta = a.triage_tier ?? 6;
  const tb = b.triage_tier ?? 6;
  if (ta !== tb) return ta - tb;
  return a.ts.localeCompare(b.ts);
}

export function ReviewQueueCard() {
  const [selfClaim, setSelfClaim] = React.useState<Finding[]>([]);
  const [selfTotal, setSelfTotal] = React.useState(0);
  const [fpTotal, setFpTotal] = React.useState(0);
  const [loading, setLoading] = React.useState(true);
  // 批量复核：选中的 finding 句柄（finding_id ?? id），用于批量确认/驳回。
  const [selected, setSelected] = React.useState<Set<string>>(new Set());
  const [busy, setBusy] = React.useState(false);
  const [notice, setNotice] = React.useState("");

  const handleId = (f: Finding) => f.finding_id ?? f.id;

  const load = React.useCallback(async () => {
    try {
      const [sc, fp] = await Promise.all([
        api.findingsPage({ page: 1, pageSize: 8, evidenceGrade: "self_claim" }),
        api.findingsPage({ page: 1, pageSize: 1, status: "false_positive" }),
      ]);
      setSelfClaim([...sc.items].sort(debounceSort));
      setSelfTotal(sc.total);
      setFpTotal(fp.total);
    } catch {
      /* 静默：卡片不阻塞页面 */
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    let alive = true;
    void (async () => {
      try {
        const [sc, fp] = await Promise.all([
          api.findingsPage({ page: 1, pageSize: 8, evidenceGrade: "self_claim" }),
          api.findingsPage({ page: 1, pageSize: 1, status: "false_positive" }),
        ]);
        if (!alive) return;
        setSelfClaim([...sc.items].sort(debounceSort));
        setSelfTotal(sc.total);
        setFpTotal(fp.total);
      } catch {
        /* 静默：卡片不阻塞页面 */
      } finally {
        if (alive) setLoading(false);
      }
    })();
    return () => {
      alive = false;
    };
  }, []);

  // 全选/取消全选当前展示项。
  const toggleAll = () => {
    setSelected((prev) => {
      const handles = selfClaim.map(handleId);
      const allOn = handles.length > 0 && handles.every((id) => prev.has(id));
      const next = new Set(prev);
      if (allOn) handles.forEach((id) => next.delete(id));
      else handles.forEach((id) => next.add(id));
      return next;
    });
  };

  const toggleOne = (id: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const allSelected = selfClaim.length > 0 && selfClaim.every((f) => selected.has(handleId(f)));

  const batchApply = async (status: FindingStatus) => {
    if (selected.size === 0 || busy) return;
    setBusy(true);
    setNotice("");
    try {
      const ids = selfClaim.filter((f) => selected.has(handleId(f))).map(handleId);
      const res = await api.batchFindingStatus(ids, status);
      setNotice(status === "confirmed" ? `已确认 ${res.updated} 条` : `已驳回 ${res.updated} 条`);
      setSelected(new Set());
      setLoading(true);
      await load();
    } catch (e) {
      setNotice(`批量操作失败：${String(e)}`);
    } finally {
      setBusy(false);
      setLoading(false);
    }
  };

  // 头条：「此刻最该处理哪个」= 最优先档里最新的一条（HeadlineRank 语义）。
  const headline = selfClaim.length > 0 ? selfClaim[0] : null;

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-sm">
          <ShieldAlertIcon data-icon="inline-start" className="size-4" />
          待人工复核队列
        </CardTitle>
        <div className="flex items-center gap-2">
          <Badge variant="outline" title="模型仅自述、无独立验证证据的发现，按「待验证线索」对待">
            自述待核 {selfTotal}
          </Badge>
          <Badge variant="outline" title="已人工定性的误报，其高频点即 review 重点">
            误报 {fpTotal}
          </Badge>
        </div>
      </CardHeader>
      <CardContent>
        {loading ? (
          <p className="text-sm text-muted-foreground">加载中…</p>
        ) : selfClaim.length === 0 ? (
          <p className="text-sm text-muted-foreground">
            暂无待复核发现——所有发现均已有独立验证证据（remote_verified）或已定性。
          </p>
        ) : (
          <div className="space-y-2">
            {headline && (
              <div className="rounded-md border border-amber-300/60 bg-amber-50/60 px-3 py-2 text-xs dark:border-amber-500/40 dark:bg-amber-950/30">
                <span className="flex items-center gap-1 font-medium text-amber-700 dark:text-amber-300">
                  <FlameIcon data-icon="inline-start" className="size-3.5" />
                  最该处理：{triageLabel(headline.triage_tier)}
                </span>
                <Link
                  href={`/function/findings/detail?id=${encodeURIComponent(headline.finding_id || headline.id)}`}
                  className="mt-1 block truncate text-sm text-foreground hover:underline"
                >
                  {headline.name || headline.vulnclass || headline.summary}
                </Link>
                <span className="mt-1 block text-muted-foreground">
                  {harmLabel(headline.harm_primitive)} · 资产{" "}
                  {headline.asset_tier ? `Tier ${headline.asset_tier.toUpperCase()}` : "Tier C"}
                </span>
              </div>
            )}
            <ul className="space-y-2">
              {selfClaim.map((f) => {
                const hid = handleId(f);
                return (
                  <li key={f.id} className="flex items-center gap-2">
                    <Checkbox
                      checked={selected.has(hid)}
                      onCheckedChange={() => toggleOne(hid)}
                      aria-label="选择该发现"
                      className="shrink-0"
                    />
                    <Link
                      href={`/function/findings/detail?id=${encodeURIComponent(f.finding_id || f.id)}`}
                      className="flex min-w-0 flex-1 items-center justify-between gap-2 text-sm hover:underline"
                    >
                      <span className="min-w-0 flex-1 truncate">{f.name || f.vulnclass || f.summary}</span>
                      <Badge variant="outline" className="shrink-0 text-[10px]" title={triageLabel(f.triage_tier)}>
                        {triageLabel(f.triage_tier)}
                      </Badge>
                      <span className="shrink-0 text-[10px] text-muted-foreground" title={harmLabel(f.harm_primitive)}>
                        {harmLabel(f.harm_primitive)}
                      </span>
                      <EvidenceGradeBadge grade={f.evidence_grade} dot />
                    </Link>
                  </li>
                );
              })}
            </ul>
            {/* 批量复核工具条：全选 + 批量确认/驳回 */}
            <div className="mt-3 flex flex-wrap items-center gap-2 border-t pt-3">
              <Button variant="ghost" size="sm" onClick={toggleAll} disabled={selfClaim.length === 0}>
                {allSelected ? "取消全选" : "全选"}
              </Button>
              <span className="text-muted-foreground text-xs">
                {selected.size > 0 ? `已选 ${selected.size} 条` : "未选"}
              </span>
              <div className="ml-auto flex items-center gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  className="border-emerald-300/60 text-emerald-700 hover:bg-emerald-50 dark:border-emerald-500/40 dark:text-emerald-300"
                  disabled={selected.size === 0 || busy}
                  onClick={() => void batchApply("confirmed")}
                >
                  {busy ? "处理中…" : "批量确认"}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  className="border-red-300/60 text-red-700 hover:bg-red-50 dark:border-red-500/40 dark:text-red-300"
                  disabled={selected.size === 0 || busy}
                  onClick={() => void batchApply("false_positive")}
                >
                  {busy ? "处理中…" : "批量驳回"}
                </Button>
              </div>
            </div>
            {notice ? <p className="mt-2 text-xs text-muted-foreground">{notice}</p> : null}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
