"use client";
import * as React from "react";

import {
  BookOpenIcon,
  CheckCircle2Icon,
  FileTextIcon,
  FolderSyncIcon,
  InfoIcon,
  RefreshCwIcon,
} from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { ObsidianStatus, ObsidianSyncResult } from "@/lib/types";

function fmtTime(ts: string | undefined | null, fallback: string) {
  if (!ts) return fallback;
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return fallback;
  return d.toLocaleString();
}

export default function ObsidianPage() {
  const { ui } = useUITranslation();

  const [status, setStatus] = React.useState<ObsidianStatus | null>(null);
  const [vault, setVault] = React.useState("");
  const [scope, setScope] = React.useState("global");
  const [limit, setLimit] = React.useState("0");
  const [syncing, setSyncing] = React.useState(false);
  const [result, setResult] = React.useState<ObsidianSyncResult | null>(null);

  const loadStatus = React.useCallback(async () => {
    try {
      const s = await api.obsidianStatus();
      setStatus(s);
      if (s.vault && !vault) setVault(s.vault);
    } catch {
      // keep last known
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  React.useEffect(() => {
    void loadStatus();
  }, [loadStatus]);

  const sync = async () => {
    if (!vault.trim()) {
      toast.error(ui("obsidian.vaultRequired"));
      return;
    }
    setSyncing(true);
    try {
      const r = await api.obsidianSync({
        vault: vault.trim(),
        scope,
        limit: Number(limit) || 0,
      });
      setResult(r.result);
      toast.success(ui("obsidian.synced"));
      await loadStatus();
    } catch (e) {
      toast.error(`${ui("obsidian.syncFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSyncing(false);
    }
  };

  const tiles: { key: string; label: string; value: string | number; icon: React.ReactNode }[] = [
    { key: "scanned", label: ui("obsidian.scanned"), value: result?.scanned ?? 0, icon: <FileTextIcon className="size-4" /> },
    { key: "imported", label: ui("obsidian.imported"), value: result?.imported ?? 0, icon: <CheckCircle2Icon className="size-4" /> },
    { key: "updated", label: ui("obsidian.updated"), value: result?.updated ?? 0, icon: <RefreshCwIcon className="size-4" /> },
    { key: "skipped", label: ui("obsidian.skipped"), value: result?.skipped ?? 0, icon: <FolderSyncIcon className="size-4" /> },
    { key: "failed", label: ui("obsidian.failed"), value: result?.failed ?? 0, icon: <InfoIcon className="size-4" /> },
  ];

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{ui("obsidian.title")}</h1>
          <p className="text-muted-foreground text-sm">{ui("obsidian.description")}</p>
        </div>
        <Badge variant={status?.vault_set ? "default" : "outline"} className="shrink-0">
          {status?.vault_set ? status.vault : ui("obsidian.vaultNotSet")}
        </Badge>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card className="gap-2">
          <CardContent className="flex items-center gap-3 pt-4">
            <BookOpenIcon className="text-muted-foreground size-5" />
            <div>
              <div className="text-muted-foreground text-xs">{ui("obsidian.notesTracked")}</div>
              <div className="text-xl font-semibold tabular-nums">{status?.notes ?? 0}</div>
            </div>
          </CardContent>
        </Card>
        <Card className="gap-2">
          <CardContent className="flex items-center gap-3 pt-4">
            <CheckCircle2Icon className="text-muted-foreground size-5" />
            <div>
              <div className="text-muted-foreground text-xs">{ui("obsidian.notesImported")}</div>
              <div className="text-xl font-semibold tabular-nums">{status?.imported ?? 0}</div>
            </div>
          </CardContent>
        </Card>
        <Card className="gap-2">
          <CardContent className="flex items-center gap-3 pt-4">
            <FolderSyncIcon className="text-muted-foreground size-5" />
            <div>
              <div className="text-muted-foreground text-xs">{ui("obsidian.lastSync")}</div>
              <div className="text-sm font-medium">{fmtTime(status?.last_sync, ui("obsidian.never"))}</div>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardContent className="grid gap-4 pt-4 sm:grid-cols-2">
          <div className="flex flex-col gap-1.5 sm:col-span-2">
            <Label htmlFor="vault-path">{ui("obsidian.vault")}</Label>
            <Input
              id="vault-path"
              value={vault}
              onChange={(e) => setVault(e.target.value)}
              placeholder={ui("obsidian.vaultPlaceholder")}
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="vault-scope">{ui("obsidian.scope")}</Label>
            <NativeSelect id="vault-scope" value={scope} onChange={(e) => setScope(e.target.value)}>
              <NativeSelectOption value="global">{ui("memory.scope.global")}</NativeSelectOption>
              <NativeSelectOption value="company">{ui("memory.scope.company")}</NativeSelectOption>
              <NativeSelectOption value="task">{ui("memory.scope.task")}</NativeSelectOption>
            </NativeSelect>
          </div>
          <div className="flex flex-col gap-1.5">
            <Label htmlFor="vault-limit">{ui("obsidian.limit")}</Label>
            <Input id="vault-limit" value={limit} onChange={(e) => setLimit(e.target.value)} inputMode="numeric" />
            <p className="text-muted-foreground text-xs">{ui("obsidian.limitHelp")}</p>
          </div>
          <div className="sm:col-span-2">
            <Button onClick={() => void sync()} disabled={syncing}>
              <FolderSyncIcon className="size-4" />
              {syncing ? ui("obsidian.syncing") : ui("obsidian.sync")}
            </Button>
          </div>
        </CardContent>
      </Card>

      {result && (
        <div className="flex flex-col gap-3">
          <div className="text-sm font-medium">{ui("obsidian.result")}</div>
          <div className="grid gap-3 sm:grid-cols-5">
            {tiles.map((t) => (
              <Card key={t.key} className="gap-2">
                <CardContent className="pt-4">
                  <div className="text-muted-foreground flex items-center gap-1.5 text-xs">
                    {t.icon} {t.label}
                  </div>
                  <div className="text-xl font-semibold tabular-nums">{t.value}</div>
                </CardContent>
              </Card>
            ))}
          </div>
          {result.errors && result.errors.length > 0 && (
            <Card>
              <CardContent className="pt-4">
                <div className="mb-2 text-sm font-medium">{ui("obsidian.errors")}</div>
                <ul className="text-muted-foreground list-inside list-disc text-xs">
                  {result.errors.map((err, i) => <li key={i} className="truncate">{err}</li>)}
                </ul>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      <Card>
        <CardContent className="flex flex-col gap-2 pt-4 text-xs">
          <div className="flex items-center gap-2 font-medium">
            <InfoIcon className="size-4" /> {ui("obsidian.hintTitle")}
          </div>
          <div className="text-muted-foreground list-inside list-disc">
            <div>· {ui("obsidian.hint1")}</div>
            <div>· {ui("obsidian.hint2")}</div>
            <div>· {ui("obsidian.hint3")}</div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
