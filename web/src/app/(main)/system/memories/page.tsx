"use client";
import * as React from "react";

import {
  BrainIcon,
  DatabaseIcon,
  NetworkIcon,
  PlusIcon,
  RefreshCwIcon,
  SearchIcon,
  Trash2Icon,
  WaypointsIcon,
} from "lucide-react";
import { toast } from "sonner";

import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Sheet, SheetContent, SheetFooter, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { MemoryEntity, MemoryGraph, MemoryItem, MemoryStatItem } from "@/lib/types";

const SCOPES = ["global", "company", "task"] as const;
const KINDS = ["fact", "preference", "lesson", "note"] as const;

function scopeLabel(scope: string, ui: UITranslate) {
  return ui(`memory.scope.${scope}`) === `memory.scope.${scope}` ? scope : ui(`memory.scope.${scope}`);
}
function kindLabel(kind: string, ui: UITranslate) {
  return ui(`memory.kind.${kind}`) === `memory.kind.${kind}` ? kind : ui(`memory.kind.${kind}`);
}
function statusLabel(status: string, ui: UITranslate) {
  return ui(`memory.status.${status}`) === `memory.status.${status}` ? status : ui(`memory.status.${status}`);
}

function fmtTime(ts: string | undefined | null, ui: UITranslate) {
  if (!ts) return "—";
  const d = new Date(ts);
  if (Number.isNaN(d.getTime())) return "—";
  return d.toLocaleString(ui("screen.91610255157661"), {
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}

type FormState = {
  id: number | null;
  title: string;
  content: string;
  scope: string;
  kind: string;
  salience: number;
  companyId: string;
  taskId: string;
};
const emptyForm: FormState = {
  id: null,
  title: "",
  content: "",
  scope: "global",
  kind: "fact",
  salience: 0.6,
  companyId: "",
  taskId: "",
};

export default function MemoriesPage() {
  const { ui } = useUITranslation();

  const [memories, setMemories] = React.useState<MemoryItem[]>([]);
  const [total, setTotal] = React.useState(0);
  const [stats, setStats] = React.useState<MemoryStatItem[]>([]);
  const [enabled, setEnabled] = React.useState(true);
  const [autoExtract, setAutoExtract] = React.useState(true);
  const [loading, setLoading] = React.useState(false);
  const [enabling, setEnabling] = React.useState(false);
  const [autoSaving, setAutoSaving] = React.useState(false);
  const [clearing, setClearing] = React.useState(false);
  const [clearOpen, setClearOpen] = React.useState(false);

  const [q, setQ] = React.useState("");
  const [scope, setScope] = React.useState("");
  const [kind, setKind] = React.useState("");
  const [status, setStatus] = React.useState("");
  const [entity, setEntity] = React.useState("");

  const [entities, setEntities] = React.useState<MemoryEntity[]>([]);
  const [graph, setGraph] = React.useState<MemoryGraph | null>(null);

  const [recallQuery, setRecallQuery] = React.useState("");
  const [recallEntity, setRecallEntity] = React.useState("");
  const [recallTask, setRecallTask] = React.useState("");
  const [recallExpired, setRecallExpired] = React.useState(false);
  const [recallResult, setRecallResult] = React.useState<MemoryItem[] | null>(null);
  const [recalling, setRecalling] = React.useState(false);

  const [sheetOpen, setSheetOpen] = React.useState(false);
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [saving, setSaving] = React.useState(false);
  const [deleting, setDeleting] = React.useState<MemoryItem | null>(null);

  const loadStats = React.useCallback(async () => {
    try {
      const r = await api.memoryStats();
      setStats(r.stats ?? []);
      setTotal(r.total ?? 0);
      setEnabled(r.enabled !== false);
    } catch {
      // keep last known values on transient failure
    }
  }, []);

  const loadEntities = React.useCallback(async () => {
    try {
      const r = await api.memoryEntities();
      setEntities(r.entities ?? []);
    } catch {
      setEntities([]);
    }
  }, []);

  const loadMemories = React.useCallback(async () => {
    setLoading(true);
    try {
      const r = await api.memories({
        q: q || undefined,
        scope: scope || undefined,
        kind: kind || undefined,
        status: status || undefined,
        entity: entity || undefined,
        limit: 200,
      });
      setMemories(r.memories ?? []);
      setTotal(r.total ?? 0);
    } catch {
      setMemories([]);
    } finally {
      setLoading(false);
    }
  }, [q, scope, kind, status, entity]);

  React.useEffect(() => {
    void loadStats();
    void loadEntities();
    void loadMemories();
    void api
      .settings()
      .then((s) => {
        if (typeof s.memory_auto_extract === "boolean") setAutoExtract(s.memory_auto_extract);
        if (typeof s.memory_enabled === "boolean") setEnabled(s.memory_enabled);
      })
      .catch(() => {});
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const toggleEnabled = async (v: boolean) => {
    setEnabling(true);
    try {
      await api.setSettings({ memory_enabled: v });
      setEnabled(v);
      toast.success(v ? ui("memory.enabledOn") : ui("memory.enabledOff"));
    } catch (e) {
      toast.error(`${ui("memory.saveFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setEnabling(false);
    }
  };

  const toggleAutoExtract = async (v: boolean) => {
    setAutoSaving(true);
    try {
      await api.setSettings({ memory_auto_extract: v });
      setAutoExtract(v);
      toast.success(v ? ui("memory.enabledOn") : ui("memory.enabledOff"));
    } catch (e) {
      toast.error(`${ui("memory.saveFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setAutoSaving(false);
    }
  };

  const clearAll = async () => {
    setClearing(true);
    try {
      const r = await api.clearAllMemories();
      const n = r.deleted?.memories ?? 0;
      toast.success(`${ui("memory.cleared")} (${n})`);
      setClearOpen(false);
      await Promise.all([loadMemories(), loadStats(), loadEntities()]);
      setRecallResult(null);
      setGraph(null);
    } catch (e) {
      toast.error(`${ui("memory.clearFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setClearing(false);
    }
  };

  const openNew = () => {
    setForm({ ...emptyForm });
    setSheetOpen(true);
  };
  const openEdit = (m: MemoryItem) => {
    setForm({
      id: m.id,
      title: m.title,
      content: m.content,
      scope: m.scope,
      kind: m.kind,
      salience: m.salience,
      companyId: m.company_id ? String(m.company_id) : "",
      taskId: m.task_id ? String(m.task_id) : "",
    });
    setSheetOpen(true);
  };
  const save = async () => {
    if (!form.title.trim() || !form.content.trim()) {
      toast.error(ui("memory.required"));
      return;
    }
    setSaving(true);
    try {
      const payload = {
        scope: form.scope,
        kind: form.kind,
        title: form.title.trim(),
        content: form.content.trim(),
        salience: form.salience,
        company_id: form.companyId ? Number(form.companyId) : 0,
        task_id: form.taskId ? Number(form.taskId) : 0,
      };
      if (form.id) {
        await api.updateMemory(form.id, {
          title: payload.title,
          kind: payload.kind,
          content: payload.content,
          salience: payload.salience,
        });
        toast.success(ui("memory.updated"));
      } else {
        await api.createMemory(payload);
        toast.success(ui("memory.created"));
      }
      setSheetOpen(false);
      await Promise.all([loadMemories(), loadStats(), loadEntities()]);
    } catch (e) {
      toast.error(`${ui("memory.saveFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setSaving(false);
    }
  };
  const remove = async () => {
    if (!deleting) return;
    try {
      await api.deleteMemory(deleting.id);
      toast.success(ui("memory.deleted"));
      setDeleting(null);
      await Promise.all([loadMemories(), loadStats(), loadEntities()]);
    } catch (e) {
      toast.error(`${ui("memory.deleteFailed")}: ${e instanceof Error ? e.message : String(e)}`);
    }
  };

  const runRecall = async () => {
    if (!recallQuery.trim() && !recallEntity.trim()) {
      toast.error(ui("memory.needQuery"));
      return;
    }
    setRecalling(true);
    try {
      const r = await api.recallMemories({
        query: recallQuery.trim() || undefined,
        entity: recallEntity.trim() || undefined,
        task_id: recallTask ? Number(recallTask) : undefined,
        include_expired: recallExpired,
      });
      setRecallResult(r.memories ?? []);
      void loadStats();
    } catch (e) {
      toast.error(`${ui("memory.recallRunning")} ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setRecalling(false);
    }
  };

  const openGraph = async (m: MemoryItem) => {
    try {
      const g = await api.memoryGraph(m.id);
      setGraph(g);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const renderTable = (items: MemoryItem[], withScore = false) => (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>{ui("memory.col.title")}</TableHead>
          <TableHead>{ui("memory.col.scope")}</TableHead>
          <TableHead>{ui("memory.col.kind")}</TableHead>
          <TableHead>{ui("memory.col.salience")}</TableHead>
          <TableHead>{ui("memory.col.hits")}</TableHead>
          {withScore && <TableHead>{ui("memory.recallScore")}</TableHead>}
          <TableHead>{ui("memory.col.updated")}</TableHead>
          <TableHead className="text-right">{ui("memory.col.actions")}</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        {items.map((m) => (
          <TableRow key={m.id}>
            <TableCell className="max-w-[320px]">
              <div className="truncate font-medium">{m.title}</div>
              <div className="text-muted-foreground truncate text-xs">{m.content}</div>
            </TableCell>
            <TableCell>
              <Badge variant="outline">{scopeLabel(m.scope, ui)}</Badge>
            </TableCell>
            <TableCell>
              <Badge variant="secondary">{kindLabel(m.kind, ui)}</Badge>
            </TableCell>
            <TableCell className="tabular-nums">{m.salience.toFixed(2)}</TableCell>
            <TableCell className="tabular-nums">{m.hit_count}</TableCell>
            {withScore && <TableCell className="tabular-nums font-medium">{m.score?.toFixed(3) ?? "—"}</TableCell>}
            <TableCell className="text-muted-foreground text-xs">{fmtTime(m.updated_at, ui)}</TableCell>
            <TableCell className="text-right">
              {withScore ? (
                <Button variant="ghost" size="icon" onClick={() => openGraph(m)} aria-label={ui("memory.preview")}>
                  <WaypointsIcon className="size-4" />
                </Button>
              ) : (
                <div className="flex justify-end gap-1">
                  <Button variant="ghost" size="icon" onClick={() => openGraph(m)} aria-label={ui("memory.preview")}>
                    <NetworkIcon className="size-4" />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => openEdit(m)} aria-label={ui("memory.edit")}>
                    <RefreshCwIcon className="size-4" />
                  </Button>
                  <Button variant="ghost" size="icon" onClick={() => setDeleting(m)} aria-label={ui("memory.delete")}>
                    <Trash2Icon className="size-4 text-destructive" />
                  </Button>
                </div>
              )}
            </TableCell>
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold tracking-tight">{ui("memory.title")}</h1>
          <p className="text-muted-foreground text-sm">{ui("memory.description")}</p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground" title={ui("memory.autoExtractHelp")}>
              {ui("memory.autoExtract")}
            </span>
            <Switch
              checked={autoExtract}
              disabled={autoSaving}
              onCheckedChange={toggleAutoExtract}
              aria-label={ui("memory.autoExtract")}
            />
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground">{ui("memory.enabled")}</span>
            <Switch
              checked={enabled}
              disabled={enabling}
              onCheckedChange={toggleEnabled}
              aria-label={ui("memory.enabled")}
            />
            <Button variant="destructive" size="sm" onClick={() => setClearOpen(true)}>
              <Trash2Icon className="size-4" />
              {ui("memory.clearAll")}
            </Button>
          </div>
        </div>
      </div>

      <div className="grid gap-3 sm:grid-cols-3">
        <Card className="gap-2">
          <CardContent className="flex items-center gap-3 pt-4">
            <DatabaseIcon className="text-muted-foreground size-5" />
            <div>
              <div className="text-muted-foreground text-xs">{ui("memory.total")}</div>
              <div className="text-xl font-semibold tabular-nums">{total}</div>
            </div>
          </CardContent>
        </Card>
        <Card className="gap-2">
          <CardContent className="pt-4">
            <div className="text-muted-foreground mb-1 text-xs">{ui("memory.byScope")}</div>
            <div className="flex flex-wrap gap-1.5">
              {SCOPES.map((s) => {
                const c = stats.filter((x) => x.scope === s).reduce((a, b) => a + b.count, 0);
                return (
                  <Badge key={s} variant="outline">
                    {scopeLabel(s, ui)} {c}
                  </Badge>
                );
              })}
            </div>
          </CardContent>
        </Card>
        <Card className="gap-2">
          <CardContent className="pt-4">
            <div className="text-muted-foreground mb-1 text-xs">{ui("memory.byKind")}</div>
            <div className="flex flex-wrap gap-1.5">
              {KINDS.map((k) => {
                const c = stats.filter((x) => x.kind === k).reduce((a, b) => a + b.count, 0);
                return (
                  <Badge key={k} variant="secondary">
                    {kindLabel(k, ui)} {c}
                  </Badge>
                );
              })}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="list">
        <TabsList>
          <TabsTrigger value="list">{ui("memory.list")}</TabsTrigger>
          <TabsTrigger value="recall">{ui("memory.recall")}</TabsTrigger>
          <TabsTrigger value="entities">{ui("memory.entities")}</TabsTrigger>
        </TabsList>

        <TabsContent value="list" className="flex flex-col gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <div className="relative min-w-[200px] flex-1">
              <SearchIcon className="text-muted-foreground absolute left-2.5 top-2.5 size-4" />
              <Input
                className="pl-8"
                value={q}
                onChange={(e) => setQ(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") void loadMemories();
                }}
                placeholder={ui("memory.searchPlaceholder")}
              />
            </div>
            <NativeSelect
              value={scope}
              onChange={(e) => setScope(e.target.value)}
              aria-label={ui("memory.filterScope")}
            >
              <NativeSelectOption value="">
                {ui("memory.all")} · {ui("memory.filterScope")}
              </NativeSelectOption>
              {SCOPES.map((s) => (
                <NativeSelectOption key={s} value={s}>
                  {scopeLabel(s, ui)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <NativeSelect value={kind} onChange={(e) => setKind(e.target.value)} aria-label={ui("memory.filterKind")}>
              <NativeSelectOption value="">
                {ui("memory.all")} · {ui("memory.filterKind")}
              </NativeSelectOption>
              {KINDS.map((k) => (
                <NativeSelectOption key={k} value={k}>
                  {kindLabel(k, ui)}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <NativeSelect
              value={status}
              onChange={(e) => setStatus(e.target.value)}
              aria-label={ui("memory.filterStatus")}
            >
              <NativeSelectOption value="">
                {ui("memory.all")} · {ui("memory.filterStatus")}
              </NativeSelectOption>
              <NativeSelectOption value="active">{ui("memory.status.active")}</NativeSelectOption>
              <NativeSelectOption value="archived">{ui("memory.status.archived")}</NativeSelectOption>
            </NativeSelect>
            <NativeSelect
              value={entity}
              onChange={(e) => setEntity(e.target.value)}
              aria-label={ui("memory.filterEntity")}
            >
              <NativeSelectOption value="">
                {ui("memory.all")} · {ui("memory.filterEntity")}
              </NativeSelectOption>
              {entities.map((en) => (
                <NativeSelectOption key={en.id} value={en.name}>
                  {en.name}
                </NativeSelectOption>
              ))}
            </NativeSelect>
            <Button variant="outline" size="sm" onClick={() => void loadMemories()} disabled={loading}>
              <RefreshCwIcon className={`size-4 ${loading ? "animate-spin" : ""}`} />
              {ui("memory.refresh")}
            </Button>
            <Button size="sm" onClick={openNew}>
              <PlusIcon className="size-4" />
              {ui("memory.new")}
            </Button>
          </div>
          <div className="rounded-md border">
            {memories.length === 0 && !loading ? (
              <div className="text-muted-foreground p-8 text-center text-sm">{ui("memory.empty")}</div>
            ) : (
              renderTable(memories)
            )}
          </div>
        </TabsContent>

        <TabsContent value="recall" className="flex flex-col gap-3">
          <Card>
            <CardContent className="grid gap-3 pt-4 sm:grid-cols-2">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="recall-q">{ui("memory.recallQuery")}</Label>
                <Input
                  id="recall-q"
                  value={recallQuery}
                  onChange={(e) => setRecallQuery(e.target.value)}
                  placeholder={ui("memory.recallQueryPlaceholder")}
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="recall-entity">{ui("memory.recallEntity")}</Label>
                <Input id="recall-entity" value={recallEntity} onChange={(e) => setRecallEntity(e.target.value)} />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="recall-task">{ui("memory.recallTaskId")}</Label>
                <Input
                  id="recall-task"
                  value={recallTask}
                  onChange={(e) => setRecallTask(e.target.value)}
                  inputMode="numeric"
                />
              </div>
              <div className="flex items-end gap-3 pb-1">
                <div className="flex items-center gap-2 text-sm">
                  <Switch
                    checked={recallExpired}
                    onCheckedChange={setRecallExpired}
                    aria-label={ui("memory.recallIncludeExpired")}
                  />
                  <span>{ui("memory.recallIncludeExpired")}</span>
                </div>
                <Button onClick={() => void runRecall()} disabled={recalling}>
                  <SearchIcon className="size-4" />
                  {recalling ? ui("memory.recallRunning") : ui("memory.recallRun")}
                </Button>
              </div>
            </CardContent>
          </Card>
          <p className="text-muted-foreground text-xs">{ui("memory.recallHint")}</p>
          {recallResult !== null && (
            <div className="rounded-md border">
              <div className="text-muted-foreground border-b px-3 py-2 text-xs">
                {ui("memory.recallResults")} · {recallResult.length}
              </div>
              {recallResult.length === 0 ? (
                <div className="text-muted-foreground p-8 text-center text-sm">{ui("memory.recallNone")}</div>
              ) : (
                renderTable(recallResult, true)
              )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="entities" className="flex flex-col gap-3">
          <p className="text-muted-foreground text-xs">{ui("memory.entitiesHint")}</p>
          <div className="rounded-md border">
            {entities.length === 0 ? (
              <div className="text-muted-foreground p-8 text-center text-sm">{ui("memory.entityEmpty")}</div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{ui("memory.entityName")}</TableHead>
                    <TableHead>{ui("memory.entityKind")}</TableHead>
                    <TableHead>{ui("memory.entityRefs")}</TableHead>
                    <TableHead>{ui("memory.entityLast")}</TableHead>
                    <TableHead className="text-right">{ui("memory.col.actions")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {entities.map((en) => (
                    <TableRow key={en.id}>
                      <TableCell className="font-medium">{en.name}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{en.kind}</Badge>
                      </TableCell>
                      <TableCell className="tabular-nums">{en.ref_count}</TableCell>
                      <TableCell className="text-muted-foreground text-xs">{fmtTime(en.last_seen, ui)}</TableCell>
                      <TableCell className="text-right">
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => {
                            setEntity(en.name);
                          }}
                        >
                          {ui("memory.filterEntity")}
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </div>
        </TabsContent>
      </Tabs>

      <Sheet open={sheetOpen} onOpenChange={setSheetOpen}>
        <SheetContent>
          <SheetHeader>
            <SheetTitle>{form.id ? ui("memory.sheet.edit") : ui("memory.sheet.new")}</SheetTitle>
          </SheetHeader>
          <div className="grid gap-4 px-4 py-2">
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-title">{ui("memory.form.title")}</Label>
              <Input
                id="m-title"
                value={form.title}
                onChange={(e) => setForm({ ...form, title: e.target.value })}
                placeholder={ui("memory.form.titlePlaceholder")}
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-content">{ui("memory.form.content")}</Label>
              <Textarea
                id="m-content"
                rows={6}
                value={form.content}
                onChange={(e) => setForm({ ...form, content: e.target.value })}
                placeholder={ui("memory.form.contentPlaceholder")}
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="m-scope">{ui("memory.form.scope")}</Label>
                <NativeSelect
                  id="m-scope"
                  value={form.scope}
                  onChange={(e) => setForm({ ...form, scope: e.target.value })}
                >
                  {SCOPES.map((s) => (
                    <NativeSelectOption key={s} value={s}>
                      {scopeLabel(s, ui)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="m-kind">{ui("memory.form.kind")}</Label>
                <NativeSelect
                  id="m-kind"
                  value={form.kind}
                  onChange={(e) => setForm({ ...form, kind: e.target.value })}
                >
                  {KINDS.map((k) => (
                    <NativeSelectOption key={k} value={k}>
                      {kindLabel(k, ui)}
                    </NativeSelectOption>
                  ))}
                </NativeSelect>
              </div>
            </div>
            <div className="flex flex-col gap-1.5">
              <Label htmlFor="m-salience">{ui("memory.form.salience")}</Label>
              <Input
                id="m-salience"
                type="number"
                min={0}
                max={1}
                step={0.1}
                value={form.salience}
                onChange={(e) => setForm({ ...form, salience: Number(e.target.value) })}
              />
              <p className="text-muted-foreground text-xs">{ui("memory.form.salienceHelp")}</p>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="m-company">{ui("memory.form.companyId")}</Label>
                <Input
                  id="m-company"
                  value={form.companyId}
                  onChange={(e) => setForm({ ...form, companyId: e.target.value })}
                  inputMode="numeric"
                />
              </div>
              <div className="flex flex-col gap-1.5">
                <Label htmlFor="m-task">{ui("memory.form.taskId")}</Label>
                <Input
                  id="m-task"
                  value={form.taskId}
                  onChange={(e) => setForm({ ...form, taskId: e.target.value })}
                  inputMode="numeric"
                />
              </div>
            </div>
            <p className="text-muted-foreground text-xs">{ui("memory.form.scopeHelp")}</p>
          </div>
          <SheetFooter>
            <Button variant="outline" onClick={() => setSheetOpen(false)}>
              {ui("memory.cancel")}
            </Button>
            <Button onClick={() => void save()} disabled={saving}>
              {ui("memory.save")}
            </Button>
          </SheetFooter>
        </SheetContent>
      </Sheet>

      <AlertDialog open={clearOpen} onOpenChange={setClearOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{ui("memory.clearAll")}</AlertDialogTitle>
            <AlertDialogDescription>{ui("memory.clearAllConfirm")}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{ui("memory.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => void clearAll()} disabled={clearing}>
              {ui("memory.clearAll")}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!deleting}
        onOpenChange={(o) => {
          if (!o) setDeleting(null);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>{ui("memory.deleteConfirm")}</AlertDialogTitle>
            <AlertDialogDescription>{deleting?.title}</AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>{ui("memory.cancel")}</AlertDialogCancel>
            <AlertDialogAction onClick={() => void remove()}>{ui("memory.delete")}</AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <AlertDialog
        open={!!graph}
        onOpenChange={(o) => {
          if (!o) setGraph(null);
        }}
      >
        <AlertDialogContent className="max-h-[80vh] max-w-2xl overflow-y-auto">
          <AlertDialogHeader>
            <AlertDialogTitle>{ui("memory.graphTitle")}</AlertDialogTitle>
            <AlertDialogDescription>{graph?.memory?.title}</AlertDialogDescription>
          </AlertDialogHeader>
          <div className="grid gap-4 py-2">
            <div>
              <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                <BrainIcon className="size-4" /> {ui("memory.graphEntities")}
              </div>
              <div className="flex flex-wrap gap-1.5">
                {graph?.entities?.length ? (
                  graph.entities.map((en) => (
                    <Badge key={en.id} variant="outline">
                      {en.kind}: {en.name}
                    </Badge>
                  ))
                ) : (
                  <span className="text-muted-foreground text-sm">{ui("memory.graphNone")}</span>
                )}
              </div>
            </div>
            <div>
              <div className="mb-2 flex items-center gap-2 text-sm font-medium">
                <NetworkIcon className="size-4" /> {ui("memory.graphRelated")} · {graph?.related_count ?? 0}
              </div>
              <div className="flex flex-col gap-2">
                {graph?.related?.map((m) => (
                  <div key={m.id} className="rounded-md border px-3 py-2 text-sm">
                    <div className="font-medium">{m.title}</div>
                    <div className="text-muted-foreground truncate text-xs">{m.content}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
          <AlertDialogFooter>
            <AlertDialogCancel>{ui("memory.cancel")}</AlertDialogCancel>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </div>
  );
}
