"use client";
import * as React from "react";

import { LayoutTemplateIcon, PlugZapIcon, PlusIcon, RefreshCwIcon, ServerIcon, Trash2Icon } from "lucide-react";
import { toast } from "sonner";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Textarea } from "@/components/ui/textarea";
import { useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { Agent, MCPServer, MCPTemplate, MCPTool } from "@/lib/types";

type Transport = "stdio" | "http" | "sse";
type FormState = {
  name: string;
  transport: Transport;
  command: string;
  args: string;
  url: string;
  env: string;
  insecure: boolean;
};
const emptyForm: FormState = {
  name: "",
  transport: "stdio",
  command: "",
  args: "",
  url: "",
  env: "",
  insecure: false,
};

export default function MCPPage() {
  const { ui } = useUITranslation();

  const [servers, setServers] = React.useState<MCPServer[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [visibility, setVisibility] = React.useState<Record<number, string[]>>({});

  const [open, setOpen] = React.useState(false);
  const [editing, setEditing] = React.useState<MCPServer | null>(null); // null = add mode
  const [tab, setTab] = React.useState<"config" | "tools">("config");
  const [form, setForm] = React.useState<FormState>(emptyForm);
  const [saving, setSaving] = React.useState(false);
  const [tools, setTools] = React.useState<MCPTool[]>([]);
  const [toolsLoading, setToolsLoading] = React.useState(false);
  const [refreshing, setRefreshing] = React.useState(false);

  // 模板库与连接测试
  const [templates, setTemplates] = React.useState<MCPTemplate[]>([]);
  const [tplOpen, setTplOpen] = React.useState(false);
  const [testing, setTesting] = React.useState(false);

  const load = React.useCallback(() => {
    api
      .agents()
      .then(setAgents)
      .catch(() => {});
    api
      .mcpServers()
      .then((ss) => {
        setServers(ss);
        ss.forEach((s) =>
          api
            .resourceVisibility("mcp", s.id)
            .then((ids) => setVisibility((v) => ({ ...v, [s.id]: ids })))
            .catch(() => {}),
        );
      })
      .catch(() => {});
  }, []);
  React.useEffect(() => {
    load();
    api
      .mcpTemplates()
      .then(setTemplates)
      .catch(() => undefined);
  }, [load]);

  function setF(patch: Partial<FormState>) {
    setForm((f) => ({ ...f, ...patch }));
  }

  function parseEnv(text: string): Record<string, string> {
    const out: Record<string, string> = {};
    for (const line of text.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const idx = trimmed.indexOf("=");
      if (idx > 0) {
        const key = trimmed.slice(0, idx).trim();
        if (key) out[key] = trimmed.slice(idx + 1).trim();
      }
    }
    return out;
  }
  function envToText(env: Record<string, string> | undefined): string {
    return Object.entries(env ?? {})
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");
  }

  function openAdd() {
    setEditing(null);
    setForm(emptyForm);
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  // 从模板预填表单：模板值落进现有 FormState，用户可改后再保存。
  // env Map → "K=V" 行文本，args 数组 → 空格连接（args 里不会出现带空格的项，
  // 官方模板均为独立 token；带空格的允许目录请保存后手动补引号场景极少）。
  function openFromTemplate(t: MCPTemplate) {
    setTplOpen(false);
    setEditing(null);
    setForm({
      name: t.name,
      transport: t.transport,
      command: t.command ?? "",
      args: (t.args ?? []).join(" "),
      url: t.url ?? "",
      env: envToText(t.env),
      insecure: t.insecure ?? false,
    });
    setTools([]);
    setTab("config");
    setOpen(true);
  }

  function openEdit(s: MCPServer) {
    setEditing(s);
    setForm({
      name: s.name,
      transport: s.transport,
      command: s.command ?? "",
      args: s.args.join(" "),
      url: s.url ?? "",
      env: envToText(s.env),
      insecure: s.insecure ?? false,
    });
    setTab("config");
    setOpen(true);
    void loadTools(s.id);
  }

  async function loadTools(id: number) {
    setToolsLoading(true);
    try {
      setTools(await api.mcpTools(id));
    } catch {
      setTools([]);
    } finally {
      setToolsLoading(false);
    }
  }

  // 表单 → 保存/测试共用的 payload。返回 null 表示校验未过。
  function buildPayload(): Partial<MCPServer> | null {
    if (!form.name.trim()) {
      toast.error(ui("screen.fbc79033bfa23d"));
      return null;
    }
    if (form.transport === "stdio" && !form.command.trim()) {
      toast.error(ui("screen.6e9a1a549d159a"));
      return null;
    }
    if (form.transport !== "stdio" && !form.url.trim()) {
      toast.error(ui("screen.fb19ca44a607a5"));
      return null;
    }
    if (form.transport !== "stdio") {
      return {
        name: form.name.trim(),
        transport: form.transport,
        url: form.url.trim(),
        command: "",
        args: [] as string[],
        env: parseEnv(form.env), // 远程模式下 env 即请求头
        insecure: form.insecure,
      };
    }
    return {
      name: form.name.trim(),
      transport: "stdio" as const,
      command: form.command.trim(),
      args: form.args.trim() ? form.args.trim().split(/\s+/) : [],
      env: parseEnv(form.env),
      insecure: false,
    };
  }

  async function saveForm() {
    const payload = buildPayload();
    if (!payload) return;
    setSaving(true);
    try {
      await api.saveMcpServer({
        ...(editing ? { id: editing.id } : {}),
        enabled: editing ? editing.enabled : true,
        ...payload,
      });
      toast.success(editing ? ui("screen.1bd91a7d0c53c9") : ui("screen.53b36687882f85"));
      if (!editing) setOpen(false);
      load();
    } catch (e) {
      toast.error(ui("screen.6ade7baf8737c0") + (e as Error).message);
    } finally {
      setSaving(false);
    }
  }

  // 起临时连接测当前表单配置，不落库。stdio 模板首次跑 npx 要拉包，可能要等一会。
  async function testConnection() {
    const payload = buildPayload();
    if (!payload) return;
    setTesting(true);
    try {
      const r = await api.testMcpServer(payload);
      if (r.ok) {
        toast.success(ui("screen.12d9a48a454087", { v0: r.tools?.length ?? 0 }));
        const names = (r.tools ?? [])
          .slice(0, 6)
          .map((t) => t.name)
          .join(", ");
        if (names) toast.message(names + ((r.tools?.length ?? 0) > 6 ? " …" : ""));
      } else {
        toast.error(ui("screen.9a6b8ca1d52324") + (r.error ?? "unknown"));
      }
    } catch (e) {
      toast.error(ui("screen.9a6b8ca1d52324") + (e as Error).message);
    } finally {
      setTesting(false);
    }
  }

  async function refreshTools() {
    if (!editing) return;
    setRefreshing(true);
    try {
      const t = await api.refreshMcpServer(editing.id);
      setTools(t);
      toast.success(ui("screen.536acc520167f3", { v0: t.length }));
      load();
    } catch (e) {
      toast.error(ui("screen.0c57a1d38e6afa") + (e as Error).message);
    } finally {
      setRefreshing(false);
    }
  }

  async function removeServer(s: MCPServer) {
    try {
      await api.deleteMcpServer(s.id);
      toast.success(ui("screen.e196bc4beeeaad", { v0: s.name }));
      setOpen(false);
      load();
    } catch (e) {
      toast.error(ui("screen.0580fcee37e020") + (e as Error).message);
    }
  }

  async function toggleEnabled(s: MCPServer) {
    try {
      await api.saveMcpServer({ ...s, enabled: !s.enabled });
      load();
    } catch (e) {
      toast.error(ui("screen.37cdfdb143a7a8") + (e as Error).message);
    }
  }

  async function toggleVisibility(serverId: number, agentId: string, agentName: string) {
    const on = (visibility[serverId] ?? []).includes(agentId);
    try {
      await api.toggleVisibility(agentId, "mcp", serverId, !on);
      toast.success(
        ui("screen.3c3fed693f6db5", {
          v0: on ? ui("screen.2cd0f3be8738a8") : ui("screen.2e87bd556c124f"),
          v1: agentName,
        }),
      );
      load();
    } catch (e) {
      toast.error(ui("screen.37cdfdb143a7a8") + (e as Error).message);
    }
  }

  function renderForm() {
    return (
      <div className="grid gap-4 py-4">
        <div className="grid gap-2">
          <Label>{ui("screen.84dada05d8d523")}</Label>
          <div className="flex gap-2">
            <Button
              type="button"
              variant={form.transport === "stdio" ? "default" : "outline"}
              onClick={() => setF({ transport: "stdio" })}
            >
              {ui("screen.45b3199c421835")}
            </Button>
            <Button
              type="button"
              variant={form.transport === "http" ? "default" : "outline"}
              onClick={() => setF({ transport: "http" })}
            >
              {ui("screen.3bdf0ff38a5f12")}
            </Button>
            <Button
              type="button"
              variant={form.transport === "sse" ? "default" : "outline"}
              onClick={() => setF({ transport: "sse" })}
            >
              {ui("screen.f70349dee545aa")}
            </Button>
          </div>
        </div>
        <div className="grid gap-2">
          <Label htmlFor="m-name">{ui("screen.d44e9b3d3b31d3")}</Label>
          <Input
            id="m-name"
            placeholder="filesystem"
            value={form.name}
            onChange={(e) => setF({ name: e.target.value })}
          />
        </div>
        {form.transport === "stdio" ? (
          <>
            <div className="grid gap-2">
              <Label htmlFor="m-cmd">{ui("screen.928f87d4507bf9")}</Label>
              <Input
                id="m-cmd"
                className="font-mono"
                placeholder="npx"
                value={form.command}
                onChange={(e) => setF({ command: e.target.value })}
              />
            </div>
            <div className="grid gap-2">
              <Label htmlFor="m-args">{ui("screen.f99517115abfc7")}</Label>
              <Input
                id="m-args"
                className="font-mono"
                placeholder="-y @modelcontextprotocol/server-filesystem /data"
                value={form.args}
                onChange={(e) => setF({ args: e.target.value })}
              />
            </div>
          </>
        ) : (
          <div className="grid gap-2">
            <Label htmlFor="m-url">{ui("screen.63340f3743eeeb")}</Label>
            <Input
              id="m-url"
              className="font-mono"
              placeholder="https://mcp.example.com/mcp"
              value={form.url}
              onChange={(e) => setF({ url: e.target.value })}
            />
            <label className="flex items-center gap-2 text-sm">
              <Checkbox checked={form.insecure} onCheckedChange={(v) => setF({ insecure: v === true })} />
              {ui("screen.5938afb19912b5")}
            </label>
          </div>
        )}
        <div className="grid gap-2">
          <Label htmlFor="m-env">
            {form.transport !== "stdio" ? ui("screen.1b79247a56f3a5") : ui("screen.4c47bd79cb47ae")}
          </Label>
          <Textarea
            id="m-env"
            className="font-mono"
            placeholder={form.transport !== "stdio" ? "Authorization=Bearer xxxx" : "API_KEY=xxxx\nFOO=bar"}
            value={form.env}
            onChange={(e) => setF({ env: e.target.value })}
          />
        </div>
      </div>
    );
  }

  function renderTools() {
    return (
      <div className="flex flex-col gap-3 py-4">
        <div className="flex items-center justify-between">
          <span className="text-muted-foreground text-sm">
            {tools.length} {ui("screen.e43b2a10830f3e")}
          </span>
          <Button size="sm" variant="outline" disabled={refreshing} onClick={refreshTools}>
            <RefreshCwIcon className={refreshing ? "animate-spin" : ""} /> {ui("screen.aee88743413144")}
          </Button>
        </div>
        {toolsLoading ? (
          <p className="text-muted-foreground text-sm">{ui("screen.4927a53bcc886a")}</p>
        ) : tools.length === 0 ? (
          <p className="text-muted-foreground text-sm">{ui("screen.f8ed21a54f39ec")}</p>
        ) : (
          <div className="flex flex-col divide-y">
            {tools.map((t) => (
              <div key={t.name} className="py-2.5">
                <code className="font-mono text-sm">{t.name}</code>
                {t.description && (
                  <p className="mt-0.5 text-muted-foreground text-xs leading-relaxed">{t.description}</p>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-1 flex-col gap-4 md:gap-6">
      <div>
        <h1 className="font-semibold text-xl tracking-tight">MCP</h1>
        <p className="text-muted-foreground text-sm">{ui("screen.87d38b3a8308a7")}</p>
      </div>

      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <button
          type="button"
          onClick={openAdd}
          className="flex min-h-[116px] flex-col items-center justify-center gap-2 rounded-xl border border-foreground/70 border-dashed text-foreground/70 transition hover:bg-muted/60 hover:shadow-sm"
        >
          <PlusIcon className="size-6" />
          <span className="text-sm">{ui("screen.c7121fa89693b0")}</span>
        </button>
        <button
          type="button"
          onClick={() => setTplOpen(true)}
          className="flex min-h-[116px] flex-col items-center justify-center gap-2 rounded-xl border border-primary/50 border-dashed text-foreground/70 transition hover:bg-muted/60 hover:shadow-sm"
        >
          <LayoutTemplateIcon className="size-6 text-primary" />
          <span className="text-sm">{ui("screen.ac28be12c3918b")}</span>
        </button>

        {servers.map((s) => (
          <Card
            key={s.id}
            onClick={() => openEdit(s)}
            className="cursor-pointer gap-3 transition hover:border-primary/60 hover:shadow-sm"
          >
            <CardHeader>
              <div className="flex items-center gap-2">
                <ServerIcon className="size-4 shrink-0 text-muted-foreground" />
                <CardTitle className="truncate text-base">{s.name}</CardTitle>
                <Badge variant="outline" className="uppercase">
                  {s.transport}
                </Badge>
                <div className="ml-auto flex items-center gap-2" onClick={(e) => e.stopPropagation()}>
                  <Switch
                    checked={s.enabled}
                    onCheckedChange={() => toggleEnabled(s)}
                    aria-label={ui("screen.f4f0ead1116b5b")}
                  />
                  <Button
                    size="icon"
                    variant="outline"
                    aria-label={ui("screen.2f9daa828907b9")}
                    onClick={() => removeServer(s)}
                  >
                    <Trash2Icon className="text-destructive" />
                  </Button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="grid gap-3">
              <p className="text-muted-foreground text-sm">
                {s.tools && s.tools.length > 0
                  ? ui("screen.0092721f98c2ec", { v0: s.tools.length })
                  : ui("screen.46c990b44f62f8")}
              </p>
              <div className="grid gap-2" onClick={(e) => e.stopPropagation()}>
                <span className="text-muted-foreground text-xs">{ui("screen.6d6c9bd4c4498a")}</span>
                <div className="flex flex-wrap gap-x-4 gap-y-2">
                  {agents.map((a) => (
                    <label key={a.key} className="flex items-center gap-2 text-sm">
                      <Checkbox
                        checked={(visibility[s.id] ?? []).includes(a.id)}
                        onCheckedChange={() => toggleVisibility(s.id, a.id, a.name)}
                      />
                      {a.name}
                    </label>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>
        ))}
      </div>

      <Sheet open={open} onOpenChange={setOpen}>
        <SheetContent side="right" className="w-full data-[side=right]:sm:max-w-lg">
          <SheetHeader>
            <SheetTitle>{editing ? editing.name : ui("screen.c52661984f930a")}</SheetTitle>
            <SheetDescription>{ui("screen.797024aa7a9b52")}</SheetDescription>
          </SheetHeader>

          {editing ? (
            <Tabs
              value={tab}
              onValueChange={(v) => setTab(v as "config" | "tools")}
              className="flex min-h-0 flex-1 flex-col px-4"
            >
              <TabsList>
                <TabsTrigger value="config">{ui("screen.148d195e21b05d")}</TabsTrigger>
                <TabsTrigger value="tools">
                  {ui("screen.415dd9f106a567")}
                  {tools.length ? `（${tools.length}）` : ""}
                </TabsTrigger>
              </TabsList>
              <TabsContent value="config" className="min-h-0 flex-1 overflow-y-auto">
                {renderForm()}
                <div className="flex gap-2 pt-2 pb-6">
                  <Button onClick={saveForm} disabled={saving}>
                    {ui("screen.a3030bf8f16dc6")}
                  </Button>
                  <Button variant="outline" disabled={testing} onClick={() => void testConnection()}>
                    <PlugZapIcon className={testing ? "animate-pulse" : ""} /> {ui("screen.0a98a48eaaac41")}
                  </Button>
                </div>
              </TabsContent>
              <TabsContent value="tools" className="min-h-0 flex-1 overflow-y-auto">
                {renderTools()}
              </TabsContent>
            </Tabs>
          ) : (
            <div className="flex min-h-0 flex-1 flex-col overflow-y-auto px-4">
              {renderForm()}
              <div className="flex gap-2 pt-2 pb-6">
                <Button onClick={saveForm} disabled={saving}>
                  <PlusIcon /> {ui("screen.7a8a11ead50742")}
                </Button>
                <Button variant="outline" disabled={testing} onClick={() => void testConnection()}>
                  <PlugZapIcon className={testing ? "animate-pulse" : ""} /> {ui("screen.0a98a48eaaac41")}
                </Button>
              </div>
            </div>
          )}
        </SheetContent>
      </Sheet>

      {/* 模板库：预配置的实用 MCP，预填表单后可改再保存 */}
      <Dialog open={tplOpen} onOpenChange={setTplOpen}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{ui("screen.ac28be12c3918b")}</DialogTitle>
            <DialogDescription>{ui("screen.03b1ea66b156b7")}</DialogDescription>
          </DialogHeader>
          <p className="text-amber-600 text-xs leading-relaxed dark:text-amber-400">⚠ {ui("screen.a24c6bdeaf7255")}</p>
          <ScrollArea className="max-h-[65vh] pr-3">
            <div className="flex flex-col gap-3">
              {templates.length === 0 ? (
                <p className="py-6 text-center text-muted-foreground text-sm">{ui("screen.4927a53bcc886a")}</p>
              ) : (
                templates.map((t) => (
                  <div key={t.key} className="rounded-lg border p-4">
                    <div className="flex items-center gap-2">
                      <ServerIcon className="size-4 shrink-0 text-muted-foreground" />
                      <span className="font-medium font-mono text-sm">{t.name}</span>
                      <Badge variant="outline">{t.category}</Badge>
                      <Badge variant="secondary" className="uppercase">
                        {t.transport}
                      </Badge>
                      <Button size="sm" variant="outline" className="ml-auto" onClick={() => openFromTemplate(t)}>
                        {ui("screen.7c2173c1bb4ed7")}
                      </Button>
                    </div>
                    <p className="mt-2 text-muted-foreground text-xs leading-relaxed">{t.description}</p>
                    {t.reminders && t.reminders.length > 0 && (
                      <ul className="mt-2 flex flex-col gap-1">
                        {t.reminders.map((r) => (
                          <li key={r} className="text-amber-600 text-xs leading-relaxed dark:text-amber-400">
                            ⚠ {r}
                          </li>
                        ))}
                      </ul>
                    )}
                  </div>
                ))
              )}
            </div>
          </ScrollArea>
        </DialogContent>
      </Dialog>
    </div>
  );
}
