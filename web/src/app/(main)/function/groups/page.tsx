"use client";
import * as React from "react";

import {
  Loader2Icon,
  MessageSquareTextIcon,
  PlusIcon,
  RefreshCwIcon,
  SendIcon,
  SquareIcon,
  Trash2Icon,
  UsersIcon,
} from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Textarea } from "@/components/ui/textarea";
import { type UITranslate, useUITranslation } from "@/i18n/use-ui-translation";
import { api } from "@/lib/api";
import type { Agent, GroupEvent, GroupRoomRow, LLMProfile } from "@/lib/types";

const KIND_LABEL: Record<string, { text: string; cls: string }> = {
  "message.user": { text: "user", cls: "bg-sky-100 text-sky-800" },
  "message.member": { text: "member", cls: "bg-violet-100 text-violet-800" },
  "turn.settled": { text: "settled", cls: "bg-teal-100 text-teal-800" },
  "turn.failed": { text: "failed", cls: "bg-red-100 text-red-800" },
  "turn.cancelled": { text: "cancelled", cls: "bg-zinc-200 text-zinc-700" },
  "room.activity": { text: "activity", cls: "bg-amber-100 text-amber-800" },
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

// Infer a room's display state from its newest event.
function roomState(room: GroupRoomRow): "running" | "needsYou" | "settled" | "idle" | "pending" {
  if (room.disbanded_at) return "idle";
  return "running";
}

const STATE_BADGE: Record<string, string> = {
  running: "bg-emerald-100 text-emerald-800",
  needsYou: "bg-red-100 text-red-800",
  settled: "bg-teal-100 text-teal-800",
  idle: "bg-zinc-100 text-zinc-600",
  pending: "bg-amber-100 text-amber-800",
};

function stateLabel(state: string, ui: UITranslate) {
  const key = `screen.groups.state${state.charAt(0).toUpperCase()}${state.slice(1)}`;
  return ui(key);
}

// Infer a room's live state from its newest event (more precise than roomState,
// which only distinguishes disbanded vs active). The backend persists a
// room.activity event with a status payload for each scheduling decision.
function roomStateFromEvents(events: GroupEvent[]): "running" | "settled" | "idle" | "pending" {
  const last = events[events.length - 1];
  if (!last) return "pending";
  if (
    last.kind === "turn.settled" ||
    last.kind === "turn.failed" ||
    last.kind === "turn.cancelled" ||
    last.kind === "turn.deferred"
  ) {
    return "settled";
  }
  if (last.kind === "room.activity") {
    const s = String(last.payload.status ?? "");
    if (s === "idle") return "idle";
    if (s === "bounded") return "settled";
  }
  return "running";
}

// ---- new room dialog -----------------------------------------------------

function NewGroupDialog({
  profiles,
  agents,
  onCreated,
  onClose,
}: {
  profiles: LLMProfile[];
  agents: Agent[];
  onCreated: () => void;
  onClose: () => void;
}) {
  const { ui } = useUITranslation();
  const [name, setName] = React.useState("");
  const memberSeq = React.useRef(3);
  const [members, setMembers] = React.useState<{ id: number; profileId: string; handle: string; agentKey: string }[]>([
    { id: 1, profileId: "", handle: "", agentKey: "" },
    { id: 2, profileId: "", handle: "", agentKey: "" },
  ]);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const updateMember = (id: number, field: "profileId" | "handle" | "agentKey", value: string) => {
    setMembers((prev) => prev.map((m) => (m.id === id ? { ...m, [field]: value } : m)));
  };

  const addMember = () => {
    if (members.length < 6) {
      const id = memberSeq.current++;
      setMembers([...members, { id, profileId: "", handle: "", agentKey: "" }]);
    }
  };
  const removeMember = (id: number) => {
    if (members.length > 2) setMembers((prev) => prev.filter((m) => m.id !== id));
  };

  const submit = async () => {
    const valid = members.filter((m) => m.profileId && m.handle.trim());
    if (!name.trim() || valid.length < 2) {
      setError(ui("screen.groups.newMembersHint"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      await api.createGroup({
        name: name.trim(),
        members: valid.map((m) => ({
          profile: m.handle.trim(),
          handle: m.handle.trim(),
          llm_profile_id: Number(m.profileId),
          agent_key: m.agentKey || undefined,
        })),
      });
      onCreated();
      onClose();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Dialog open onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{ui("screen.groups.newTitle")}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-1.5">
            <Label>{ui("screen.groups.newName")}</Label>
            <Input
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder={ui("screen.groups.newNamePlaceholder")}
            />
          </div>
          <div className="space-y-1.5">
            <Label>{ui("screen.groups.newMembers")}</Label>
            <p className="text-xs text-muted-foreground">{ui("screen.groups.newMembersHint")}</p>
            <div className="space-y-2">
              {members.map((m) => (
                <div key={m.id} className="space-y-1.5 rounded-md border p-2">
                  <div className="flex items-center gap-2">
                    <NativeSelect
                      className="flex-1"
                      value={m.profileId}
                      onChange={(e) => updateMember(m.id, "profileId", e.target.value)}
                    >
                      <option value="">{ui("screen.groups.newProfile")}</option>
                      {profiles.map((p) => (
                        <option key={p.id} value={p.id}>
                          {p.name} ({p.model})
                        </option>
                      ))}
                    </NativeSelect>
                    <Input
                      className="flex-1"
                      value={m.handle}
                      onChange={(e) => updateMember(m.id, "handle", e.target.value)}
                      placeholder={ui("screen.groups.newHandle")}
                    />
                    <Button
                      variant="ghost"
                      size="icon"
                      disabled={members.length <= 2}
                      onClick={() => removeMember(m.id)}
                    >
                      <Trash2Icon className="h-4 w-4" />
                    </Button>
                  </div>
                  <NativeSelect
                    className="w-full"
                    value={m.agentKey}
                    onChange={(e) => updateMember(m.id, "agentKey", e.target.value)}
                  >
                    <option value="">{ui("screen.groups.newAgentNone")}</option>
                    {agents.map((a) => (
                      <option key={a.key} value={a.key}>
                        {a.name} ({a.key})
                      </option>
                    ))}
                  </NativeSelect>
                </div>
              ))}
            </div>
            <Button variant="outline" size="sm" disabled={members.length >= 6} onClick={addMember}>
              <PlusIcon className="mr-1 h-3.5 w-3.5" />
              {ui("screen.groups.newMembers")}
            </Button>
          </div>
          {error && <p className="text-sm text-red-600">{error}</p>}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>
            {ui("screen.groups.cancel")}
          </Button>
          <Button onClick={submit} disabled={busy}>
            {busy && <Loader2Icon className="mr-1 h-4 w-4 animate-spin" />}
            {ui("screen.groups.create")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ---- room view -----------------------------------------------------------

function RoomView({ roomId, onBack }: { roomId: string; onBack: () => void }) {
  const { ui } = useUITranslation();
  const [detail, setDetail] = React.useState<{ room: GroupRoomRow; events: GroupEvent[] } | null>(null);
  const [text, setText] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");

  const load = React.useCallback(async () => {
    try {
      const r = await api.group(roomId);
      setDetail({ room: r.room, events: r.events });
    } catch (e) {
      setError(String(e));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [roomId]);

  React.useEffect(() => {
    void load();
  }, [load]);

  // Poll while a discussion may be running so member turns stream in.
  React.useEffect(() => {
    const timer = setInterval(() => void load(), 4000);
    return () => clearInterval(timer);
  }, [load]);

  const send = async () => {
    if (!text.trim()) return;
    setBusy(true);
    setError("");
    try {
      await api.sendGroupMessage(roomId, text.trim());
      setText("");
      await load();
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  };

  const stop = async () => {
    await api.stopGroup(roomId);
    await load();
  };
  const cont = async () => {
    await api.continueGroup(roomId);
    await load();
  };

  const events = detail?.events ?? [];
  const visible = events.filter(
    (e) => e.kind === "message.user" || e.kind === "message.member" || e.kind === "room.activity",
  );
  const state = detail ? roomStateFromEvents(events) : "pending";

  // Auto-scroll the transcript to the newest event as member turns stream in.
  const bottomRef = React.useRef<HTMLDivElement | null>(null);
  React.useEffect(() => {
    if (visible.length === 0) return;
    bottomRef.current?.scrollIntoView({ behavior: "smooth", block: "end" });
  }, [visible.length]);

  return (
    <div className="flex h-[calc(100vh-8rem)] flex-col gap-3">
      <div className="flex items-center gap-2">
        <Button variant="ghost" size="sm" onClick={onBack}>
          ← {ui("screen.groups.title")}
        </Button>
        <h2 className="text-lg font-semibold">
          {ui("screen.groups.roomHeader")}
          {detail?.room.room.name ?? ""}
        </h2>
        <Badge className={STATE_BADGE[state]}>{stateLabel(state, ui)}</Badge>
        <div className="ml-auto flex items-center gap-2">
          {detail?.room.members.map((m) => (
            <Badge key={m.member_id} variant="outline">
              @{m.handle}
            </Badge>
          ))}
        </div>
      </div>
      <Card className="flex-1 overflow-hidden">
        <CardContent className="flex h-full flex-col p-0">
          <ScrollArea className="flex-1 p-4">
            {visible.length === 0 ? (
              <p className="text-sm text-muted-foreground">{ui("screen.groups.empty")}</p>
            ) : (
              <div className="space-y-2">
                {visible.map((e) => {
                  const meta = KIND_LABEL[e.kind] ?? { text: e.kind, cls: "bg-zinc-100" };
                  const textContent = String(e.payload.text ?? "");
                  const speaker =
                    e.kind === "message.member"
                      ? `@${detail?.room.members.find((m) => m.member_id === e.payload.member_id)?.handle ?? e.payload.member_id}`
                      : ui("screen.groups.userLabel");
                  return (
                    <div key={e.seq} className="flex items-start gap-2">
                      <Badge className={meta.cls}>{speaker}</Badge>
                      <div className="min-w-0 flex-1 rounded-lg bg-muted px-3 py-2 text-sm">
                        {textContent || String(e.payload.reason_code ?? e.payload.status ?? "")}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
            <div ref={bottomRef} className="h-px" />
          </ScrollArea>
          <div className="flex items-center gap-2 border-t p-3">
            <Textarea
              className="flex-1"
              rows={2}
              value={text}
              onChange={(e) => setText(e.target.value)}
              placeholder={ui("screen.groups.sendPlaceholder")}
              onKeyDown={(e) => {
                if (e.key === "Enter" && !e.shiftKey) {
                  e.preventDefault();
                  void send();
                }
              }}
            />
            <div className="flex flex-col gap-1.5">
              <Button size="sm" onClick={send} disabled={busy || !text.trim()}>
                <SendIcon className="mr-1 h-4 w-4" />
                {ui("screen.groups.send")}
              </Button>
              <div className="flex gap-1.5">
                <Button size="sm" variant="outline" onClick={stop} title={ui("screen.groups.stop")}>
                  <SquareIcon className="h-3.5 w-3.5" />
                </Button>
                <Button size="sm" variant="outline" onClick={cont} title={ui("screen.groups.continue")}>
                  <RefreshCwIcon className="h-3.5 w-3.5" />
                </Button>
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
      {error && <p className="text-sm text-red-600">{error}</p>}
    </div>
  );
}

// ---- page ----------------------------------------------------------------

export default function GroupsPage() {
  const { ui } = useUITranslation();
  const [rooms, setRooms] = React.useState<GroupRoomRow[]>([]);
  const [profiles, setProfiles] = React.useState<LLMProfile[]>([]);
  const [agents, setAgents] = React.useState<Agent[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [error, setError] = React.useState("");
  const [selectedId, setSelectedId] = React.useState<string>("");
  const [showNew, setShowNew] = React.useState(false);

  // biome-ignore lint/correctness/useExhaustiveDependencies: ui is locale-stable; load is triggered only on mount or manual refresh.
  const load = React.useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const r = await api.groups();
      setRooms(r.items);
    } catch (e) {
      setError(ui("screen.groups.error") + "：" + String(e));
    } finally {
      setLoading(false);
    }
  }, []);

  React.useEffect(() => {
    void load();
    void api
      .llmProfiles()
      .then(setProfiles)
      .catch(() => setProfiles([]));
    void api
      .agents()
      .then(setAgents)
      .catch(() => setAgents([]));
  }, [load]);

  const disband = async (id: string) => {
    if (!window.confirm(ui("screen.groups.disbandConfirm"))) return;
    await api.disbandGroup(id);
    await load();
  };

  if (selectedId) {
    return <RoomView roomId={selectedId} onBack={() => setSelectedId("")} />;
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-semibold">{ui("screen.groups.title")}</h2>
          <p className="text-sm text-muted-foreground">{ui("screen.groups.subtitle")}</p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => void load()}>
            <RefreshCwIcon className="mr-1 h-4 w-4" />
            {ui("screen.groups.refresh")}
          </Button>
          <Button onClick={() => setShowNew(true)}>
            <PlusIcon className="mr-1 h-4 w-4" />
            {ui("screen.groups.new")}
          </Button>
        </div>
      </div>

      {loading && (
        <div className="flex justify-center py-12">
          <Loader2Icon className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}
      {!loading && rooms.length === 0 && (
        <Card>
          <CardContent className="flex flex-col items-center gap-2 py-12 text-muted-foreground">
            <UsersIcon className="h-8 w-8" />
            <p className="text-sm">{ui("screen.groups.empty")}</p>
          </CardContent>
        </Card>
      )}
      {!loading && rooms.length > 0 && (
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {rooms.map((room) => {
            const state = roomState(room);
            return (
              <Card key={room.room.room_id} className="cursor-pointer" onClick={() => setSelectedId(room.room.room_id)}>
                <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
                  <CardTitle className="text-base">{room.room.name}</CardTitle>
                  <Badge className={STATE_BADGE[state]}>{stateLabel(state, ui)}</Badge>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-center gap-1.5 text-sm text-muted-foreground">
                    <UsersIcon className="h-4 w-4" />
                    {ui("screen.groups.memberCount").replace("{count}", String(room.member_count))}
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground">
                    <span>{fmtDate(room.updated_at, ui)}</span>
                    <div className="flex gap-1">
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedId(room.room.room_id);
                        }}
                        title={ui("screen.groups.open")}
                      >
                        <MessageSquareTextIcon className="h-4 w-4" />
                      </Button>
                      <Button
                        variant="ghost"
                        size="icon"
                        onClick={(e) => {
                          e.stopPropagation();
                          void disband(room.room.room_id);
                        }}
                        title={ui("screen.groups.disband")}
                      >
                        <Trash2Icon className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}
      {error && <p className="text-sm text-red-600">{error}</p>}
      {showNew && (
        <NewGroupDialog
          profiles={profiles}
          agents={agents}
          onCreated={() => void load()}
          onClose={() => setShowNew(false)}
        />
      )}
    </div>
  );
}
