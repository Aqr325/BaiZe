'use client';

import React from "react";
import { useTheme } from "next-themes";
import { HugeiconsIcon } from "@hugeicons/react";
import {
  CodeIcon,
  File01Icon,
  FingerPrintIcon,
  GitBranchIcon,
  Key01Icon,
  SparklesIcon,
  Tick02Icon,
} from "@hugeicons/core-free-icons";
import MagicBentoImpl from "./magic-bento";
import AnimatedListImpl from "./animated-list";
import type { Activity, Agent, Finding, MCPServer, Task } from "@/lib/types";

// 两个动效组件为纯 JS，TS 把无默认值 props(style/glowColor/onItemClick 等)
// 推断成必填，但运行时均为可选。这里转宽松类型，避免调用点类型误报。
type LooseFC = React.FC<Record<string, unknown>>;
const MagicBento = MagicBentoImpl as unknown as LooseFC;
const AnimatedList = AnimatedListImpl as unknown as LooseFC;

// ---------------------------------------------------------------------------
// 白泽「动效总览」：把实时数据映射进 MagicBento(系统状态 bento) 与
// AnimatedList(最近动态列表)。纯展示层，不改变任何既有数据流。
// ---------------------------------------------------------------------------

const ICON_SIZE = 18;
const glyph = (icon: unknown) => <HugeiconsIcon icon={icon as never} size={ICON_SIZE} strokeWidth={1.6} />;

// 动态 kind → 图标
function kindIcon(kind: Activity["kind"], isError?: boolean): unknown {
  if (isError) return File01Icon;
  switch (kind) {
    case "tool_use":
      return CodeIcon;
    case "tool_result":
      return GitBranchIcon;
    case "thinking":
      return SparklesIcon;
    case "result":
    case "text":
      return File01Icon;
    case "user":
      return FingerPrintIcon;
    case "intent":
      return Key01Icon;
    case "round":
      return Tick02Icon;
    case "intercept_request":
      return Key01Icon;
    case "llm_switch":
    case "llm_failover":
      return GitBranchIcon;
    default:
      return SparklesIcon;
  }
}

// 相对时间（分钟级精度，够用）
function relTime(ts: string): string {
  const t = new Date(ts).getTime();
  if (!Number.isFinite(t)) return "";
  const diff = Date.now() - t;
  if (diff < 60_000) return "now";
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h`;
  return `${Math.floor(diff / 86_400_000)}d`;
}

export interface OverviewMotionProps {
  tasks: Task[];
  findings: Finding[];
  agents: Agent[];
  mcpServers: MCPServer[];
  activity: Activity[];
}

export default function OverviewMotion({ tasks, findings, agents, mcpServers, activity }: OverviewMotionProps) {
  const { resolvedTheme } = useTheme();
  const theme = resolvedTheme === "light" ? "light" : "dark";

  // ---- 实时指标 ----
  const runningTasks = tasks.filter((t) => t.status === "running").length;
  const pausedTasks = tasks.filter((t) => t.status === "paused").length;
  const enabledAgents = agents.filter((a) => a.enabled).length;
  const enabledMcp = mcpServers.filter((m) => m.enabled).length;
  const mcpTools = mcpServers.reduce((acc, m) => acc + (m.tools?.length ?? 0), 0);
  const highSeverity = findings.filter((f) => {
    const s = (f as { severity?: string }).severity;
    return s === "high" || s === "critical";
  }).length;

  // ---- MagicBento: 系统状态 bento ----
  const bentoItems = [
    {
      title: "任务管控",
      description: `${runningTasks} 运行中 · ${pausedTasks} 暂停 · ${tasks.length} 总任务`,
      visual: "dashboard",
      colSpan: 2,
      rowSpan: 2,
    },
    {
      title: "发现分析",
      description: `${findings.length} 条发现 · ${highSeverity} 高危`,
      visual: "analytics",
    },
    {
      title: "Agent 协同",
      description: `${enabledAgents}/${agents.length} 在线`,
      visual: "collaboration",
    },
    {
      title: "自动化",
      description: `${enabledMcp} MCP · ${mcpTools} 工具`,
      visual: "automation",
      colSpan: 2,
      rowSpan: 2,
    },
    {
      title: "集成接入",
      description: `${mcpServers.length} 个服务`,
      visual: "integration",
    },
    {
      title: "安全防护",
      description: `${highSeverity} 项需关注`,
      visual: "security",
    },
  ];

  // ---- AnimatedList: 最近动态 ----
  const listItems = activity.slice(0, 12).map((a) => ({
    icon: glyph(kindIcon(a.kind, a.is_error)),
    title: a.summary || a.kind,
    description: `${a.worker}${a.tool ? ` · ${a.tool}` : ""}`,
    meta: relTime(a.ts),
  }));

  return (
    <div className="flex flex-col gap-4">
      {/* MagicBento 系统总览 */}
      <div>
        <div className="mb-2 text-[10px] font-medium text-muted-foreground">系统状态总览</div>
        <MagicBento items={bentoItems} columns={4} rowHeight={150} theme={theme} enableStars={false} textAutoHide={false} radius={18} />
      </div>

      {/* AnimatedList 最近动态 */}
      {listItems.length > 0 && (
        <div>
          <div className="mb-2 text-[10px] font-medium text-muted-foreground">最近动态</div>
          <div className="flex justify-center">
            <AnimatedList
              items={listItems}
              theme={theme}
              width={680}
              maxHeight={380}
              radius={14}
              gap={8}
              frame={false}
              showGradients
              fadeSize={48}
              selectOnHover={false}
              enableArrowNavigation
            />
          </div>
        </div>
      )}
    </div>
  );
}
