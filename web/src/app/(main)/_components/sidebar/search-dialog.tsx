"use client";

import * as React from "react";

import { useRouter } from "next/navigation";

import { Search } from "lucide-react";
import { useTranslation } from "react-i18next";

import { Button } from "@/components/ui/button";
import {
  Command,
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
} from "@/components/ui/command";
import type { NavMainItem } from "@/navigation/sidebar/sidebar-items";
import { getSidebarItems } from "@/navigation/sidebar/sidebar-items";
import { api } from "@/lib/api";

type SearchItem = {
  id: string;
  group: string;
  label: string;
  url: string;
  icon?: NavMainItem["icon"];
  disabled?: boolean;
  newTab?: boolean;
  subtitle?: string;
};

// 全局数据搜索结果（任务/发现/对话/资产），key 用于按数据指纹合并去重。
type DataResult = {
  kind: string;
  id: string;
  title: string;
  subtitle?: string;
  url: string;
};

const KIND_GROUP_KEY: Record<string, string> = {
  task: "search.groupTasks",
  finding: "search.groupFindings",
  conversation: "search.groupConversations",
  asset: "search.groupAssets",
};

function groupBy(items: SearchItem[]) {
  const groups = [...new Set(items.map((item) => item.group))];
  return groups.map((group) => ({
    group,
    items: items.filter((item) => item.group === group),
  }));
}

export function SearchDialog() {
  const { t } = useTranslation();
  const searchItems: SearchItem[] = getSidebarItems(t)
    .flatMap((group) =>
      group.items.flatMap((item) =>
        item.subItems
          ? item.subItems.map((sub) => ({ ...sub, group: item.title, label: sub.title }))
          : [{ ...item, group: group.label ?? t("common.other"), label: item.title }],
      ),
    )
    .filter((item) => !item.disabled && !item.url.includes("coming-soon"));
  const [open, setOpen] = React.useState(false);
  const [query, setQuery] = React.useState("");
  const [dataResults, setDataResults] = React.useState<DataResult[]>([]);
  const [dataLoading, setDataLoading] = React.useState(false);
  const router = useRouter();

  // 输入非空时对后端做全局数据搜索（防抖 300ms；导航项过滤仍走前端）。
  React.useEffect(() => {
    const q = query.trim();
    if (q.length < 2) {
      setDataResults([]);
      setDataLoading(false);
      return;
    }
    setDataLoading(true);
    const timer = setTimeout(() => {
      api
        .globalSearch(q)
        .then((r) => setDataResults(r.items ?? []))
        .catch(() => setDataResults([]))
        .finally(() => setDataLoading(false));
    }, 300);
    return () => clearTimeout(timer);
  }, [query]);

  // 数据结果 → 导航同构条目，分组标签按 kind 取 i18n。
  const dataItems: SearchItem[] = React.useMemo(
    () =>
      dataResults.map((r) => ({
        id: `${r.kind}-${r.id}`,
        group: t(KIND_GROUP_KEY[r.kind] ?? "common.other"),
        label: r.title || r.url,
        url: r.url,
        subtitle: r.subtitle,
      })),
    [dataResults, t],
  );

  React.useEffect(() => {
    const down = (e: KeyboardEvent) => {
      if (e.key === "j" && (e.metaKey || e.ctrlKey)) {
        e.preventDefault();
        setOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", down);
    return () => document.removeEventListener("keydown", down);
  }, []);

  const handleOpenChange = (value: boolean) => {
    setOpen(value);
    if (!value) setQuery("");
  };

  const handleSelect = (item: SearchItem) => {
    if (item.disabled) return;
    handleOpenChange(false);
    if (item.newTab) {
      window.open(item.url, "_blank", "noopener,noreferrer");
    } else {
      router.push(item.url);
    }
  };

  const renderGroups = (items: SearchItem[]) =>
    groupBy(items).map(({ group, items: groupItems }, index) => (
      <React.Fragment key={group}>
        {index > 0 && <CommandSeparator />}
        <CommandGroup heading={group}>
          {groupItems.map((item) => (
            <CommandItem
              disabled={item.disabled}
              key={`${group}-${item.id}`}
              value={`${item.group} ${item.label} ${item.subtitle ?? ""}`}
              onSelect={() => handleSelect(item)}
            >
              <span className="flex min-w-0 items-center gap-2">
                {item.icon && <item.icon />}
                <span className="flex min-w-0 flex-col">
                  <span className="truncate">{item.label}</span>
                  {item.subtitle ? (
                    <span className="text-muted-foreground truncate text-xs">{item.subtitle}</span>
                  ) : null}
                </span>
              </span>
            </CommandItem>
          ))}
        </CommandGroup>
      </React.Fragment>
    ));

  return (
    <>
      <Button
        onClick={() => handleOpenChange(true)}
        variant="link"
        className="px-0! font-normal text-muted-foreground hover:no-underline"
      >
        <Search data-icon="inline-start" />
        {t("common.search")}
        <kbd className="inline-flex h-5 select-none items-center gap-1 rounded border bg-muted px-1.5 font-medium text-[10px]">
          <span className="text-xs">⌘</span>J
        </kbd>
      </Button>
      <CommandDialog open={open} onOpenChange={handleOpenChange}>
        <Command>
          <CommandInput placeholder={t("search.placeholder")} value={query} onValueChange={setQuery} />
          <CommandList>
            <CommandEmpty>
              {dataLoading ? t("search.searching") : t("search.empty")}
            </CommandEmpty>
            {renderGroups(searchItems)}
            {dataItems.length > 0 ? renderGroups(dataItems) : null}
          </CommandList>
        </Command>
      </CommandDialog>
    </>
  );
}
