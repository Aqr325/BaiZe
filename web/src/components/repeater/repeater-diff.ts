// 行级 diff 工具：供 Repeater 响应对比（改包调参后直观看到响应变化）。
// 纯函数、无依赖，便于单测；响应体通常 < 数千行，O(n*m) LCS 足够快。

export type DiffLineKind = "same" | "add" | "remove";
export type DiffLine = { kind: DiffLineKind; text: string };

// 行级 LCS diff。返回按行序排列的 diff：same 为上下文，remove 为基线独有，
// add 为对比目标独有。空串视为单行空文件，保证至少返回一行。
export function diffLines(a: string, b: string): DiffLine[] {
  // 空串视为 0 行（split 会把 "" 变成 [""]），使「空体 vs 内容体」只显示增行。
  const A = a === "" ? [] : a.split("\n");
  const B = b === "" ? [] : b.split("\n");
  const n = A.length;
  const m = B.length;
  // dp[i][j] = A[0..i) 与 B[0..j) 的最长公共子序列长度。
  const dp: number[][] = Array.from({ length: n + 1 }, () => new Array<number>(m + 1).fill(0));
  for (let i = 1; i <= n; i++) {
    for (let j = 1; j <= m; j++) {
      dp[i][j] = A[i - 1] === B[j - 1] ? dp[i - 1][j - 1] + 1 : Math.max(dp[i - 1][j], dp[i][j - 1]);
    }
  }
  const out: DiffLine[] = [];
  let i = n;
  let j = m;
  while (i > 0 && j > 0) {
    if (A[i - 1] === B[j - 1]) {
      out.push({ kind: "same", text: A[i - 1] });
      i--;
      j--;
    } else if (dp[i - 1][j] > dp[i][j - 1]) {
      out.push({ kind: "remove", text: A[i - 1] });
      i--;
    } else {
      out.push({ kind: "add", text: B[j - 1] });
      j--;
    }
  }
  while (i > 0) {
    out.push({ kind: "remove", text: A[--i] });
  }
  while (j > 0) {
    out.push({ kind: "add", text: B[--j] });
  }
  return out.reverse();
}

export type DiffStats = { added: number; removed: number; same: number };

export function countDiff(lines: DiffLine[]): DiffStats {
  const stats: DiffStats = { added: 0, removed: 0, same: 0 };
  for (const line of lines) {
    if (line.kind === "add") stats.added++;
    else if (line.kind === "remove") stats.removed++;
    else stats.same++;
  }
  return stats;
}

// 把响应体做美化（可解析的 JSON 缩进 2 格），便于人眼对比与 diff 命中。
export function prettyBody(body: string): string {
  try {
    return JSON.stringify(JSON.parse(body), null, 2);
  } catch {
    return body;
  }
}
