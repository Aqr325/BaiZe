#!/usr/bin/env python3
"""SkillSpector 扫描结果体检（供 ci.yml skillspector-audit job 调用）。

读取 scan-<skill>.json 的剩余 issue，打印诊断摘要：
剩余 issue 数、被基线抑制数、风险等级、以及仍可见的 HIGH/CRITICAL 明细。

门禁由 skillspector scan 自身的退出码（$?，经 --use-shipped-baseline 与
--no-llm 判定）驱动；本脚本仅汇总展示剩余 HIGH/CRITICAL 发现，供审计确认，
不额外改变退出码（与原内联 heredoc 逻辑完全一致）。

用法: python skillspector-check.py <skill-name>
"""

import collections
import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print("用法: skillspector-check.py <skill-name>", file=sys.stderr)
        return 2
    s = sys.argv[1]
    with open(f"scan-{s}.json") as fh:
        d = json.load(fh)
    remaining = d.get("issues", [])
    blocked = [i for i in remaining if i.get("severity") in ("HIGH", "CRITICAL")]
    risk = d.get("risk_assessment", {})
    print(
        f"  {s}: remaining={len(remaining)} "
        f"suppressed={d.get('suppressed_count')} "
        f"risk={risk.get('severity')}/{risk.get('recommendation')} "
        f"blocking_high_crit={len(blocked)}"
    )
    if blocked:
        print(f"  BLOCKED rules: {collections.Counter(i['id'] for i in blocked)}")
    for i in remaining:
        if i.get("severity") in ("HIGH", "CRITICAL"):
            loc = i.get("location") or {}
            f = loc.get("file") if isinstance(loc, dict) else loc
            print(f"    [{i['severity']}] {i['id']} {f} {(i.get('pattern') or '')[:60]}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
