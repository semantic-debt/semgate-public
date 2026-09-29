"""Print a TLC counterexample from formal/results/tlc/<job>.out as one line
per step: the action name, and the variables that changed (short form).

    .venv\\Scripts\\python.exe formal\\trace_summary.py MC_Semgate__code__LedgerOneLine [var1,var2]
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent


def states(text: str):
    parts = re.split(r"^State (\d+): (<[^>]*>|.*)$", text, flags=re.M)
    out = []
    for i in range(1, len(parts) - 2, 3):
        num, action, body = parts[i], parts[i + 1], parts[i + 2]
        body = body.split("\nError:")[0].split("\nBack to state")[0]
        vals = {}
        for m in re.finditer(r"^/\\ (\w+) = (.*?)(?=^/\\ |\Z)", body, flags=re.M | re.S):
            vals[m.group(1)] = " ".join(m.group(2).split())
        name = re.sub(r" line \d+.*", "", action.strip("<>"))
        out.append((int(num), name, vals))
    return out


def main() -> int:
    job = sys.argv[1]
    only = set(sys.argv[2].split(",")) if len(sys.argv) > 2 else None
    text = (HERE / "results" / "tlc" / f"{job}.out").read_text(encoding="utf-8")
    prev = {}
    for num, name, vals in states(text):
        changed = {k: v for k, v in vals.items() if prev.get(k) != v and (only is None or k in only)}
        print(f"{num:3} {name}")
        for k, v in changed.items():
            print(f"      {k} = {v[:300]}")
        prev = vals
    m = re.search(r"Back to state (\d+)", text)
    if m:
        print(f"    (lasso: back to state {m.group(1)})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
