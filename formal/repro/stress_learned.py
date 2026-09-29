"""Stress test: learned auto-allow store (semgate/history.py) under the
Antigravity pre/post hook pattern. Each process plays one agent conversation:
for every step it writes the PreToolUse `pending` record (decision "ask",
command `npm test`), then the PostToolUse join `record_executed` (no error:
the human approved and it ran), and every 5th step a `deny` step for
`rm -rf build` whose post event carries an error (it did not run).

Correct end state: count_executed_after_ask("bash", npm test) == number of
ask steps; the deny command's count == 0.

Measured: undercount (safe: learning is slower), overcount (unsafe: learned
allow sooner than the humans approved), how often the real readers raise
(ToolHistory.records raises JSONDecodeError on a partial or torn line; the
post hook swallows it, so the executed record is silently not written), and
whether the final file makes every later reader raise (learning off for good).

    .venv\\Scripts\\python.exe formal\\repro\\stress_learned.py --procs 8 --steps 60 --rounds 10
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate, scan_jsonl  # noqa: E402

ASK_CMD = {"command": "npm test"}
DENY_CMD = {"command": "rm -rf build"}


def child(path: str, pid: int, steps: int, barrier, out) -> None:
    from semgate.history import ToolHistory
    h = ToolHistory(path)
    barrier.wait()
    post_raised = asks = 0
    for s in range(steps):
        conv = f"conv-{pid}"
        if s % 5 == 4:
            h.record_pending(conv, s, "bash", DENY_CMD, "deny", "semantic")
            try:
                h.record_executed(conv, s, error="denied by hook")
            except Exception:
                post_raised += 1
            continue
        asks += 1
        h.record_pending(conv, s, "bash", ASK_CMD, "ask", "semantic")
        try:
            h.record_executed(conv, s, error="")
        except Exception:          # antigravity_post_hook.py:458 swallows this
            post_raised += 1
    out.put((asks, post_raised))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--steps", type=int, default=60)
    ap.add_argument("--rounds", type=int, default=10)
    a = ap.parse_args()
    tmp = isolate("semgate-formal-learned-")
    from semgate.history import ToolHistory
    ctx = mp.get_context("spawn")
    tot = dict(asks=0, counted=0, over=0, deny_counted=0, post_calls=0, post_raised=0, final_raise=0, torn=0, unmatched=0)
    t0 = time.time()
    for r in range(a.rounds):
        path = tmp / f"round{r}" / "tool_history.jsonl"
        barrier = ctx.Barrier(a.procs)
        out = ctx.Queue()
        ps = [ctx.Process(target=child, args=(str(path), i, a.steps, barrier, out)) for i in range(a.procs)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        res = [out.get() for _ in ps]
        asks = sum(x for x, _ in res)
        raised = sum(y for _, y in res)
        good, bad = scan_jsonl(path)
        unmatched = sum(1 for g in good if g.get("record_type") == "executed_unmatched")
        try:
            counted = ToolHistory(str(path)).count_executed_after_ask("bash", ASK_CMD)
            deny_counted = ToolHistory(str(path)).count_executed_after_ask("bash", DENY_CMD)
            final = "ok"
        except Exception as exc:
            final = type(exc).__name__
            tot["final_raise"] += 1
            # what the judge would see: fail closed, so count as 0; independent count from the scan:
            counted = sum(1 for g in good if g.get("record_type") == "executed" and g.get("prior_decision") == "ask"
                          and not g.get("error") and g.get("args_normalized") == '{"command":"npm test"}')
            deny_counted = 0
        tot["asks"] += asks
        tot["counted"] += counted
        tot["over"] += max(0, counted - asks)
        tot["deny_counted"] += deny_counted
        tot["post_calls"] += a.procs * a.steps
        tot["post_raised"] += raised
        tot["torn"] += len(bad)
        tot["unmatched"] += unmatched
        print(f"round {r}: approved asks={asks} counted={counted} deny_counted={deny_counted} post raised={raised} "
              f"executed_unmatched={unmatched} torn={len(bad)} final reader={final}", flush=True)
    print(f"SUMMARY procs={a.procs} steps/proc={a.steps} rounds={a.rounds} elapsed={time.time()-t0:.1f}s")
    print(f"  approvals not counted (undercount, safe): {rate(tot['asks'] - tot['counted'] + tot['over'], tot['asks'])}; "
          f"overcount (unsafe): {tot['over']}; denied command counted (unsafe): {tot['deny_counted']}")
    print(f"  post-hook joins that raised (executed record silently not written): {rate(tot['post_raised'], tot['post_calls'])}")
    print(f"  executed_unmatched records (pending record lost): {tot['unmatched']}; torn lines: {tot['torn']}")
    print(f"  rounds where the final file makes every reader raise (learning off until the file is repaired): {rate(tot['final_raise'], a.rounds)}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
