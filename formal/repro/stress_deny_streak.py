"""Stress test: deny-escalation state file (antigravity_hook._deny_streak_update,
semgate/antigravity_hook.py:165-182). It is a read-modify-write of one JSON
file with Path.write_text (truncate, then write) and no lock of any kind.

N real processes each record K blocks for the same session. Correct result:
total == N*K. Also checks whether the file becomes unparseable, and whether
a corrupt file is ever repaired: _deny_streak_update returns zeros on a parse
error and does NOT rewrite the file, so once corrupt, escalation stays off.

    .venv\\Scripts\\python.exe formal\\repro\\stress_deny_streak.py --procs 8 --updates 100 --rounds 20
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate  # noqa: E402


def child(path: str, pid: int, updates: int, barrier, out) -> None:
    from semgate.antigravity_hook import _deny_streak_update
    barrier.wait()
    zeros = 0
    for _ in range(updates):
        # Two sessions with different key lengths make old and new contents differ in length.
        _deny_streak_update(path, "sess-long-name-" + "x" * (pid % 3), True)
        r = _deny_streak_update(path, "s", True)
        if r == {"consecutive": 0, "total": 0}:
            zeros += 1
    out.put(zeros)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--updates", type=int, default=100)
    ap.add_argument("--rounds", type=int, default=20)
    a = ap.parse_args()
    tmp = isolate("semgate-formal-streak-")
    ctx = mp.get_context("spawn")
    expected_total = a.procs * a.updates
    lost_sum = corrupt_rounds = stuck_rounds = zero_answers = 0
    t0 = time.time()
    for r in range(a.rounds):
        path = tmp / f"round{r}" / "deny_streak.json"
        barrier = ctx.Barrier(a.procs)
        out = ctx.Queue()
        ps = [ctx.Process(target=child, args=(str(path), i, a.updates, barrier, out)) for i in range(a.procs)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        zeros = sum(out.get() for _ in ps)
        zero_answers += zeros
        raw = path.read_text(encoding="utf-8") if path.exists() else ""
        try:
            total = int(json.loads(raw)["s"]["total"])
            state = "ok"
        except Exception as exc:
            total = 0
            state = f"corrupt({type(exc).__name__}): {raw[:90]!r}"
            corrupt_rounds += 1
            # Is the corruption permanent? One more block, then re-read.
            from semgate.antigravity_hook import _deny_streak_update
            again = _deny_streak_update(str(path), "s", True)
            if path.read_text(encoding="utf-8") == raw and again == {"consecutive": 0, "total": 0}:
                stuck_rounds += 1
        lost = expected_total - total
        lost_sum += lost
        print(f"round {r}: expected total={expected_total} stored={total} lost={lost} zero_answers={zeros} state={state}", flush=True)
    print(f"SUMMARY procs={a.procs} updates/proc={a.updates} rounds={a.rounds} elapsed={time.time()-t0:.1f}s")
    print(f"  blocks lost from the session total: {rate(lost_sum, expected_total * a.rounds)}")
    print(f"  calls that got zeros (read failed mid-write): {rate(zero_answers, a.procs * a.updates * a.rounds)}")
    print(f"  rounds ending with an unparseable state file: {rate(corrupt_rounds, a.rounds)}; "
          f"of those, never repaired by a later call: {stuck_rounds}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
