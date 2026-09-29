"""Stress test (HEAD 5805459 and later): session drift reads earlier judgments
from the ledger (Ledger.session_on_task in semgate/ledger.py; used by the
judge only with policy thresholds.drift_session_ask_max, e.g.
policies/router_policy_dev_sdrift.json: max 0.5, window 5, at least 3 values).

Before the fix, a judgment line lost to the Windows append race was a missing
on_task value. Losing a low value can raise the mean above the limit, so the
"allow -> ask" of session drift did not happen (fail-open for this signal).
Now Ledger._append goes through semgate/filelock.py (cross-process lock), and
session_on_task reads under the same lock and raises ledger.IncompleteWindow
when the window may be incomplete (lock timeout, unreadable file, malformed
line since the session's first record, or a record of the session in a
lock-timeout spill file). The judge then asks. This script counts such a
round as "ask (window incomplete)" and keeps counting lost lines in the
rounds where session_on_task returns.

Per round: 4 real processes (parallel hook calls of one session) append one
judgment each, in the shape Ledger.record_judgment writes (real
Envelope.to_dict() of a Claude Code event; decision.stage "semantic";
predicate_votes on_task p), with on_task p = 0.3, 0.3, 0.3, 0.9. Four other
processes append host_response lines of another session at the same time
(the ledger is shared by every session of that host).
Then the real Ledger.session_on_task + router.session_drift_mean compute the
drift decision for the next step (current on_task p = 0.6):
  nothing lost: mean(0.3, 0.3, 0.3, 0.9, 0.6) = 0.48 <= 0.5 -> ask
  one 0.3 lost: mean(0.3, 0.3, 0.9, 0.6)      = 0.525 > 0.5 -> stays allow

    .venv\\Scripts\\python.exe formal\\repro\\stress_drift.py --rounds 200
"""
from __future__ import annotations

import argparse
import multiprocessing as mp
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import isolate, rate  # noqa: E402

P_VALUES = [0.3, 0.3, 0.3, 0.9]
CURRENT_P = 0.6
LIMIT, WINDOW = 0.5, 5


def envelope(session: str, cmd: str):
    from semgate.adapters import claude_family
    from semgate.envelope import UserGrant
    grant = UserGrant(grant_id="g", principal="p", purpose="Software development in this project",
                      expires_at="2099-01-01T00:00:00Z")
    return claude_family.envelope_from_event({"hook_event_name": "PreToolUse", "tool_name": "Bash",
                                              "tool_input": {"command": cmd}, "session_id": session,
                                              "tool_use_id": "t", "cwd": "/w/p"}, grant, host="claude")


def child(path: str, kind: str, idx: int, barrier) -> None:
    from semgate.ledger import Ledger
    from semgate.envelope import utcnow_iso
    led = Ledger(path)
    if kind == "judgment":
        env = envelope("sess-drift", f"npm run step-{idx}").to_dict()
        rec = {"record_type": "judgment", "judgment_id": f"j{idx}", "ts": utcnow_iso(), "envelope": env,
               "decision": {"decision": "allow", "stage": "semantic",
                            "predicate_votes": [{"predicate": "on_task", "vote": "drift", "p": P_VALUES[idx]}]}}
        barrier.wait()
        led._append(rec)
    else:
        barrier.wait()
        led.record_host_response("sess-other", f"t{idx}", {"decision": "allow", "reason": "x" * 300}, tool="bash")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=200)
    a = ap.parse_args()
    tmp = isolate("semgate-formal-drift-")
    from semgate import router
    from semgate.ledger import IncompleteWindow, Ledger
    ctx = mp.get_context("spawn")
    cur_env = envelope("sess-drift", "npm run next")
    outcome = Counter()
    lost_total = incomplete = read_rounds = 0
    t0 = time.time()
    for r in range(a.rounds):
        path = tmp / f"round{r}" / "ledger.jsonl"
        n = len(P_VALUES) + 4
        barrier = ctx.Barrier(n)
        ps = [ctx.Process(target=child, args=(str(path), "judgment", i, barrier)) for i in range(len(P_VALUES))]
        ps += [ctx.Process(target=child, args=(str(path), "other", i, barrier)) for i in range(4)]
        for p in ps:
            p.start()
        for p in ps:
            p.join()
        try:
            earlier = Ledger(str(path)).session_on_task(cur_env)
        except IncompleteWindow as exc:
            # The judge turns an allow into an ask when the window may be incomplete.
            outcome["ask (window incomplete)"] += 1
            incomplete += 1
            print(f"round {r}: IncompleteWindow({exc}) -> ask (window incomplete)", flush=True)
            continue
        lost = len(P_VALUES) - len(earlier)
        lost_total += lost
        read_rounds += 1
        mean = router.session_drift_mean(list(earlier) + [CURRENT_P], WINDOW)
        decision = "no signal (<3 values)" if mean is None else ("ask" if mean <= LIMIT else "allow (drift ask missed)")
        outcome[decision] += 1
        if r < 5 or lost:
            print(f"round {r}: on_task values read={sorted(earlier)} lost={lost} mean={mean} -> {decision}", flush=True)
    print(f"SUMMARY rounds={a.rounds} elapsed={time.time()-t0:.1f}s")
    print(f"  judgment lines lost (rounds where session_on_task returned: {read_rounds}): "
          f"{rate(lost_total, read_rounds * len(P_VALUES))}")
    print(f"  rounds where session_on_task raised IncompleteWindow: {rate(incomplete, a.rounds)}")
    for k, v in sorted(outcome.items()):
        print(f"  {k}: {rate(v, a.rounds)}")
    print("  correct result every round: ask")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
