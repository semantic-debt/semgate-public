"""Stress test: approval scope under concurrency (finding U1 in formal/REPORT.md).

An approval (`semgate feedback allow`) now applies only to the exact command,
the same session, the same project, before its expiry
(semgate/feedback.py FeedbackStore._applies). Reads and writes of
feedback.jsonl take a cross-process lock (semgate/filelock.py); a read that
cannot get the lock fails closed (judge.py human_override: an allow becomes
an ask, reason "feedback_unreadable").

Setup (temp dirs, fake provider with the ALLOWING answers of stress_hook.py,
policies/router_policy_dev.json, mode enforce, block_when_unsure true, bash
NOT in auto_allow_tools, feedback enabled). The feedback store holds:
  - a scoped approval for `rm -rf dist`, sess-A, project root realpath(projA)
    (FeedbackStore.record, schema 2, expires in 4 h);
  - an expired approval for `rm -rf dist`, sess-B, projA (now = time.time() - 5 h);
  - a legacy unscoped allow line for `rm -rf dist` (no schema, appended raw).

Then N spawn processes x K decisions each call semgate.claude_hook.run(event,
config, "claude", meta) in-process, then antigravity_hook.record_host_response
(what claude_hook.main does next: block_when_unsure and the host_response
ledger line), all started at once with a barrier. A decision counts as an
allow if run() or the host answer is allow. The
events cycle over (sess-A, projA), (sess-B, projA), (sess-A, projB),
(sess-C, projC) and the commands `rm -rf dist` / `rm -rf dist/`. At the same
time one extra writer process appends 200 more approvals (FeedbackStore.record)
for other commands and sessions, to contend on the feedback lock.

Counts:
  allows for (sess-A, projA, `rm -rf dist`)   expected: all of them
  allows anywhere else                        must be 0
  errors                                      exceptions raised by run()
  fail-closed answers                         reason names feedback_unreadable / semgate failure
Also checks the shared files afterwards: feedback.jsonl has 3 + 200 records
and no malformed line; the ledger has one host_response per decision and no
malformed line. No command is executed: commands are strings in JSON.

    .venv\\Scripts\\python.exe formal\\repro\\stress_feedback_scope.py --procs 8 --decisions 40
"""
from __future__ import annotations

import argparse
import json
import multiprocessing as mp
import os
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, isolate, rate, scan_jsonl  # noqa: E402
from stress_hook import ALLOWING  # noqa: E402

COMBOS = [("sess-A", "projA"), ("sess-B", "projA"), ("sess-A", "projB"), ("sess-C", "projC")]
COMMANDS = ["rm -rf dist", "rm -rf dist/"]
IN_SCOPE = ("sess-A", "projA", "rm -rf dist")
WRITER_RECORDS = 200


def child(cfg_path: str, tmp: str, pid: int, decisions: int, barrier, out) -> None:
    from semgate import claude_hook
    from semgate.antigravity_hook import load_json, record_host_response
    config = load_json(cfg_path)
    results = []
    barrier.wait()
    for j in range(decisions):
        k = pid * decisions + j
        session, proj = COMBOS[k % len(COMBOS)]
        cmd = COMMANDS[(k // len(COMBOS)) % len(COMMANDS)]
        ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd},
              "session_id": session, "tool_use_id": f"toolu_p{pid}_d{j}", "cwd": str(Path(tmp) / proj)}
        try:
            meta: dict = {}
            res = claude_hook.run(ev, config, "claude", meta)
            # Same as claude_hook.main: the host answer (block_when_unsure applied) and its ledger line.
            host = record_host_response({"conversationId": session, "stepIdx": ev["tool_use_id"]}, config, res, meta)
            host_dec = claude_hook._TO_HOST.get(str(host.get("decision")), "ask")
            dec = "allow" if "allow" in (res["decision"], host_dec) else host_dec
            results.append((session, proj, cmd, dec, (res.get("reason", "") + " | host: " + str(host.get("reason", "")))[:300]))
        except Exception as exc:
            results.append((session, proj, cmd, "error", f"{type(exc).__name__}: {exc}"[:200]))
    out.put(results)


def writer(fb_path: str, tmp: str, n: int, barrier, out) -> None:
    from semgate.feedback import FeedbackStore
    store = FeedbackStore(fb_path)
    errors = 0
    barrier.wait()
    for i in range(n):
        proj = str(Path(tmp) / ("projA", "projB", "projC")[i % 3])
        session = ("sess-A", "sess-B", "sess-C", f"sess-W{i % 7}")[i % 4]
        try:
            store.record("allow", "bash", {"command": f"rm -rf other-{i}"}, note=f"writer-{i}",
                         session_id=session, project_root=proj)
        except Exception:
            errors += 1
    out.put(("writer", errors))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--decisions", type=int, default=40, help="decisions per process")
    a = ap.parse_args()
    tmp = isolate("semgate-formal-fbscope-")
    for p in ("projA", "projB", "projC"):
        (tmp / p / "dist").mkdir(parents=True)
    grant = tmp / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    fb = tmp / "feedback.jsonl"
    ledger = tmp / "ledger.jsonl"
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(REPO / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(ledger),
           "feedback": {"enabled": True, "feedback_file": str(fb)},
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": True}}
    cfg_path = tmp / "semgate.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

    from semgate.feedback import FeedbackStore, _key
    from semgate.history import normalize_args
    store = FeedbackStore(str(fb))
    store.record("allow", "bash", {"command": "rm -rf dist"}, note="scoped sess-A projA",
                 session_id="sess-A", project_root=os.path.realpath(str(tmp / "projA")))
    store.record("allow", "bash", {"command": "rm -rf dist"}, note="expired sess-B projA",
                 session_id="sess-B", project_root=os.path.realpath(str(tmp / "projA")), now=time.time() - 5 * 3600)
    legacy = {"record_type": "feedback", "decision": "allow", "tool": "bash",
              "action_key": _key("bash", {"command": "rm -rf dist"}),
              "args_normalized": normalize_args({"command": "rm -rf dist"}),
              "reviewer": "operator", "note": "legacy unscoped", "ts": "2026-09-23T00:00:00Z"}
    with fb.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(legacy) + "\n")

    ctx = mp.get_context("spawn")
    barrier = ctx.Barrier(a.procs + 1)
    out = ctx.Queue()
    t0 = time.time()
    ps = [ctx.Process(target=child, args=(str(cfg_path), str(tmp), i, a.decisions, barrier, out)) for i in range(a.procs)]
    ps.append(ctx.Process(target=writer, args=(str(fb), str(tmp), WRITER_RECORDS, barrier, out)))
    for p in ps:
        p.start()
    results = []
    writer_errors = None
    for _ in ps:
        item = out.get()
        if isinstance(item, tuple) and item[0] == "writer":
            writer_errors = item[1]
        else:
            results.extend(item)
    for p in ps:
        p.join()
    elapsed = time.time() - t0

    by = Counter()
    in_scope_total = in_scope_allow = out_scope_allow = errors = fail_closed = 0
    examples = []
    for session, proj, cmd, dec, reason in results:
        by[(session, proj, cmd, dec)] += 1
        scoped = (session, proj, cmd) == IN_SCOPE
        in_scope_total += scoped
        if dec == "allow":
            if scoped:
                in_scope_allow += 1
            else:
                out_scope_allow += 1
                if len(examples) < 5:
                    examples.append((session, proj, cmd, reason))
        if dec == "error":
            errors += 1
            if len(examples) < 5:
                examples.append((session, proj, cmd, reason))
        if "feedback_unreadable" in reason or "semgate failure" in reason:
            fail_closed += 1
    for key in sorted(by):
        print(f"{key[0]} {key[1]} {key[2]!r:15} -> {key[3]:5} x{by[key]}")
    for ex in examples:
        print(f"example: {ex}")

    fgood, fbad = scan_jsonl(fb)
    lgood, lbad = scan_jsonl(ledger)
    hr = [g for g in lgood if g.get("record_type") == "host_response"]
    n = len(results)
    print(f"SUMMARY procs={a.procs} decisions/proc={a.decisions} decisions={n} writer approvals={WRITER_RECORDS} "
          f"elapsed={elapsed:.1f}s")
    print(f"  allows for (sess-A, projA, 'rm -rf dist'): {rate(in_scope_allow, in_scope_total)} (expected all)")
    print(f"  allows anywhere else: {out_scope_allow} of {n - in_scope_total} (must be 0)")
    print(f"  errors: {errors}; fail-closed answers (feedback_unreadable / semgate failure): {fail_closed}; "
          f"writer errors: {writer_errors}")
    print(f"  feedback.jsonl records: {len(fgood)} (expected {3 + WRITER_RECORDS}); malformed lines: {len(fbad)}")
    print(f"  ledger host_response lines: {len(hr)} (expected {n}); ledger malformed lines: {len(lbad)}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
