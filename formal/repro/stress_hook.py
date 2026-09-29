"""Stress test: N real `python -m semgate.claude_hook` processes at once, on
the same temp ledger / tool history / deny-streak state file.

This is what Claude Code does when parallel tool calls (read-only tools, or
subagents) each start a PreToolUse hook. Provider: the offline fake provider
with fixed answers (no network). Commands are only judged, never executed.

Per round, N processes start together (one event each, own tool_use_id).
Half the calls send `rm -rf /` (hard-deny rule -> "deny", the command is a
string in JSON, nothing runs), half send `git status` (read-only -> "allow").

Checks after each round:
  ledger   exactly one complete host_response line per tool_use_id, with the
           same decision the process printed on stdout; one judgment per call
  history  one pending record per tool_use_id (record_outcomes: true)
  streak   deny_streak.json parses, and its `total` for the session equals the
           number of deny answers printed (lost updates show as a lower total)

    .venv\\Scripts\\python.exe formal\\repro\\stress_hook.py --procs 8 --rounds 25
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, isolate, rate, scan_jsonl  # noqa: E402

ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.02, "executes": {"value": 0.0, "confidence": 1.0},
            "leaks_secrets": 0.01, "remote_code": 0.01, "needs_root": 0.01, "changes_running_system": 0.01}


def make_config(d: Path) -> Path:
    grant = d / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    cfg = {
        "mode": "enforce", "grant_file": str(grant),
        "policy_file": str(REPO / "policies" / "router_policy_dev.json"),
        "provider": "fake", "fake_answers": ALLOWING,
        "ledger_file": str(d / "ledger.jsonl"),
        "record_outcomes": True,
        "auto_allow_learned": {"enabled": False, "history_file": str(d / "tool_history.jsonl")},
        "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False,
                        "deny_escalation": {"enabled": True, "consecutive": 1000, "total": 100000,
                                            "state_file": str(d / "deny_streak.json")}},
    }
    p = d / "semgate.json"
    p.write_text(json.dumps(cfg), encoding="utf-8")
    return p


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--procs", type=int, default=8)
    ap.add_argument("--rounds", type=int, default=25)
    a = ap.parse_args()
    tmp = isolate("semgate-formal-hook-")
    totals = Counter()
    t0 = time.time()
    for r in range(a.rounds):
        d = tmp / f"round{r}"
        d.mkdir()
        cfg = make_config(d)
        events = []
        for i in range(a.procs):
            cmd = "rm -rf /" if i % 2 == 0 else "git status"
            events.append({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd},
                           "session_id": "sess-A", "tool_use_id": f"toolu_r{r}_p{i}", "cwd": str(d)})
        procs = [subprocess.Popen([sys.executable, "-m", "semgate.claude_hook", "--config", str(cfg)],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  cwd=str(REPO), text=True) for _ in events]
        # Write all stdins, then close them together so the processes judge at about the same time.
        for p, ev in zip(procs, events):
            p.stdin.write(json.dumps(ev))
        for p in procs:
            p.stdin.close()
        printed = {}
        for p, ev in zip(procs, events):
            out = p.stdout.read()
            p.wait(timeout=120)
            printed[ev["tool_use_id"]] = json.loads(out)["hookSpecificOutput"]["permissionDecision"]
        good, bad = scan_jsonl(d / "ledger.jsonl")
        hr = [g for g in good if g.get("record_type") == "host_response"]
        judg = [g for g in good if g.get("record_type") == "judgment"]
        by_id = Counter(g.get("step_idx") for g in hr)
        missing = [t for t in printed if by_id.get(t, 0) == 0]
        dup = [t for t, c in by_id.items() if c > 1]
        mismatch = [g["step_idx"] for g in hr if g.get("step_idx") in printed
                    and {"allow": "allow", "deny": "deny", "ask": "ask", "force_ask": "ask"}.get(g["native"]["decision"]) != printed[g["step_idx"]]]
        hgood, hbad = scan_jsonl(d / "tool_history.jsonl")
        pend = Counter(g.get("step_idx") for g in hgood if g.get("record_type") == "pending")
        pend_missing = [t for t in printed if pend.get(t, 0) == 0]
        denies = sum(1 for v in printed.values() if v == "deny")
        streak_state = "ok"
        streak_total = None
        try:
            data = json.loads((d / "deny_streak.json").read_text(encoding="utf-8"))
            streak_total = int(data["sess-A"]["total"])
            if streak_total != denies:
                streak_state = "lost_update"
        except FileNotFoundError:
            streak_state = "missing"
        except Exception as exc:
            streak_state = f"corrupt({type(exc).__name__})"
        totals["calls"] += len(printed)
        totals["hr_missing"] += len(missing)
        totals["hr_dup"] += len(dup)
        totals["hr_mismatch"] += len(mismatch)
        totals["ledger_torn"] += len(bad)
        totals["judgments_expected"] += len(printed)
        totals["judgments_found"] += len(judg)
        totals["pending_missing"] += len(pend_missing)
        totals["history_torn"] += len(hbad)
        totals["deny_calls"] += denies
        totals["streak_counted"] += streak_total or 0
        totals[f"streak_{streak_state.split('(')[0]}"] += 1
        print(f"round {r}: calls={len(printed)} host_response missing={len(missing)} dup={len(dup)} mismatch={len(mismatch)} "
              f"ledger_torn={len(bad)} judgments={len(judg)}/{len(printed)} pending_missing={len(pend_missing)} "
              f"history_torn={len(hbad)} denies={denies} streak_total={streak_total} streak={streak_state}", flush=True)
    c = totals["calls"]
    print(f"SUMMARY procs={a.procs} rounds={a.rounds} calls={c} elapsed={time.time()-t0:.1f}s")
    print(f"  returned decisions with no host_response line: {rate(totals['hr_missing'], c)}")
    print(f"  host_response duplicates: {totals['hr_dup']}; decision mismatches: {totals['hr_mismatch']}; ledger torn lines: {totals['ledger_torn']}")
    print(f"  judgment lines found: {totals['judgments_found']}/{totals['judgments_expected']}")
    print(f"  pending history records missing: {rate(totals['pending_missing'], c)}; history torn lines: {totals['history_torn']}")
    print(f"  deny_streak: deny answers={totals['deny_calls']} counted={totals['streak_counted']} "
          f"(lost {rate(totals['deny_calls'] - totals['streak_counted'], totals['deny_calls'])}); "
          f"rounds ok={totals['streak_ok']} lost_update={totals['streak_lost_update']} corrupt={totals['streak_corrupt']} missing={totals['streak_missing']}")
    print(f"  temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
