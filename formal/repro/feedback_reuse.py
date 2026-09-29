"""Repro (deterministic, no concurrency): scope of an exact-command approval
(`semgate feedback allow "<command>"`), finding U1 in formal/REPORT.md.

Before the fix an approval was never consumed and had no scope: one record
allowed that exact text forever, in any session and any project.

Now (semgate/feedback.py):
  - FeedbackStore.record("allow", ...) REQUIRES session_id and project_root
    (ValueError otherwise) and writes schema 2 with an expiry (default 4 h);
  - FeedbackStore._applies honours an allow only for the exact command text,
    the same session, the same project (os.path.realpath + normcase), before
    its expiry. Reuse inside that scope is by design (owner decision);
  - legacy allow records (no "schema") are ignored;
  - the CLI (semgate/cli.py _cmd_feedback, feedback.blocked_candidates) binds
    the approval to the most recent session of the current project whose
    ledger shows the exact command was asked/blocked; exit 2 and nothing
    written when there is none.

Steps (real `python -m semgate.claude_hook` processes and the real CLI, fake
provider, temp dirs; commands are only judged, never executed):
   1 sess-A projA `rm -rf dist`             -> deny (block_when_unsure)
   2 sess-B projB `rm -rf dist`             -> deny
   3 CLI: semgate feedback allow "rm -rf dist" --config ..., cwd projA (output printed)
   4 sess-A projA `rm -rf dist`             -> allow (the approved use)
   5 sess-A projA `rm -rf dist` again       -> allow (reuse in scope, by design)
   6 sess-B projB `rm -rf dist`             -> deny (other session, other project)
   7 sess-B projA `rm -rf dist`             -> deny (other session, same project)
   8 sess-A projA `rm -rf dist/`            -> deny (not the exact text)
   9 sess-C projA `rm -rf dist`: ask, then an approval whose expiry passed
     (FeedbackStore.record with now = time.time() - 5 h)  -> deny
  10 sess-A projA `rm -rf build`: ask, then a legacy unscoped allow line
     (pre-schema-2 shape, appended raw)                  -> deny

    .venv\\Scripts\\python.exe formal\\repro\\feedback_reuse.py
"""
from __future__ import annotations

import json
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, isolate  # noqa: E402
from stress_hook import ALLOWING  # noqa: E402


def main() -> int:
    tmp = isolate("semgate-formal-feedback-")
    for p in ("projA", "projB"):
        (tmp / p / "dist").mkdir(parents=True)
    (tmp / "projA" / "build").mkdir()
    grant = tmp / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    fb = tmp / "feedback.jsonl"
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(REPO / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(tmp / "ledger.jsonl"),
           "feedback": {"enabled": True, "feedback_file": str(fb)},
           "enforcement": {"enabled": True, "auto_allow_tools": ["read"], "block_when_unsure": True}}
    cfg_path = tmp / "semgate.json"
    cfg_path.write_text(json.dumps(cfg), encoding="utf-8")
    results = []     # (step, in_scope, expected, got)

    def hook(step: str, session: str, proj: str, cmd: str, tid: str, expected: str, in_scope: bool = False) -> None:
        ev = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": cmd},
              "session_id": session, "tool_use_id": tid, "cwd": str(tmp / proj)}
        p = subprocess.run([sys.executable, "-m", "semgate.claude_hook", "--config", str(cfg_path)], input=json.dumps(ev),
                           capture_output=True, text=True, cwd=str(REPO), timeout=120)
        out = json.loads(p.stdout)["hookSpecificOutput"]
        got = out["permissionDecision"]
        results.append((step, in_scope, expected, got))
        flag = "" if got == expected else "   <-- UNEXPECTED"
        print(f"{step:>2} {session} {proj}  {cmd:13} -> {got:5}  {out.get('permissionDecisionReason', '')[:100]}"
              f"  (expected {expected}){flag}", flush=True)

    hook("1", "sess-A", "projA", "rm -rf dist", "t1", "deny")
    hook("2", "sess-B", "projB", "rm -rf dist", "t2", "deny")
    cli = subprocess.run([sys.executable, "-m", "semgate", "feedback", "allow", "rm -rf dist", "--config", str(cfg_path)],
                         capture_output=True, text=True, cwd=str(tmp / "projA"), timeout=120)
    print(f" 3 CLI (cwd projA): semgate feedback allow \"rm -rf dist\" --config semgate.json  -> exit {cli.returncode}")
    for line in (cli.stdout + cli.stderr).splitlines():
        print(f"     | {line}")
    hook("4", "sess-A", "projA", "rm -rf dist", "t3", "allow", in_scope=True)
    hook("5", "sess-A", "projA", "rm -rf dist", "t4", "allow", in_scope=True)
    hook("6", "sess-B", "projB", "rm -rf dist", "t5", "deny")
    hook("7", "sess-B", "projA", "rm -rf dist", "t6", "deny")
    hook("8", "sess-A", "projA", "rm -rf dist/", "t7", "deny")

    from semgate.feedback import FeedbackStore, _key
    from semgate.history import normalize_args
    hook("9a", "sess-C", "projA", "rm -rf dist", "t8", "deny")
    rec = FeedbackStore(str(fb)).record("allow", "bash", {"command": "rm -rf dist"}, reviewer="operator",
                                        note="expired approval", session_id="sess-C", project_root=str(tmp / "projA"),
                                        now=time.time() - 5 * 3600)
    print(f"    approval for sess-C projA written with ts {rec['ts']}, expires_at {rec['expires_at']} (already passed)")
    hook("9", "sess-C", "projA", "rm -rf dist", "t9", "deny")

    hook("10a", "sess-A", "projA", "rm -rf build", "t10", "deny")
    legacy = {"record_type": "feedback", "decision": "allow", "tool": "bash",
              "action_key": _key("bash", {"command": "rm -rf build"}),
              "args_normalized": normalize_args({"command": "rm -rf build"}),
              "reviewer": "operator", "note": "legacy unscoped approval", "ts": "2026-09-23T00:00:00Z"}
    with fb.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(legacy) + "\n")
    print("    legacy allow line (no schema, no session, no project, no expiry) appended raw for `rm -rf build`")
    hook("10", "sess-A", "projA", "rm -rf build", "t11", "deny")

    in_scope_allows = sum(1 for _, s, _, g in results if s and g == "allow")
    in_scope_total = sum(1 for _, s, _, _ in results if s)
    out_scope_allows = [st for st, s, _, g in results if not s and g == "allow"]
    unexpected = [st for st, _, e, g in results if g != e]
    print(f"feedback file lines: {len(fb.read_text(encoding='utf-8').splitlines())}")
    print(f"SUMMARY allows in scope: {in_scope_allows}/{in_scope_total}; allows out of scope: {len(out_scope_allows)} "
          f"(must be 0){' steps ' + ','.join(out_scope_allows) if out_scope_allows else ''}; "
          f"CLI exit {cli.returncode}; steps with an unexpected answer: {len(unexpected)}"
          f"{' (' + ','.join(unexpected) + ')' if unexpected else ''}")
    print(f"temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
