"""Repro (TLA+ SemgateF6: E3 AgentContentOnly / E4 EditedStaysIneligible):
content that someone else writes between the end of the agent's tool call and
the PostToolUse hook is recorded as "created by the agent, unchanged".

Before the fix, record_post hashed the file as it was WHEN THE POST HOOK
RAN, not the content the tool wrote. If the user's editor, a formatter, or a
parallel subagent wrote the file in that window, the user's content got a
`created` record and a snapshot. A later `rm` of that file was then judged as
restorable (`agent_created`): the destructive gate was relaxed and the model
decided. The judge was told a false fact ("created by the agent in this
session").

Now (semgate/agentfiles.py): the pre hook passes expected={target: sha256s}
to AgentFiles.record_pre (agentfiles.expected_hashes of the Write tool's
content: the text and its CRLF variant), and AgentFiles.record_post records
a path as `created` ONLY if its current sha256 is one of them; otherwise it
writes a `not_recorded` record. So scenario C should now match B.

Real `python -m semgate.claude_hook` processes (pre + post + pre), fake
provider, temp git repo, temp HOME and agent_files.dir. Nothing is executed
by semgate; the "tool run" and the "user edit" are file writes done here.

Scenarios (file notes.txt, untracked):
  A  agent Write -> post hook -> rm            : allow expected (F6 works)
  B  agent Write -> post hook -> user edit -> rm: ask (edit after post: correct)
  C  agent Write -> user edit -> post hook -> rm: was allow (the bug); expected now: same as B

    .venv\\Scripts\\python.exe formal\\repro\\f6_post_window.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from common import REPO, isolate  # noqa: E402

EDIT = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 1.0, "confidence": 1.0}, "user_asked": 0.9,
        "on_task": 0.9, "executes": {"value": 0.0, "confidence": 1.0}}


def main() -> int:
    tmp = isolate("semgate-formal-f6-")
    grant = tmp / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}), encoding="utf-8")
    results = {}
    for scenario in ("A", "B", "C"):
        d = tmp / scenario
        repo = d / "repo"
        repo.mkdir(parents=True)
        git = lambda *a: subprocess.run(["git", *a], cwd=repo, check=True, capture_output=True)  # noqa: E731
        git("init", "-q"); git("config", "user.email", "t@t"); git("config", "user.name", "t")
        (repo / "app.py").write_text("print(1)\n")
        git("add", "."); git("commit", "-qm", "init")
        cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(REPO / "policies" / "router_policy_dev.json"),
               "provider": "fake", "fake_answers": EDIT, "ledger_file": str(d / "ledger.jsonl"), "git_facts": True,
               "agent_files": {"enabled": True, "dir": str(d / "sg")},
               "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "write"], "block_when_unsure": False}}
        cfg_path = d / "semgate.json"
        cfg_path.write_text(json.dumps(cfg), encoding="utf-8")

        def hook(ev):
            p = subprocess.run([sys.executable, "-m", "semgate.claude_hook", "--config", str(cfg_path)], input=json.dumps(ev),
                               capture_output=True, text=True, cwd=str(REPO), env=dict(os.environ), timeout=120)
            return json.loads(p.stdout)

        target = repo / "notes.txt"
        write_ev = {"hook_event_name": "PreToolUse", "tool_name": "Write",
                    "tool_input": {"file_path": str(target), "content": "agent draft\n"},
                    "session_id": "cs", "tool_use_id": "tu1", "cwd": str(repo)}
        hook(write_ev)                                           # PreToolUse: pre record (existed = false)
        target.write_text("agent draft\n", encoding="utf-8")     # the Write tool runs
        if scenario == "C":
            target.write_text("user notes, typed in the editor\n", encoding="utf-8")   # before the post hook
        hook(dict(write_ev, hook_event_name="PostToolUse", tool_response={"success": True}))   # PostToolUse
        if scenario == "B":
            target.write_text("user notes, typed in the editor\n", encoding="utf-8")   # after the post hook
        out = hook({"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": {"command": "rm notes.txt"},
                    "session_id": "cs", "tool_use_id": "tu2", "cwd": str(repo)})["hookSpecificOutput"]
        rec = [json.loads(l) for l in (d / "sg" / "agent_files").glob("*.jsonl").__next__().read_text(encoding="utf-8").splitlines()]
        created = [r for r in rec if r.get("record_type") == "created"]
        results[scenario] = out["permissionDecision"]
        print(f"{scenario}: file now = {target.read_text(encoding='utf-8').strip()!r}")
        print(f"   created record sha = {created[0]['sha256'][:12] if created else None} "
              f"(sha of 'agent draft' = {__import__('hashlib').sha256(b'agent draft' + os.linesep.encode()).hexdigest()[:12]} or "
              f"{__import__('hashlib').sha256(b'agent draft' + chr(10).encode()).hexdigest()[:12]})")
        print(f"   rm notes.txt -> {out['permissionDecision']}: {out.get('permissionDecisionReason', '')[:150]}")
    verdict = "it equals B: fixed" if results["C"] == results["B"] else (
        "it equals A: the bug" if results["C"] == results["A"] else "it equals neither")
    print(f"SUMMARY A={results['A']} B={results['B']} C={results['C']} (C should equal B; {verdict})")
    print(f"temp dir: {tmp}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
