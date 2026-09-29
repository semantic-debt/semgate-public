"""A contained agent loop that obeys Semgate in enforce mode.

For each proposed command the loop asks the Semgate gate (the same
antigravity_hook.run used by the real harness). Then, unlike Antigravity 1.2.7
which prompts even on allow, THIS loop honours the decision directly:

  allow      -> run the command in the throwaway workspace
  deny       -> never run it
  ask / force_ask -> hold: run only if --interactive and the operator says yes

Meant to run inside the Docker image in this folder, against /sandbox/workspace,
so a command that does run cannot touch the real machine. It executes real
commands, so do not run it outside a container.

Needs TYPESAFE_API_KEY in the environment for the Jev router.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, "/app")
from semgate.antigravity_hook import history_path, load_json, run  # noqa: E402
from semgate.history import ToolHistory  # noqa: E402

RUN, HOLD, BLOCK = "allow", "ask", "deny"


def gate(event, config):
    result = run(event, config)
    d = result.get("decision")
    if d == "allow":
        return RUN, result.get("reason", "")
    if d in ("deny", "deny_unless_prior_grant"):
        return BLOCK, result.get("reason", "")
    return HOLD, result.get("reason", "")  # ask / force_ask


def execute(command: str, workspace: Path) -> tuple[int, str]:
    proc = subprocess.run(["bash", "-lc", command], cwd=str(workspace),
                          capture_output=True, text=True, timeout=120)
    out = (proc.stdout + proc.stderr).strip()
    return proc.returncode, out[:400]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", default="/sandbox/semgate.enforce.json")
    parser.add_argument("--tasks", default="/sandbox/tasks.jsonl")
    parser.add_argument("--workspace", default="/sandbox/workspace")
    parser.add_argument("--interactive", action="store_true", help="prompt the operator on a hold")
    parser.add_argument("--dry-run", action="store_true", help="show gate decisions only; never execute (safe outside a container)")
    args = parser.parse_args()

    config = load_json(args.config)
    workspace = Path(args.workspace); workspace.mkdir(parents=True, exist_ok=True)
    store = history_path(config)
    history = ToolHistory(store) if store else None
    tasks = [json.loads(l) for l in Path(args.tasks).read_text(encoding="utf-8").splitlines() if l.strip()]

    counts = {RUN: 0, HOLD: 0, BLOCK: 0}
    for i, task in enumerate(tasks):
        command = str(task["command"])
        event = {
            "toolCall": {"name": "run_command", "args": {"CommandLine": command, "Cwd": args.workspace}},
            "stepIdx": i, "conversationId": "sandbox-loop", "workspacePaths": [args.workspace],
            "user_message": task.get("user_message", ""),
        }
        action, reason = gate(event, config)
        counts[action] += 1
        print(f"\n[{i}] {command}")
        print(f"    gate: {action.upper()}  ({reason[:120]})")

        if args.dry_run:
            continue
        approved = action == RUN
        if action == HOLD and args.interactive:
            approved = input("    hold: run this command? [y/N] ").strip().lower() == "y"
        if approved:
            rc, out = execute(command, workspace)
            if history is not None:
                history.record_executed("sandbox-loop", i, error="" if rc == 0 else f"exit {rc}")
            print(f"    ran -> exit {rc}: {out[:200]}")
        elif action == BLOCK:
            print("    blocked, not run")
        else:
            print("    held, not run")

    print(f"\nsummary: ran={counts[RUN]} held={counts[HOLD]} blocked={counts[BLOCK]}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
