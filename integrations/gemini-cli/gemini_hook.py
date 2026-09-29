#!/usr/bin/env python3
"""Real Semgate BeforeTool hook for Gemini CLI. Keep this one.

Reads a Gemini BeforeTool event on stdin, judges the shell command with the
Semgate router (Jev), and blocks the dangerous ones. In YOLO the agent auto-runs
everything, so this hook is the safety net: it can only DENY (Gemini ignores a
hook "allow"), which is exactly what YOLO needs.

Output: {"decision":"deny","reason":...} to block, or {} to let it run.

Profiles (env SEMGATE_GEMINI_PROFILE):
  safety-net (default): block only clear dangers - hard rules, human gates,
                        and a confident semantic deny. Benign work flows.
  strict:               also block anything the judge is unsure about (ask).
                        Only confident-benign runs. Safest, more friction.

Fails CLOSED: if the judge or Jev errors, the command is blocked, because in
YOLO an un-judged command would otherwise run unchecked.
Env: TYPESAFE_API_KEY (required for live judging), SEMGATE_GEMINI_POLICY,
SEMGATE_GEMINI_PURPOSE.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

DEFAULT_PURPOSE = (
    "Software development in this project: reading files, listing and searching, building, running "
    "tests and development tools, and editing files inside the project. Not authorized: reading or "
    "sending credentials, network exfiltration, installing system software, or changing the system."
)


def block(reason: str) -> None:
    print(json.dumps({"decision": "deny", "reason": reason[:500]}))


def allow_run() -> None:
    print("{}")  # not a block; in YOLO the agent runs it


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except Exception:
        allow_run(); return 0  # not our event shape; do not interfere
    if event.get("hook_event_name") != "BeforeTool" or event.get("tool_name") != "run_shell_command":
        allow_run(); return 0
    command = str((event.get("tool_input") or {}).get("command", "")).strip()
    if not command:
        allow_run(); return 0

    try:
        from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant
        from semgate.judge import judge
        from semgate.policy import Policy
        from semgate.providers.typesafe import TypeSafeProvider

        policy = Policy.load(os.environ.get("SEMGATE_GEMINI_POLICY", str(ROOT / "policies" / "router_policy_v3.json")))
        grant = UserGrant(grant_id="gemini-hook", principal="operator",
                          purpose=os.environ.get("SEMGATE_GEMINI_PURPOSE", DEFAULT_PURPOSE),
                          expires_at="2099-01-01T00:00:00Z", provenance="semgate gemini hook")
        cwd = str(event.get("cwd") or Path.cwd())
        envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}),
                            grant=grant, environment=Environment(project_root=cwd, cwd=cwd, harness="gemini-cli"))
        decision = judge(envelope, policy, provider=TypeSafeProvider())
    except Exception as exc:
        block(f"semgate hook error; blocking to stay safe: {type(exc).__name__}: {exc}")
        return 0

    profile = os.environ.get("SEMGATE_GEMINI_PROFILE", "safety-net")
    d, stage = decision.decision, decision.stage
    reason = f"semgate: {stage}/{d}; " + ("; ".join(decision.reasons) or "no reason")
    if d == "deny":
        block(reason)
    elif profile == "strict" and d == "ask":
        block("block_when_unsure: " + reason)
    else:
        allow_run()  # allow or (in safety-net) ask -> let YOLO run it
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
