"""Semgate -> Gemini CLI policy writer. Semgate is the criterion; Gemini enforces.

Judges each candidate command with the Semgate router (Jev) and writes an
`allow` rule for every command it confidently clears to Gemini CLI's own native
policy file, `~/.gemini/policies/semgate.toml`. Gemini reads that file at
startup and auto-runs matching commands with no prompt. Commands that Semgate
sends to ask or deny are never written, so they keep prompting.

No fork, no launcher, no hook: Semgate only decides which commands earn a
standing native allow rule. This never executes any command.

Rule format matches what Gemini CLI writes itself in policies/auto-saved.toml:
  [[rule]]
  toolName = "run_shell_command"
  decision = "allow"
  priority = 100
  commandPrefix = [ "git", "status" ]      # prefix tokens (default)
Or, with --exact, command-exact matching:
  commandRegex = "^git status --short$"

Writing this file may trigger Gemini's one-time "policies changed, accept?"
prompt on next launch (its integrity check); accept it once. `tools.allowed`
and policy files take effect at startup, not mid-session.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant  # noqa: E402
from semgate.judge import judge  # noqa: E402
from semgate.policy import Policy  # noqa: E402

DEFAULT_PURPOSE = (
    "Software development in this project: reading files, listing and searching, building, running "
    "tests and development tools, and editing files inside the project. Not authorized: reading or "
    "sending credentials, network exfiltration, installing system software, or changing the system."
)
GEMINI_POLICIES = Path.home() / ".gemini" / "policies"
MANAGED_FILE = "semgate.toml"
FLAG_OR_OPERAND = re.compile(r"^[-/]|[\\/.]|[\"']|[*?$`|<>]")


def prefix_tokens(command: str) -> list[str]:
    """Leading command + subcommand words, stopping at the first flag/operand.
    `git status --short` -> ['git','status']; `cat pyproject.toml` -> ['cat']."""
    tokens: list[str] = []
    for tok in command.strip().split():
        if FLAG_OR_OPERAND.search(tok) or not tok.isascii() or not re.fullmatch(r"[A-Za-z0-9_.:-]+", tok):
            break
        tokens.append(tok)
        if len(tokens) >= 3:
            break
    return tokens or [command.strip().split()[0]]


def rule_for(command: str, exact: bool, priority: int) -> str:
    head = f'[[rule]]\ntoolName = "run_shell_command"\ndecision = "allow"\npriority = {priority}\n'
    if exact:
        return head + f'commandRegex = "^{re.escape(command.strip())}$"\n'
    toks = ", ".join(f'"{t}"' for t in prefix_tokens(command))
    return head + f"commandPrefix = [ {toks} ]\n"


def judge_command(command: str, user_message: str, policy: Policy, provider) -> "tuple[str, str]":
    grant = UserGrant(grant_id="gemini-writer", principal="operator", purpose=DEFAULT_PURPOSE,
                      expires_at="2099-01-01T00:00:00Z", provenance="semgate gemini policy writer")
    env = Environment(project_root=str(Path.cwd()), cwd=str(Path.cwd()), harness="gemini-cli")
    envelope = Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}),
                        grant=grant, environment=env, user_message=user_message)
    d = judge(envelope, policy, provider=provider)
    return d.decision, "; ".join(d.reasons)


def load_commands(args) -> list[tuple[str, str]]:
    if args.commands_file:
        rows = [json.loads(l) for l in Path(args.commands_file).read_text(encoding="utf-8").splitlines() if l.strip()]
        return [(str(r["command"]), str(r.get("user_message", ""))) for r in rows]
    return [(c, "") for c in args.command]


def main() -> int:
    parser = argparse.ArgumentParser(description="Write Gemini CLI allow rules for commands Semgate clears.")
    parser.add_argument("command", nargs="*", help="one or more commands to judge")
    parser.add_argument("--commands-file", help="JSONL with {command, user_message} per line")
    parser.add_argument("--policy", default=str(ROOT / "policies" / "router_policy_v3.json"))
    parser.add_argument("--exact", action="store_true", help="command-exact rules (commandRegex) instead of prefix")
    parser.add_argument("--priority", type=int, default=100)
    parser.add_argument("--out", default=str(GEMINI_POLICIES / MANAGED_FILE))
    parser.add_argument("--dry-run", action="store_true", help="judge and show what would be written; write nothing")
    args = parser.parse_args()

    commands = load_commands(args)
    if not commands:
        parser.error("give commands as arguments or via --commands-file")
    from semgate.providers.typesafe import TypeSafeProvider
    policy, provider = Policy.load(args.policy), TypeSafeProvider()

    allowed, skipped = [], []
    for command, user_message in commands:
        decision, reason = judge_command(command, user_message, policy, provider)
        if decision == "allow":
            allowed.append(command)
            print(f"ALLOW  {command}")
        else:
            skipped.append((command, decision))
            print(f"{decision.upper():5}  {command}  ({reason[:80]})")

    header = ("# Managed by Semgate. Do not edit by hand.\n"
              "# Each rule is a command Semgate's Jev router confidently cleared.\n"
              "# Regenerated on each run; commands sent to ask/deny are omitted.\n\n")
    body = header + "\n".join(rule_for(c, args.exact, args.priority) for c in allowed)
    print(f"\n{'[dry-run] would write' if args.dry_run else 'wrote'} {len(allowed)} allow rule(s); skipped {len(skipped)}")
    if args.dry_run:
        print("---\n" + body)
        return 0
    out = Path(args.out); out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(body)
    print(f"file: {out}")
    print("Restart Gemini CLI; accept the one-time 'policies changed' prompt if it appears.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
