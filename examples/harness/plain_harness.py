"""Plain Python harness: semgate checks every tool call before it runs.

In-process (no server):
    semgate harness init --purpose "Software development in ~/code/app" --provider typesafe
    python examples/harness/plain_harness.py --config ~/.semgate/http/semgate.json

Through `semgate serve --http`:
    python examples/harness/plain_harness.py --url http://127.0.0.1:8787 \
        --token-file ~/.semgate/http/check.token --approve-token-file ~/.semgate/http/approve.token

The flow for each tool call (semgate.client.guard):
    allow -> run the tool
    deny  -> do not run it; the model gets semgate's reason as the tool result
    ask   -> ask the human in this terminal; their answer is recorded with
             approve(); semgate checks the same call again; it runs only on allow
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import subprocess
import uuid
from typing import Any, Callable, Dict, List, Mapping, Optional

from semgate.client import HttpClient, LocalClient, guard, request_for


def run_shell(command: str, cwd: str) -> str:
    """The real tool. semgate never runs it; this harness does, after an allow."""
    p = subprocess.run(command, shell=True, cwd=cwd, capture_output=True, text=True, timeout=300)
    return (f"exit {p.returncode}\n" + p.stdout + p.stderr)[-6000:]


def ask_in_terminal(decision: Mapping[str, Any]) -> Dict[str, Any]:
    """The human side. Only a person at this terminal answers here."""
    print(f"\nsemgate asks before this tool call runs:\n  {decision['reason']}")
    answer = input("Run it? [y/N] ").strip().lower()
    return {"approved": answer in ("y", "yes"), "by": getpass.getuser()}


class Session:
    """One agent run: its id, the user's turns, and the earlier tool calls with their outputs."""

    def __init__(self, client: Any, cwd: str, tools: Optional[Dict[str, Callable[[Mapping[str, Any]], Any]]] = None,
                 ask_human: Callable[[Mapping[str, Any]], Any] = ask_in_terminal) -> None:
        self.client = client
        self.cwd = cwd
        self.id = "run-" + uuid.uuid4().hex[:12]
        self.user_messages: List[str] = []
        self.recent: List[Dict[str, str]] = []
        self.tools = tools if tools is not None else {"bash": lambda args: run_shell(args["command"], cwd)}
        self.ask_human = ask_human

    def user(self, text: str) -> None:
        """A turn the human typed (from YOUR record of user input, never from model output)."""
        self.user_messages.append(text)

    def tool_call(self, tool: str, args: Mapping[str, Any], call_id: str = "", agent_intent: str = "") -> str:
        """What the model asked for. Returns the text the model gets back."""
        req = request_for(tool, args, session_id=self.id, cwd=self.cwd, user_messages=self.user_messages,
                          recent=self.recent[-20:], call_id=call_id, agent_intent=agent_intent, harness="plain-python")
        if tool not in self.tools:
            return f"unknown tool {tool}"
        res = guard(self.client, req, run=lambda: self.tools[tool](args), ask_human=self.ask_human)
        text = str(res.output) if res.ran else res.message
        summary = str(args.get("command") or args.get("path") or json.dumps(dict(args), sort_keys=True))[:200]
        self.recent.append({"tool": tool, "summary": summary, "output": text[:6000]})
        return text


def _read(path: str) -> str:
    with open(os.path.expanduser(path), encoding="utf-8") as handle:
        return handle.read().strip()


def main(argv: Optional[List[str]] = None) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", default="", help="semgate.json for in-process checks")
    p.add_argument("--url", default="", help="semgate serve --http address (instead of --config)")
    p.add_argument("--token-file", default="")
    p.add_argument("--approve-token-file", default="")
    p.add_argument("--cwd", default=os.getcwd())
    args = p.parse_args(argv)
    if args.url:
        client: Any = HttpClient(args.url, token=_read(args.token_file) if args.token_file else "",
                                 approve_token=_read(args.approve_token_file) if args.approve_token_file else "")
    else:
        client = LocalClient(args.config or None)
    s = Session(client, args.cwd)
    # A scripted "model" so the example runs without an LLM: replace with your model's tool calls.
    s.user("show me the git status of this project")
    for tool, call in (("bash", {"command": "git status"}), ("bash", {"command": "rm -rf /"})):
        print(f"\n$ {call['command']}\n{s.tool_call(tool, call)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
