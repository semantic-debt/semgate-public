"""Antigravity PostToolUse command.

One JSON event is read from stdin and an empty JSON object is written to
stdout, as the PostToolUse contract requires. The payload carries only
`conversationId`, `stepIdx` and `error`; the tool name and arguments come from
the pending record the PreToolUse hook wrote for the same step.

This hook only records: executed steps (tool history) and, with
agent_files / script_source on, files the agent created (hash + snapshot) and
scripts that changed after the decision. It never fails the agent loop.
"""
from __future__ import annotations
import argparse, json, os, sys
from . import storepaths
from .antigravity_hook import history_path, record_post_event
from .history import ToolHistory

def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="semgate-antigravity-post-hook")
    parser.add_argument("--config", default=os.environ.get("SEMGATE_ANTIGRAVITY_CONFIG", "~/.semgate/antigravity/semgate.json"))
    args = parser.parse_args(argv)
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("hook input must be a JSON object")
        config = storepaths.load(args.config, "antigravity")
        path = history_path(config)
        if path:
            ToolHistory(path).record_executed(
                str(event.get("conversationId", "")),
                event.get("stepIdx"),
                str(event.get("error") or ""),
            )
        # F6/F4: files the agent created (hash + snapshot); scripts changed since the decision.
        record_post_event(config, str(event.get("conversationId", "")), event.get("stepIdx"), str(event.get("error") or ""))
    except Exception as exc:
        print(f"semgate post hook failure: {type(exc).__name__}: {exc}", file=sys.stderr)
    sys.stdout.write("{}\n")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
