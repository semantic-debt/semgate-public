#!/usr/bin/env python3
"""Minimal Gemini CLI BeforeTool probe to test whether YOLO fires the hook.

Blocks ONLY the marker command `echo SEMGATE_DENY_PROBE`; every other tool call
is a no-op (prints {} = do not block). Run Gemini CLI in YOLO
(--yolo / --approval-mode=yolo) and ask it to run that exact command:
  - blocked  -> YOLO still fires BeforeTool hooks and honors deny. Design works.
  - it runs  -> YOLO bypasses hooks. echo is harmless either way.

Gemini BeforeTool input (stdin JSON): hook_event_name, tool_name, tool_input.
To block, output {"decision":"deny","reason":...}.
"""
import json, sys

MARKER = "SEMGATE_DENY_PROBE"
try:
    inp = json.load(sys.stdin)
except Exception:
    inp = {}
tool = inp.get("tool_name")
command = (inp.get("tool_input") or {}).get("command", "") if isinstance(inp.get("tool_input"), dict) else ""

if inp.get("hook_event_name") == "BeforeTool" and tool == "run_shell_command" and MARKER in str(command):
    print(json.dumps({"decision": "deny", "reason": "semgate probe: YOLO-honors-hook test; this marker command is blocked"}))
else:
    print("{}")
