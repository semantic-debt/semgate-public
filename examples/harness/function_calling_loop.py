"""A generic function-calling loop (OpenAI chat completions style, any model)
with semgate in front of every tool call.

`agent_loop` needs only a `call_model(messages) -> reply` function, where
reply is {"content": str, "tool_calls": [{"id", "name", "arguments": <JSON string>}]}.
With the OpenAI SDK that is roughly:

    def call_model(messages):
        r = openai.chat.completions.create(model=..., messages=messages, tools=TOOL_SPECS)
        m = r.choices[0].message
        return {"content": m.content or "",
                "tool_calls": [{"id": c.id, "name": c.function.name, "arguments": c.function.arguments}
                               for c in (m.tool_calls or [])]}

OpenAI Agents SDK: guard inside the tool function itself (the SDK runs the
function; semgate decides first):

    from agents import function_tool
    from semgate.client import HttpClient, guard, request_for

    gate = HttpClient("http://127.0.0.1:8787", token=CHECK_TOKEN, approve_token=APPROVE_TOKEN)

    @function_tool
    def run_shell(command: str) -> str:
        req = request_for("bash", {"command": command}, session_id=SESSION_ID, cwd=CWD,
                          user_messages=USER_TURNS, recent=RECENT)
        res = guard(gate, req, run=lambda: _run(command), ask_human=ask_in_terminal)
        return res.output if res.ran else res.message

USER_TURNS must be what the person typed (your own record), never model output.
"""
from __future__ import annotations

import json
from typing import Any, Callable, Dict, List, Mapping

from semgate.client import guard, request_for, safe_id


def agent_loop(call_model: Callable[[List[Dict[str, Any]]], Mapping[str, Any]],
               tools: Mapping[str, Callable[..., Any]], client: Any, *, session_id: str, cwd: str, user_text: str,
               ask_human: Callable[[Mapping[str, Any]], Any], max_steps: int = 10) -> str:
    messages: List[Dict[str, Any]] = [{"role": "user", "content": user_text}]
    user_turns = [user_text]
    recent: List[Dict[str, str]] = []
    for _ in range(max_steps):
        reply = call_model(messages)
        calls = list(reply.get("tool_calls") or [])
        messages.append({"role": "assistant", "content": reply.get("content") or "",
                         "tool_calls": [{"id": c["id"], "type": "function",
                                         "function": {"name": c["name"], "arguments": c["arguments"]}} for c in calls]})
        if not calls:
            return str(reply.get("content") or "")
        for c in calls:
            try:
                args = json.loads(c["arguments"] or "{}")
            except ValueError:
                args = {"_unparsed": str(c["arguments"])[:2000]}
            fn = tools.get(c["name"])
            if fn is None:
                out = f"unknown tool {c['name']}"
            else:
                req = request_for(c["name"], args, session_id=session_id, cwd=cwd, user_messages=user_turns,
                                  recent=recent[-20:], call_id=safe_id(c["id"]), agent_intent=reply.get("content") or "",
                                  harness="function-calling")
                res = guard(client, req, run=lambda: fn(**args), ask_human=ask_human)
                out = str(res.output) if res.ran else res.message
            recent.append({"tool": c["name"], "summary": str(args.get("command") or args.get("path") or "")[:200],
                           "output": out[:6000]})
            messages.append({"role": "tool", "tool_call_id": c["id"], "content": out})
    return "stopped: too many steps"
