"""Parallel tool calls: every host adapter pairs a tool's output with the call
that produced it, not with the call next to it in the transcript.

Live agy run 2026-09-24: two parallel view_file calls (AGENTS.md, SKILL.md)
got each other's text (fixed in adapters/antigravity.py, tested in
test_antigravity_adapter.py). Pins decide "is this an instruction file" from
an entry's summary, and evidence text is labeled by it, so a swap sends the
wrong file to the pin question. Each host below writes both calls first and
the results in reverse order (the second call finishes first)."""
import json

from semgate import tooloutputs
from semgate.adapters import claude_family, codex, opencode_tool, pi
from semgate.envelope import TrajectoryEntry, UserGrant

A_PATH, S_PATH = "/w/AGENTS.md", "/home/me/.claude/skills/semgate/SKILL.md"
A_TEXT, S_TEXT = "Before committing, you must run npm run e2e", "When semgate blocks a command, tell the user."
GRANT = UserGrant(grant_id="g", principal="p", purpose="dev", expires_at="2099-01-01T00:00:00Z")


def _by_summary(trace):
    return {e.summary: e.output for e in trace}


def _check(trace):
    outs = _by_summary(trace)
    assert A_TEXT in outs[A_PATH] and S_TEXT not in outs[A_PATH]
    assert S_TEXT in outs[S_PATH] and A_TEXT not in outs[S_PATH]


def test_claude_code_pairs_by_tool_use_id(tmp_path):
    t = tmp_path / "t.jsonl"
    rows = [
        {"type": "user", "uuid": "u1", "message": {"role": "user", "content": "read AGENTS.md and do what it says"}},
        {"type": "assistant", "uuid": "a1", "message": {"role": "assistant", "content": [
            {"type": "tool_use", "id": "t1", "name": "Read", "input": {"file_path": A_PATH}},
            {"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": S_PATH}}]}},
        {"type": "user", "uuid": "r2", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t2", "content": S_TEXT}]}},
        {"type": "user", "uuid": "r1", "message": {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "t1", "content": A_TEXT}]}},
    ]
    t.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    ctx = claude_family.read_transcript_context(str(t), "npm run e2e", current_id="t3")
    _check(ctx.trace)
    assert ctx.call_ids == ("t1", "t2")


def test_codex_pairs_by_call_id(tmp_path):
    def row(kind, payload):
        return {"timestamp": "2026-09-24T10:00:00Z", "type": kind, "payload": payload}
    t = tmp_path / "rollout.jsonl"
    rows = [
        row("response_item", {"type": "function_call", "call_id": "c1", "name": "exec_command",
                              "arguments": json.dumps({"cmd": f"cat {A_PATH}"})}),
        row("response_item", {"type": "function_call", "call_id": "c2", "name": "exec_command",
                              "arguments": json.dumps({"cmd": f"cat {S_PATH}"})}),
        row("response_item", {"type": "function_call_output", "call_id": "c2", "output": S_TEXT}),
        row("response_item", {"type": "function_call_output", "call_id": "c1", "output": A_TEXT}),
    ]
    t.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")
    outs = _by_summary(codex.read_transcript_context(str(t), "c3").trace)
    assert outs[f"cat {A_PATH}"] == A_TEXT and outs[f"cat {S_PATH}"] == S_TEXT


def test_pi_pairs_by_tool_call_id():
    def message(ident, role, content, **extra):
        return {"type": "message", "id": ident, "timestamp": "2026-09-24T10:00:00Z",
                "message": {"role": role, "content": content, **extra}}
    entries = [
        message("u1", "user", [{"type": "text", "text": "read AGENTS.md and do what it says"}]),
        message("a1", "assistant", [
            {"type": "toolCall", "id": "c1", "name": "read", "arguments": {"path": A_PATH}},
            {"type": "toolCall", "id": "c2", "name": "read", "arguments": {"path": S_PATH}}]),
        message("r2", "toolResult", [{"type": "text", "text": S_TEXT}], toolCallId="c2", isError=False),
        message("r1", "toolResult", [{"type": "text", "text": A_TEXT}], toolCallId="c1", isError=False),
        message("a2", "assistant", [{"type": "toolCall", "id": "c3", "name": "bash", "arguments": {"command": "npm run e2e"}}]),
    ]
    env = pi.envelope_from_request({"entries": entries, "callID": "c3", "tool": "bash", "args": {"command": "npm run e2e"}}, GRANT)
    _check(env.trajectory.recent)


def test_opencode_ai_sdk_shape_pairs_by_tool_call_id():
    messages = [
        {"role": "user", "content": [{"type": "text", "text": "read AGENTS.md and do what it says"}]},
        {"role": "assistant", "content": [
            {"type": "tool-call", "toolCallId": "c1", "toolName": "read", "input": {"filePath": A_PATH}},
            {"type": "tool-call", "toolCallId": "c2", "toolName": "read", "input": {"filePath": S_PATH}}]},
        {"role": "tool", "content": [
            {"type": "tool-result", "toolCallId": "c2", "toolName": "read", "output": {"type": "text", "value": S_TEXT}},
            {"type": "tool-result", "toolCallId": "c1", "toolName": "read", "output": {"type": "text", "value": A_TEXT}}]},
    ]
    ctx = opencode_tool.parse_messages_context(messages)
    _check(ctx.trace)


def test_opencode_v1_keeps_the_output_inside_its_own_call():
    # V1 tool parts carry input and output together (state.input / state.output): no pairing step.
    def part(cid, path, out):
        return {"type": "tool", "tool": "read", "callID": cid,
                "state": {"status": "completed", "input": {"filePath": path}, "output": out}}
    messages = [{"info": {"role": "user"}, "parts": [{"type": "text", "text": "read AGENTS.md"}]},
                {"info": {"role": "assistant"}, "parts": [part("c1", A_PATH, A_TEXT), part("c2", S_PATH, S_TEXT)]}]
    _check(opencode_tool.parse_messages_context(messages).trace)


def test_records_without_a_call_id_pair_by_summary_before_order():
    # Hosts without tool_use_id (tooloutputs.merge_trace). The second read
    # finished first, so its record was written first; by order alone the
    # AGENTS.md entry got SKILL.md's text.
    trace = (TrajectoryEntry(tool="Read", decision="", summary=A_PATH), TrajectoryEntry(tool="Read", decision="", summary=S_PATH))
    recs = [tooloutputs.make_record("s", "", "Read", S_TEXT, summary=S_PATH),
            tooloutputs.make_record("s", "", "Read", A_TEXT, summary=A_PATH)]
    out, stats = tooloutputs.merge_trace(trace, ("", ""), frozenset(), recs)
    _check(out)
    assert stats["by_summary"] == 2 and stats["by_order"] == 0
    # two calls with the same summary: not unique, so order decides (as before)
    same = (TrajectoryEntry(tool="Bash", decision="", summary="npm test"), TrajectoryEntry(tool="Bash", decision="", summary="npm test"))
    recs = [tooloutputs.make_record("s", "", "Bash", "first", summary="npm test"),
            tooloutputs.make_record("s", "", "Bash", "second", summary="npm test")]
    out, stats = tooloutputs.merge_trace(same, ("", ""), frozenset(), recs)
    assert [e.output for e in out] == ["first", "second"] and stats["by_order"] == 2 and "by_summary" not in stats
