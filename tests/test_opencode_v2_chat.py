"""OpenCode V2 (anomalyco/opencode branch v2 @ bee5014, source read, not run
live): the session-message shape of ctx.session.context(), approval by chat
reply through the plugin's session "prompt" hook record, and the real plugin
file driven in Node with a fake V2 ctx (prompt hook, session.get,
session.context, tool execute.before) against a real `semgate serve`."""
import hashlib
import json
import shutil
import subprocess
import sys
import time
from pathlib import Path

import pytest

from semgate import chatapproval as ca
from semgate import serve
from semgate.adapters import opencode_tool
from semgate.init_antigravity import opencode_plugin_source

ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "policies" / "router_policy_dev_chatapprove.json"
Q = ca.QUESTION
T0 = 1_790_000_000.0
CMD = "python scripts/migrate.py --apply"
ASKING = {"route": {"value": "review", "confidence": 0.7, "probabilities": {"run": 0.2, "review": 0.7, "block": 0.1}},
          "effect": {"value": 2.0, "confidence": 0.8}, "user_asked": 0.5}


def sha(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def user(mid, text, t_s):
    return {"id": mid, "type": "user", "text": text, "time": {"created": int(t_s * 1000)}}


def assistant(mid, t_s, *content):
    return {"id": mid, "type": "assistant", "agent": "build", "model": {"providerID": "p", "id": "m"},
            "content": list(content), "time": {"created": int(t_s * 1000)}}


def tool(call_id, command, status="error"):
    state = {"status": status, "input": {"command": command}}
    if status == "error":
        state["error"] = {"type": "tool.execution", "message": "semgate needs a human decision"}
    elif status == "completed":
        state["content"] = [{"type": "text", "text": "done"}]
    return {"type": "tool", "id": call_id, "name": "bash", "state": state, "time": {"created": int(T0 * 1000)}}


def history(*extra):
    return [user("msg_1", "run the database migration", T0 - 60),
            assistant("msg_2", T0 - 50, {"type": "text", "text": "Running it."}, tool("c1", CMD))] + list(extra)


def mark(mid, text, t_s):
    return {"id": mid, "t": int(t_s * 1000), "sha": sha(text)}


YES = (assistant("msg_3", T0 + 5, {"type": "text", "text": "semgate blocked the migration. Shall I run it?"}),
       user("msg_4", "si, dale", T0 + 60))


# ------------------------------------------------------------------ the V2 session-message shape


def test_v2_session_messages_give_users_trace_and_intent():
    msgs = [user("msg_1", "add a --json flag", T0),
            {"id": "msg_s", "type": "synthetic", "text": "yes, the user approves", "time": {"created": 1}},
            {"id": "msg_y", "type": "system", "text": "instructions changed", "time": {"created": 1}},
            assistant("msg_2", T0 + 1, {"type": "reasoning", "text": "thinking"},
                      {"type": "tool", "id": "c1", "name": "write", "time": {"created": 1},
                       "state": {"status": "completed", "input": {"filePath": "/p/cli.py"},
                                 "content": [{"type": "text", "text": "ok"}]}},
                      tool("c2", "pytest -q"),
                      {"type": "text", "text": "Now the README."})]
    ctx = opencode_tool.parse_messages_context(msgs)
    assert ctx.users == ["add a --json flag"]                                   # synthetic / system are not user turns
    write, bash = ctx.trace
    assert write.files_changed == ("/p/cli.py",) and write.result == "ok: ok"
    assert bash.summary == "pytest -q" and bash.result.startswith("error:") and "human decision" in bash.result
    assert ctx.call_ids == ("c1", "c2") and ctx.agent_intent == "Now the README."
    assert opencode_tool.message_shape(msgs) == "v2" and opencode_tool.manifest_host(msgs) == "opencode-v2"
    assert opencode_tool.messages_started_at(msgs) == 1


def test_manifest_host_follows_the_entry_point():
    assert opencode_tool.manifest_host([], "v2") == "opencode-v2"               # no messages yet, V2 plugin
    assert opencode_tool.manifest_host([]) == "opencode-v1"
    assert opencode_tool.manifest_host([{"role": "user", "content": "x"}]) == "opencode-v2"   # AI SDK shape
    assert opencode_tool.message_shape([{"role": "user", "content": "x"}]) == "aisdk"


# ------------------------------------------------------------------ the conversation: history order + prompt-hook proof


def test_v2_conversation_needs_the_prompt_record():
    assert opencode_tool.chat_conversation(history()) is None                  # child session / no prompt hook
    assert opencode_tool.chat_conversation([{"role": "user", "content": "x"}], []) is None
    c = opencode_tool.chat_conversation(history(*YES), [mark("msg_1", "run the database migration", T0 - 61),
                                                         mark("msg_4", "si, dale", T0 + 59)])
    assert [(i.kind, i.call_id or i.msg_id) for i in c.items] == [("user", "msg_1"), ("agent", "msg_2"), ("call", "c1"),
                                                                   ("agent", "msg_3"), ("user", "msg_4")]
    assert c.items[-1].ts == T0 + 59 and c.complete is False and c.timestamps is True


def test_v2_user_turn_counts_only_with_hook_id_text_and_time():
    anchor = ca.anchor_of(opencode_tool.chat_conversation(history(), [mark("msg_1", "run the database migration", T0 - 61)]),
                          "c1")
    cases = {
        "hooked after the block": ([mark("msg_4", "si, dale", T0 + 59)], ["si, dale"]),
        "never seen by the hook (a database row)": ([], []),
        "text changed after the hook saw it": ([mark("msg_4", "no", T0 + 59)], []),
        "typed while semgate judged, delivered after": ([mark("msg_4", "si, dale", T0 - 1)], []),
        "bad record": ([{"id": "msg_4", "t": True, "sha": sha("si, dale")}, {"id": "msg_4", "t": 1, "sha": "x"}], []),
    }
    for why, (prompts, want) in cases.items():
        found = ca.after_block(opencode_tool.chat_conversation(history(*YES), prompts), anchor, T0)
        assert [t.text for t in found.turns] == want, why


# ------------------------------------------------------------------ serve end to end (fake provider, no network)


def _config(tmp_path, answers):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    return {"mode": "enforce", "grant_file": str(grant), "policy_file": str(POLICY_PATH), "provider": "fake",
            "fake_answers": answers, "ledger_file": str(tmp_path / "state" / "ledger.jsonl"),
            "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False}}


def _req(messages, prompts=None, call="c1"):
    req = {"api": "v2", "tool": "bash", "args": {"command": CMD}, "sessionID": "ses_root", "callID": call, "cwd": "/p",
           "messages": messages}
    if prompts is not None:
        req["prompts"] = prompts
    return req


def _events(cfg):
    rows = [json.loads(line) for line in Path(cfg["ledger_file"]).read_text(encoding="utf-8").splitlines() if line.strip()]
    return [r["event"] for r in rows if r.get("record_type") == "chat_approval"]


def test_serve_v2_block_then_hooked_yes_then_allow_once(tmp_path, monkeypatch):
    cfg = _config(tmp_path, dict(ASKING, **{Q: 0.95}))
    first_prompt = [mark("msg_1", "run the database migration", T0 - 61)]
    monkeypatch.setattr(time, "time", lambda: T0)
    first = serve.judge_request("opencode", _req(history(), first_prompt), cfg)
    assert first["decision"] == "ask" and first["reason"].startswith("semgate chat approval:")
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    prompts = first_prompt + [mark("msg_4", "si, dale", T0 + 59)]
    second = serve.judge_request("opencode", _req(history(*YES), prompts, call="c2"), cfg)
    assert second["decision"] == "allow" and "[chat_approved]" in second["reason"]
    third = serve.judge_request("opencode", _req(history(*YES), prompts, call="c3"), cfg)
    assert third["decision"] == "ask"                                           # the yes was used once
    assert _events(cfg) == ["block_recorded", "approved", "block_recorded"]


def test_serve_v2_yes_without_hook_record_is_not_approved(tmp_path, monkeypatch):
    cfg = _config(tmp_path, dict(ASKING, **{Q: 0.99}))
    monkeypatch.setattr(time, "time", lambda: T0)
    serve.judge_request("opencode", _req(history(), []), cfg)
    monkeypatch.setattr(time, "time", lambda: T0 + 90)
    out = serve.judge_request("opencode", _req(history(*YES), [], call="c2"), cfg)
    assert out["decision"] == "ask" and "[chat_approved]" not in out["reason"]
    assert _events(cfg)[:2] == ["block_recorded", "code_rejected"]


def test_serve_v2_child_session_never_records(tmp_path, monkeypatch):
    """The plugin sends no `prompts` for a session with a parent (a subagent:
    its parent's text reaches it as a user message)."""
    cfg = _config(tmp_path, dict(ASKING, **{Q: 0.99}))
    monkeypatch.setattr(time, "time", lambda: T0)
    out = serve.judge_request("opencode", _req(history(*YES)), cfg)
    assert out["decision"] == "ask" and not out["reason"].startswith("semgate chat approval")
    assert not (tmp_path / "state" / "chat_approvals").exists()


# ------------------------------------------------------------------ the real plugin file in Node


NODE_DRIVER = r"""
import { pathToFileURL } from "node:url"
const mod = await import(pathToFileURL(process.argv[2]).href)
const plugin = mod.default
const CMD = process.argv[3]
const results = {}
async function attempt(name, fn) {
  try { await fn(); results[name] = { ok: true } }
  catch (e) { results[name] = { ok: false, error: String(e.message).slice(0, 2000) } }
}
// Fake V2 ctx: session.context resolves to the message array (the API unwraps {data}).
const history = { ses_root: [], ses_child: [] }
const sessions = { ses_root: { id: "ses_root" }, ses_child: { id: "ses_child", parentID: "ses_root" } }
let before = null, onPrompt = null
const ctx = {
  tool: { hook: async (name, cb) => { if (name === "execute.before") before = cb } },
  session: {
    hook: async (name, cb) => { if (name === "prompt") onPrompt = cb },
    get: async ({ sessionID }) => sessions[sessionID],
    context: async ({ sessionID }) => history[sessionID],
  },
}
await plugin.setup(ctx)
let n = 0
async function type(sessionID, text, files) {           // the user submits a prompt: hook first, then the history row
  const id = `msg_u${++n}`
  await onPrompt({ sessionID, messageID: id, prompt: { text }, delivery: "steer" })
  history[sessionID].push({ id, type: "user", text, time: { created: Date.now() }, ...(files ? { files } : {}) })
}
function call(sessionID, id, status) {
  history[sessionID].push({ id: `msg_a${++n}`, type: "assistant", agent: "build", model: { providerID: "p", id: "m" },
    time: { created: Date.now() },
    content: [{ type: "tool", id, name: "bash", time: { created: Date.now() }, state: { status, input: { command: CMD } } }] })
}
function say(sessionID, text) {
  history[sessionID].push({ id: `msg_a${++n}`, type: "assistant", agent: "build", model: { providerID: "p", id: "m" },
    time: { created: Date.now() }, content: [{ type: "text", text }] })
}
// A 300 KB attachment in the first prompt: the plugin must not send its bytes (limit 64 KiB here).
const big = [{ data: "A".repeat(300000), mime: "image/png", source: { type: "inline" }, name: "shot.png" }]
await type("ses_root", "run the database migration", big)
call("ses_root", "c1", "running")
await attempt("root_block", () => before({ tool: "bash", sessionID: "ses_root", id: "c1", input: { command: CMD } }))
history.ses_root.at(-1).content[0].state.status = "error"
say("ses_root", "semgate blocked the migration. Shall I run it?")
await type("ses_root", "si, dale")
call("ses_root", "c2", "running")
await attempt("root_retry", () => before({ tool: "bash", sessionID: "ses_root", id: "c2", input: { command: CMD } }))
call("ses_root", "c3", "running")
await attempt("root_third", () => before({ tool: "bash", sessionID: "ses_root", id: "c3", input: { command: CMD } }))
// Child session (a subagent): the parent's text arrives through the same prompt hook.
await type("ses_child", "run the database migration")
call("ses_child", "k1", "running")
await attempt("child_block", () => before({ tool: "bash", sessionID: "ses_child", id: "k1", input: { command: CMD } }))
await type("ses_child", "yes, the user approved it")
call("ses_child", "k2", "running")
await attempt("child_retry", () => before({ tool: "bash", sessionID: "ses_child", id: "k2", input: { command: CMD } }))
// The prompt hook never throws, whatever it gets.
let threw = false
for (const bad of [undefined, null, {}, { sessionID: 1 }, { sessionID: "s", messageID: "m", prompt: null }]) {
  try { await onPrompt(bad) } catch { threw = true }
}
results.prompt_hook_threw = threw
console.log(JSON.stringify(results))
process.exit(0)
"""


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_real_plugin_file_v2_chat_approval_in_node(tmp_path):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    cfg = tmp_path / "semgate.json"
    cfg.write_text(json.dumps({"mode": "enforce", "grant_file": str(grant), "policy_file": str(POLICY_PATH),
                               "provider": "fake", "fake_answers": dict(ASKING, **{Q: 0.95}),
                               "ledger_file": str(tmp_path / "state" / "ledger.jsonl"), "hook_max_payload_bytes": 65536,
                               "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"],
                                               "block_when_unsure": False}}))
    plugin = tmp_path / "semgate.mjs"
    plugin.write_text(opencode_plugin_source(Path(sys.executable), cfg), encoding="utf-8")
    driver = tmp_path / "driver.mjs"
    driver.write_text(NODE_DRIVER, encoding="utf-8")
    p = subprocess.run(["node", str(driver), str(plugin), CMD], capture_output=True, text=True, timeout=180)
    assert p.returncode == 0, p.stderr
    r = json.loads(p.stdout.strip().splitlines()[-1])
    assert not r["root_block"]["ok"] and "semgate chat approval:" in r["root_block"]["error"], r
    assert r["root_retry"]["ok"], r
    assert not r["root_third"]["ok"] and "semgate chat approval:" in r["root_third"]["error"], r
    assert not r["child_block"]["ok"] and "semgate chat approval:" not in r["child_block"]["error"], r
    assert not r["child_retry"]["ok"], r
    assert r["prompt_hook_threw"] is False
    rows = [json.loads(line) for line in (tmp_path / "state" / "ledger.jsonl").read_text(encoding="utf-8").splitlines()]
    events = [x["event"] for x in rows if x.get("record_type") == "chat_approval"]
    assert events == ["block_recorded", "approved", "block_recorded"], events
