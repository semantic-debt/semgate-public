"""Hook input: memory guard, session id check, payload size evidence, S5."""
import io
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from semgate import hookinput, payloadsize
from semgate.judge import judge
from semgate.ledger import Ledger
from semgate.policy import Policy
from semgate.providers.base import JudgeProvider, PredicateAnswer

ROOT = Path(__file__).parents[1]
ALLOWING = {"route": {"value": "run", "confidence": 1.0}, "effect": {"value": 0.0, "confidence": 1.0}, "user_asked": 0.9,
            "on_task": 0.9, "instructed_by_context": 0.05, "unneeded_change": 0.05}


def _config(tmp_path, **extra):
    grant = tmp_path / "grant.json"
    grant.write_text(json.dumps({"grant_id": "g", "principal": "p", "purpose": "Software development in this project",
                                 "expires_at": "2099-01-01T00:00:00Z"}))
    cfg = {"mode": "enforce", "grant_file": str(grant), "policy_file": str(ROOT / "policies" / "router_policy_dev.json"),
           "provider": "fake", "fake_answers": ALLOWING, "ledger_file": str(tmp_path / "ledger.jsonl"),
           "enforcement": {"enabled": True, "auto_allow_tools": ["bash", "read"], "block_when_unsure": False}}
    cfg.update(extra)
    path = tmp_path / "semgate.json"
    path.write_text(json.dumps(cfg))
    return str(path)


def _run(module, config, data: bytes, *args, cwd=None):
    # cwd None: the temp current directory of conftest._temp_home_and_cwd, never the repo.
    p = subprocess.run([sys.executable, "-m", module, "--config", config, *args], input=data, capture_output=True,
                       cwd=cwd, timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def _incidents(tmp_path):
    return [r for r in Ledger(str(tmp_path / "ledger.jsonl")).records() if r.get("record_type") == "incident"]


# ------------------------------------------------------------------ reading


def test_read_limited_keeps_under_limit_and_counts_over_limit():
    raw = hookinput.read_limited(io.BytesIO(b"x" * 3000), limit=4096)
    assert raw.data == b"x" * 3000 and raw.size == 3000 and not raw.over_limit
    raw = hookinput.read_limited(io.BytesIO(b"x" * (3 << 20)), limit=1 << 20)
    assert raw.over_limit and raw.data is None and raw.size == 3 << 20       # the rest is drained and counted
    with pytest.raises(hookinput.InputRejected) as err:
        hookinput.parse_event(raw)
    assert err.value.kind == "payload_over_limit" and err.value.detail == {"bytes": 3 << 20, "limit": 1 << 20}


def test_limit_comes_from_config_with_a_high_default(tmp_path):
    assert hookinput.max_payload_bytes(str(tmp_path / "missing.json")) == 64 * 1024 * 1024
    assert hookinput.max_payload_bytes({"hook_max_payload_bytes": 2048}) == 2048
    for bad in (10, -1, "big", True, 1.5, None):
        assert hookinput.max_payload_bytes({"hook_max_payload_bytes": bad}) == hookinput.DEFAULT_MAX_PAYLOAD_BYTES


@pytest.mark.parametrize("sid,ok", [
    ("", True), ("3f2a9c1e-5b7d-4e1f-9a2b-0c8d7e6f5a4b", True), ("ses_3f2a9c1eXYZ", True), ("a.b:c-d_e", True),
    ("../../etc/passwd", False), ("a/b", False), ("a\\b", False), ("x" * 257, False), ("..", False), ("a b", False),
    ("é", False), (12, False),
])
def test_session_id_check(sid, ok):
    assert (hookinput.session_id_problem(sid) == "") is ok


def test_bounded_lines_replaces_an_oversized_line():
    lines = list(hookinput.bounded_lines(io.StringIO("short\n" + "y" * 5000 + "\nnext\n"), limit=1024))
    assert lines[0] == "short\n" and isinstance(lines[1], hookinput.OversizeLine) and lines[1].size == 5001
    assert lines[2] == "next\n"


# ------------------------------------------------------------------ hooks


def test_claude_hook_over_limit_asks_and_records(tmp_path):
    cfg = _config(tmp_path, hook_max_payload_bytes=2048)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s",
             "tool_input": {"command": "git status", "pad": "z" * 5000}}
    out = _run("semgate.claude_hook", cfg, json.dumps(event).encode())
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    assert "above hook_max_payload_bytes" in out["hookSpecificOutput"]["permissionDecisionReason"]
    inc = _incidents(tmp_path)
    assert inc and inc[0]["kind"] == "hook_input_rejected" and inc[0]["detail"]["reason"] == "payload_over_limit"


def test_claude_hook_invalid_session_id_asks(tmp_path):
    cfg = _config(tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "../../x", "tool_input": {"command": "git status"}}
    out = _run("semgate.claude_hook", cfg, json.dumps(event).encode())
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    detail = _incidents(tmp_path)[0]["detail"]
    assert detail["reason"] == "invalid_session_id" and "../../x" not in json.dumps(detail)


def test_claude_hook_records_payload_sizes_for_every_decision(tmp_path):
    cfg = _config(tmp_path)
    event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "s", "model": "claude-opus-4-5-20251101",
             "tool_input": {"command": "git status"}}
    data = json.dumps(event).encode()
    out = _run("semgate.claude_hook", cfg, data)
    assert out["hookSpecificOutput"]["permissionDecision"] == "allow"         # unchanged decision
    ev = Ledger(str(tmp_path / "ledger.jsonl")).judgments()[0]["decision"]["evidence"]["payload"]
    assert ev["hook_payload_bytes"] == len(data) and ev["tool_input_bytes"] == len('{"command":"git status"}')
    assert ev["model"] == "claude-opus-4-5-20251101" and ev["max_output_tokens"] == 64000
    assert ev["expected_max_bytes"] == 64000 * 4 * 4 and ev["anomaly"] is False


def test_model_id_from_the_claude_transcript(tmp_path):
    t = tmp_path / "t.jsonl"
    t.write_text("\n".join(json.dumps(x) for x in [
        {"type": "user", "message": {"role": "user", "content": "hi"}},
        {"type": "assistant", "message": {"role": "assistant", "model": "claude-sonnet-4-5-20250929", "content": []}},
        {"type": "assistant", "message": {"role": "assistant", "model": "<synthetic>", "content": []}},
    ]) + "\n", encoding="utf-8")
    assert hookinput.model_from_transcript(str(t)) == "claude-sonnet-4-5-20250929"
    assert hookinput.model_from_transcript(str(tmp_path / "missing")) == ""


def test_antigravity_hook_invalid_session_and_over_limit(tmp_path):
    cfg = _config(tmp_path, hook_max_payload_bytes=2048)
    ev = {"conversationId": "a/b", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}}
    out = _run("semgate.antigravity_hook", cfg, json.dumps(ev).encode())
    assert out["decision"] == "deny" and "session id" in out["reason"]       # agy: a failure is never an ask
    ev["conversationId"] = "c1"
    ev["toolCall"]["args"]["pad"] = "z" * 4000
    out = _run("semgate.antigravity_hook", cfg, json.dumps(ev).encode())
    assert out["decision"] == "deny" and "hook_max_payload_bytes" in out["reason"]
    assert [i["detail"]["reason"] for i in _incidents(tmp_path)] == ["invalid_session_id", "payload_over_limit"]


def test_serve_oversize_line_and_bad_session_deny(tmp_path):
    from semgate.serve import serve
    cfg = _config(tmp_path, hook_max_payload_bytes=2048)
    lines = [json.dumps({"id": 1, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls", "pad": "z" * 4000}, "sessionID": "s"}}),
             json.dumps({"id": 2, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls"}, "sessionID": "../x"}})]
    out = io.StringIO()
    serve(cfg, stdin=io.StringIO("\n".join(lines) + "\n"), stdout=out)
    answers = [json.loads(l) for l in out.getvalue().splitlines()]
    assert answers[0]["id"] == 1 and answers[0]["decision"] == "deny" and "hook_max_payload_bytes" in answers[0]["reason"]
    assert answers[1]["id"] == 2 and answers[1]["decision"] == "deny" and "session id" in answers[1]["reason"]


def _host_responses(tmp_path):
    return [r for r in Ledger(str(tmp_path / "ledger.jsonl")).records() if r.get("record_type") == "host_response"]


def test_invalid_session_id_is_hashed_in_host_response_records(tmp_path):
    """claude_hook, antigravity_hook and serve: a rejected session id is never
    written to the ledger; the host_response keeps conversation_id "" and the
    same {length, sha256_12} as the hook_input_rejected incident."""
    from semgate.serve import serve
    raw_ids = ["../../claudeRAWsid", "../../copilotRAWsid", "agy/RAWsid/1", 12345, "../opencodeRAWsid"]
    cfg = _config(tmp_path)
    for key in ("session_id", "sessionId"):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Bash", key: raw_ids[len(_incidents(tmp_path))],
                 "tool_use_id": "t1", "tool_input": {"command": "git status"}}
        assert _run("semgate.claude_hook", cfg, json.dumps(event).encode())["hookSpecificOutput"]["permissionDecision"] == "ask"
    for sid in raw_ids[2:4]:
        ev = {"conversationId": sid, "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}}
        assert _run("semgate.antigravity_hook", cfg, json.dumps(ev).encode())["decision"] == "deny"
    line = json.dumps({"id": 1, "host": "opencode", "request": {"tool": "bash", "args": {"command": "ls"}, "sessionID": raw_ids[4],
                                                                 "callID": "c1"}})
    out = io.StringIO()
    serve(cfg, stdin=io.StringIO(line + "\n"), stdout=out)
    assert json.loads(out.getvalue().splitlines()[0])["decision"] == "deny"

    incidents, responses = _incidents(tmp_path), _host_responses(tmp_path)
    assert [i["detail"]["reason"] for i in incidents] == ["invalid_session_id"] * 5 and len(responses) == 5
    for raw, inc, rec in zip(raw_ids, incidents, responses):
        digest = hookinput.session_id_digest(raw)
        assert digest == {"length": inc["detail"]["length"], "sha256_12": inc["detail"]["sha256_12"]}
        assert rec["conversation_id"] == "" and rec["invalid_session_id"] == digest
    text = (tmp_path / "ledger.jsonl").read_text(encoding="utf-8")
    for raw in raw_ids[:3] + raw_ids[4:]:
        assert "RAWsid" not in text and raw not in text


def test_valid_session_id_is_kept_in_host_response_records(tmp_path):
    cfg = _config(tmp_path)
    ev = {"conversationId": "conv-1", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "git status"}}}
    _run("semgate.antigravity_hook", cfg, json.dumps(ev).encode())
    (rec,) = _host_responses(tmp_path)
    assert rec["conversation_id"] == "conv-1" and "invalid_session_id" not in rec


# ------------------------------------------------------------------ where early failures are recorded


def _files(path):
    return sorted(p.relative_to(path).as_posix() for p in Path(path).rglob("*"))


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """HOME/USERPROFILE and the hook's current directory: empty temp dirs."""
    home, project = tmp_path / "home", tmp_path / "project"
    home.mkdir()
    project.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    return home, project


def test_early_rejection_is_recorded_in_the_configured_ledger_not_under_cwd(tmp_path, isolated):
    home, project = isolated
    ledger = tmp_path / "state" / "ledger.jsonl"
    cfg = _config(tmp_path, hook_max_payload_bytes=2048, ledger_file=str(ledger))
    bad_session = {"hook_event_name": "PreToolUse", "tool_name": "Bash", "session_id": "../../x",
                   "tool_input": {"command": "git status"}}
    out = _run("semgate.claude_hook", cfg, json.dumps(bad_session).encode(), cwd=str(project))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    out = _run("semgate.claude_hook", cfg, b"not json", cwd=str(project))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    ev = {"conversationId": "c1", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "ls", "pad": "z" * 4000}}}
    out = _run("semgate.antigravity_hook", cfg, json.dumps(ev).encode(), cwd=str(project))
    assert out["decision"] == "deny"
    records = list(Ledger(str(ledger)).records())
    assert [r["detail"]["reason"] for r in records if r.get("record_type") == "incident"] == [
        "invalid_session_id", "payload_not_json", "payload_over_limit"]
    assert [r["native"]["decision"] for r in records if r.get("record_type") == "host_response"] == ["ask", "ask", "deny"]
    assert _files(project) == [] and _files(home) == []


def test_early_rejection_without_a_readable_config_goes_to_the_user_state_dir(tmp_path, isolated):
    home, project = isolated
    missing = str(tmp_path / "missing.json")
    out = _run("semgate.claude_hook", missing, b"not json", cwd=str(project))
    assert out["hookSpecificOutput"]["permissionDecision"] == "ask"
    ev = {"conversationId": "a/b", "stepIdx": 1, "toolCall": {"name": "run_command", "args": {"CommandLine": "ls"}}}
    out = _run("semgate.antigravity_hook", missing, json.dumps(ev).encode(), cwd=str(project))
    assert out["decision"] == "deny"
    for host, reason, decision in (("claude", "payload_not_json", "ask"), ("antigravity", "invalid_session_id", "deny")):
        records = list(Ledger(str(home / ".semgate" / host / "ledger.jsonl")).records())
        assert [r["detail"]["reason"] for r in records if r.get("record_type") == "incident"] == [reason]
        assert [r["native"]["decision"] for r in records if r.get("record_type") == "host_response"] == [decision]
    assert _files(project) == []


def test_serve_rejection_without_a_readable_config_goes_to_the_user_state_dir(tmp_path, isolated, monkeypatch):
    # Without a config the limit is the 64 MiB default: give the server the
    # oversize line bounded_lines would give it, not 64 MiB of input.
    from semgate.serve import Server
    home, project = isolated
    monkeypatch.chdir(project)
    out = io.StringIO()
    server = Server(str(tmp_path / "missing.json"), out)
    server.reject_oversize(hookinput.OversizeLine(5000, 2048, '{"id": 7, "host": "opencode"'))
    server.drain()
    server.close()
    (answer,) = [json.loads(l) for l in out.getvalue().splitlines()]
    assert answer["id"] == 7 and answer["decision"] == "deny"
    records = list(Ledger(str(home / ".semgate" / "opencode" / "ledger.jsonl")).records())
    assert [r["detail"]["reason"] for r in records if r.get("record_type") == "incident"] == ["payload_over_limit"]
    assert _files(project) == []


def test_early_ledger_path(tmp_path, isolated):
    home, _ = isolated
    fallback = os.path.join(str(home), ".semgate", "claude", "ledger.jsonl")
    good = tmp_path / "c.json"
    good.write_text(json.dumps({"ledger_file": str(tmp_path / "l.jsonl")}), encoding="utf-8")
    assert hookinput.early_ledger_path(str(good), "claude") == str(tmp_path / "l.jsonl")
    assert hookinput.early_ledger_path({"ledger_file": "x/l.jsonl"}, "claude") == "x/l.jsonl"
    assert hookinput.early_ledger_path({}, "claude") == fallback      # as the normal path (storepaths.resolve)
    # a relative ledger_file in a config file: against the config's folder, not the cwd
    agy = tmp_path / "proj" / ".antigravity"
    agy.mkdir(parents=True)
    (agy / "semgate.json").write_text(json.dumps({"ledger_file": ".antigravity/semgate/ledger.jsonl"}), encoding="utf-8")
    assert hookinput.early_ledger_path(str(agy / "semgate.json"), "antigravity") ==         str(tmp_path / "proj" / ".antigravity" / "semgate" / "ledger.jsonl")
    (agy / "empty.json").write_text("{}", encoding="utf-8")
    assert hookinput.early_ledger_path(str(agy / "empty.json"), "claude") == fallback
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    for config in (str(tmp_path / "missing.json"), str(bad), None, [1]):
        assert hookinput.early_ledger_path(config, "claude") == fallback, config
    assert hookinput.early_ledger_path(None, "../x") == os.path.join(str(home), ".semgate", "x", "ledger.jsonl")
    assert hookinput.early_ledger_path(None, "") == os.path.join(str(home), ".semgate", "unknown", "ledger.jsonl")


# ------------------------------------------------------------------ expected maximum and S5


@pytest.mark.parametrize("model,tokens", [
    ("claude-opus-5-5", 128000), ("claude-opus-5-5[1m]", 128000), ("claude-haiku-4-5-20251001", 64000),
    ("anthropic.claude-sonnet-4-5-20250929-v1:0", 64000), ("claude-opus-4-5@20251101", 64000),
    ("gpt-5.5", 128000), ("openai/gpt-5.5-2026-04-23", 128000), ("gemini-3.8-flash", 65536),
    ("gpt-5-codex", None), ("claude-opus-4-1", None), ("claude-opus-5-7", None), ("", None), ("mystery", None),
])
def test_model_limits_lookup(model, tokens):
    entry = payloadsize.lookup(model)
    assert (entry["max_output_tokens"] if entry else None) == tokens


def test_limits_table_has_sources_and_a_date():
    raw = json.loads((ROOT / "semgate" / "data" / "model_limits.json").read_text(encoding="utf-8"))
    assert raw["retrieved"] == "2026-09-23" and raw["bytes_per_token"] == 4 and raw["safety_factor"] == 4
    assert all(m["source"] and m["max_output_tokens"] > 0 for m in raw["models"])


def test_describe_flags_an_input_larger_than_one_response():
    big = {"content": "a" * (64000 * 16 + 10)}
    ev = payloadsize.describe(2_000_000, big, "claude-haiku-4-5")
    assert ev["anomaly"] is True and ev["expected_max_bytes"] == 1_024_000
    assert payloadsize.describe(10, big, "unknown-model")["anomaly"] is False          # no expectation, no anomaly


class Capture(JudgeProvider):
    name = "capture"

    def __init__(self):
        self.states = []

    def evaluate(self, state, questions):
        self.states.append(dict(state))
        out = {}
        for q, spec in questions.items():
            if spec.get("type") == "choice":
                out[q] = PredicateAnswer(q, value="run", confidence=0.95, raw={"probabilities": {"run": 0.95, "review": 0.04, "block": 0.01}})
            elif spec.get("type") == "score":
                out[q] = PredicateAnswer(q, value=1.0, confidence=0.9, raw={"probabilities": {}})
            else:
                out[q] = PredicateAnswer(q, probability=0.9, confidence=0.8)
        return out


def test_s5_reaches_the_model_only_when_switched_on_and_never_decides(tmp_path):
    from conftest import make_envelope
    e = make_envelope("write", {"path": "/home/me/proj/src/big.py", "content": "a" * (64000 * 16 + 10)},
                      evaluated_at="2026-09-18T08:00:00Z")
    ev = payloadsize.describe(1_100_000, dict(e.action.arguments), "claude-haiku-4-5")
    dev = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    dev_s5 = Policy.load(str(ROOT / "policies" / "router_policy_dev_s5.json"))
    p0, p1 = Capture(), Capture()
    l0, l1 = Ledger(str(tmp_path / "l0.jsonl")), Ledger(str(tmp_path / "l1.jsonl"))
    d0 = judge(e, dev, provider=p0, ledger=l0, payload=ev)
    d1 = judge(e, dev_s5, provider=p1, ledger=l1, payload=ev)
    assert "code_signals" not in p0.states[0]
    assert "larger than the model can write in one response (about 1,000 KB for claude-haiku-4-5)" in p1.states[0]["code_signals"]
    assert d0.decision == d1.decision                               # a fact, not a block
    for d, ledger in ((d0, l0), (d1, l1)):
        assert d.evidence["payload"]["anomaly"] is True
        inc = [r for r in ledger.records() if r.get("record_type") == "incident"]
        assert inc and inc[0]["kind"] == "payload_anomaly" and inc[0]["detail"]["judgment_id"] == d.envelope_digest
    fired = d1.evidence["code_signals"]["fired"]
    assert [f["id"] for f in fired] == [payloadsize.S5_ID] and d1.evidence["code_signals"]["sent"] is True


def test_dev_s5_is_dev_plus_the_signal():
    """dev_s5 is an experiment built on dev before dev adopted the post-tool
    secret-intent question (2026-09-23) and approval by chat reply
    (2026-09-24): compare against dev minus both."""
    a = json.loads((ROOT / "policies" / "router_policy_dev.json").read_text(encoding="utf-8"))
    a["router"].pop("test_run_facts", None)          # adopted 2026-09-25, from dev_testrun
    a["router"].pop("test_run_build_facts", None)    # adopted 2026-09-26, from dev_buildfacts
    a["router"]["thresholds"].pop("test_damage_withholds_edit_allow", None)    # adopted 2026-09-26, from dev_s4allow
    a["router"].pop("exposure_questions")
    a["router"]["thresholds"].pop("exposure_intended_min")
    for key in ("chat_approval", "approval_questions", "chat_approval_limits"):
        a["router"].pop(key)
    a["router"]["thresholds"].pop("chat_approval_min")
    for key in ("trust_requests", "trust_questions", "pin_requests", "pin_questions"):      # adopted 2026-09-24
        a["router"].pop(key)
    for key in ("trust_request_min", "pin_request_min"):
        a["router"]["thresholds"].pop(key)
    a["router"]["code_signals"].remove("S6_link_placement")        # adopted 2026-09-24, after dev_s5
    b = json.loads((ROOT / "policies" / "router_policy_dev_s5.json").read_text(encoding="utf-8"))
    assert b["router"]["code_signals"] == a["router"]["code_signals"] + ["S5_payload_size"]
    for raw in (a, b):
        raw.pop("name"); raw.pop("provenance"); raw["router"].pop("code_signals")
    assert a == b
    assert "S5_payload_size" not in json.loads((ROOT / "policies" / "router_policy_dev.json").read_text())["router"]["code_signals"]


def test_telemetry_keeps_sizes_not_content():
    from semgate import telemetry
    rec = {"record_type": "judgment", "ts": "2026-09-23T00:00:00Z",
           "envelope": {"action": {"tool": "bash", "arguments": {"command": "ls"}}},
           "decision": {"decision": "allow", "evidence": {"payload": {"hook_payload_bytes": 10, "tool_input_bytes": 5,
                                                                       "model": "m", "expected_max_bytes": None, "anomaly": False,
                                                                       "extra": "secret"}}}}
    clean = telemetry.telemetry_record(rec)
    assert clean["payload"] == {"hook_payload_bytes": 10, "tool_input_bytes": 5, "model": "m", "expected_max_bytes": None, "anomaly": False}
