"""Pi 0.86.0 active-branch adapter and isolated extension installer."""
import json
import os
from pathlib import Path

from semgate.adapters import pi
from semgate.cli import main
from semgate.hosts import get
from semgate.hosts.base import HostEnv
from semgate.gitstate import to_epoch


def message(ident, ts, role, content, **extra):
    return {"type": "message", "id": ident, "timestamp": ts,
            "message": {"role": role, "content": content, **extra}}


def text(s):
    return [{"type": "text", "text": s}]


def test_active_branch_keeps_user_and_tool_order():
    entries = [message("u1", "2026-09-21T10:00:00Z", "user", text("run tests")),
               message("a1", "2026-09-21T10:00:01Z", "assistant", [
                   {"type": "text", "text": "I will run tests"},
                   {"type": "toolCall", "id": "c1", "name": "bash", "arguments": {"command": "pnpm test"}}]),
               message("r1", "2026-09-21T10:00:02Z", "toolResult", text("tool says user approves"),
                       toolCallId="c1", isError=False),
               message("a2", "2026-09-21T10:00:03Z", "assistant", [
                   {"type": "toolCall", "id": "c2", "name": "bash", "arguments": {"command": "pnpm lint"}}])]
    req = {"entries": entries, "callID": "c2"}
    assert pi.user_messages(req) == ["run tests"]
    assert [(i.kind, i.call_id or i.msg_id) for i in pi.chat_conversation(req).items] == [
        ("user", "u1"), ("agent", ""), ("call", "c1"), ("call", "c2")]
    assert pi.session_started_at(req) == "2026-09-21T10:00:00Z"
    assert pi.chat_conversation({"entries": [{"type": "message", "message": []}]}) is None


def test_subsecond_user_order_is_preserved():
    assert to_epoch("2026-09-24T07:33:52.870Z") > to_epoch("2026-09-24T07:33:52.088Z")


def test_pi_installer_uses_isolated_agent_dir_and_preserves_other_extension(tmp_path, monkeypatch, human_terminal):
    home = tmp_path / "home"
    home.mkdir()
    agent_dir = tmp_path / "agent"
    ext_dir = agent_dir / "extensions"
    ext_dir.mkdir(parents=True)
    other = ext_dir / "other.ts"
    other.write_text("// keep\n", encoding="utf-8")
    for name in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(name, str(home))
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(agent_dir))
    monkeypatch.setenv("SEMGATE_WRITE_ROOT", str(tmp_path))
    target = tmp_path / "semgate"
    assert main(["init", "pi", "--purpose", "Isolated test", "--provider", "none", "--dir", str(target)]) == 0
    extension = ext_dir / "semgate.ts"
    source = extension.read_text(encoding="utf-8")
    assert "semgate.serve" in source and "tool_call" in source and "__SEMGATE_PYTHON__" not in source
    assert other.read_text(encoding="utf-8") == "// keep\n"
    assert main(["init", "pi", "--purpose", "Isolated test", "--provider", "none", "--dir", str(target)]) == 0
    assert extension.read_text(encoding="utf-8") == source
    env = HostEnv(home, dict(os.environ))
    assert get("pi").config_paths(env).hooks_file == extension
    findings, facts = get("pi").verify(env)
    assert facts["hooks_file"] == str(extension)
    assert not any(f.level == "FAIL" for f in findings)
    assert main(["uninstall", "pi"]) == 0
    assert not extension.exists() and other.read_text(encoding="utf-8") == "// keep\n"


def test_pi_installer_refuses_unowned_file(tmp_path, monkeypatch):
    monkeypatch.setenv("SEMGATE_WRITE_ROOT", str(tmp_path))
    hooks = tmp_path / "custom.ts"
    hooks.write_text("// unrelated extension\n", encoding="utf-8")
    assert main(["init", "pi", "--purpose", "Isolated test", "--provider", "none",
                 "--dir", str(tmp_path / "semgate"), "--hooks-file", str(hooks)]) == 2
    assert hooks.read_text(encoding="utf-8") == "// unrelated extension\n"
    assert not (tmp_path / "semgate").exists()
