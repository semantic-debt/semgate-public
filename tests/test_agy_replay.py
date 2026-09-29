"""Hermetic replay tests using synthetic on-disk Antigravity-format data.

No personal session history, home-directory installation, network or model API
is required. The nine actions are a format fixture, not historical observations.
"""
import json
from pathlib import Path

import pytest

from semgate.extractor import AgySessionExtractor, normalize_args
from semgate.ledger import Ledger
from semgate.policy import Policy
from semgate.providers.fake import FakeProvider
from semgate.replay_offline import replay_actions

ROOT = Path(__file__).resolve().parents[1]
SESSION_ID = "00000000-0000-4000-8000-000000000001"


@pytest.fixture
def synthetic_session(tmp_path):
    agy_dir = tmp_path / "agy-fixture"
    transcript = agy_dir / "brain" / SESSION_ID / ".system_generated" / "logs" / "transcript.jsonl"
    transcript.parent.mkdir(parents=True)
    records = [{"type": "USER_INPUT", "step_index": 0,
                "content": "<USER_REQUEST>Inspect the synthetic fixture</USER_REQUEST>"}]
    for index in range(9):
        step = 1 + index * 3
        name = "read_url_content" if index == 0 else "run_command"
        arguments = ({"Url": json.dumps("https://example.test")}
                     if index == 0 else {"CommandLine": "echo fixture-" + str(index)})
        if index == 2:
            arguments = {"CommandLine": "ffprobe fixture.mp4"}
        records.append({"type": "PLANNER_RESPONSE", "step_index": step,
                        "tool_calls": [{"name": name, "args": arguments}]})
    transcript.write_text("\n".join(json.dumps(record) for record in records) + "\n", encoding="utf-8")
    logs = agy_dir / "log"; logs.mkdir()
    (logs / "cli-fixture.log").write_text(
        f"Streaming conversation {SESSION_ID}\n"
        'Surfacing tool confirmation: "read_url_content" at step 2\n'
        f"Responding to tool confirmation: convID={SESSION_ID}, stepIdx=2, approved=true\n"
        'Surfacing tool confirmation: "run_command" at step 8\n'
        f"Responding to tool confirmation: convID={SESSION_ID}, stepIdx=8, approved=true\n",
        encoding="utf-8",
    )
    return AgySessionExtractor(agy_dir=str(agy_dir))


def test_normalize_args():
    raw = {"Url": '\"https://example.com\"', "Count": "42", "Raw": "plain text"}
    norm = normalize_args(raw)
    assert norm["Url"] == "https://example.com"
    assert norm["Raw"] == "plain text"


def test_extract_synthetic_session(synthetic_session):
    actions = synthetic_session.extract_session(SESSION_ID)
    assert len(actions) == 9
    a0 = actions[0]
    assert a0.tool == "read_url_content"
    assert a0.proposed_step_idx == 1
    assert a0.execution_step_idx == 2
    assert a0.was_agy_approval_point is True
    assert a0.agy_approval_response == "approved"
    assert a0.arguments.get("Url") == "https://example.test"
    assert a0.user_prompt == "Inspect the synthetic fixture"
    a2 = actions[2]
    assert a2.tool == "run_command"
    assert a2.proposed_step_idx == 7
    assert a2.execution_step_idx == 8
    assert a2.was_agy_approval_point is True
    assert a2.agy_approval_response == "approved"
    assert "fixture.mp4" in a2.arguments.get("CommandLine", "")
    assert sum(action.was_agy_approval_point for action in actions) == 2


def test_missing_session_returns_no_actions(synthetic_session):
    assert synthetic_session.extract_session("missing-session") == []


def test_replay_offline_with_fake_provider(tmp_path, synthetic_session):
    actions = synthetic_session.extract_session(SESSION_ID)
    grant_data = {"grant_id": "test-grant", "principal": "test",
                  "purpose": "Testing offline replay", "allowed_domains": ["localhost"]}
    policy = Policy.load(str(ROOT / "policies" / "default_policy.json"))
    provider = FakeProvider(script={"outside_grant_purpose": 0.01, "outside_project_boundary": 0.01})
    ledger_file = tmp_path / "replay_ledger.jsonl"
    ledger = Ledger(str(ledger_file))
    workspace = tmp_path / "workspace"; workspace.mkdir()
    summary = replay_actions(actions, policy, grant_data, provider=provider,
                             ledger=ledger, workspace_path=str(workspace))
    assert summary.total_actions == 9
    assert summary.total_approval_points == 2
    assert ledger_file.exists()
    assert len(ledger.judgments()) == 9


# ---------- no owner-specific defaults (prepublish cleanup) ----------

def _workspace_with_grant(tmp_path):
    workspace = tmp_path / "proj"
    grant_dir = workspace / ".antigravity" / "semgate"
    grant_dir.mkdir(parents=True)
    (grant_dir / "grant.json").write_text(json.dumps({
        "grant_id": "test-grant", "principal": "test", "purpose": "Testing offline replay",
        "allowed_domains": ["localhost"]}), encoding="utf-8")
    return workspace


def test_replay_main_defaults_live_in_the_workspace(tmp_path, synthetic_session, capsys):
    from semgate import replay_offline
    workspace = _workspace_with_grant(tmp_path)
    rc = replay_offline.main(["--workspace", str(workspace), "--agy-dir", str(synthetic_session.agy_dir),
                              "--session", SESSION_ID, "--provider", "fake"])
    assert rc == 0
    ledger_file = workspace / ".antigravity" / "semgate" / "replay_ledger.jsonl"
    assert len(Ledger(str(ledger_file)).judgments()) == 9
    assert f"Target session: {SESSION_ID}\n" in capsys.readouterr().out


def test_replay_main_workspace_defaults_to_current_directory(tmp_path, synthetic_session, monkeypatch):
    from semgate import replay_offline
    workspace = _workspace_with_grant(tmp_path)
    monkeypatch.chdir(workspace)
    assert replay_offline.main(["--agy-dir", str(synthetic_session.agy_dir), "--session", SESSION_ID,
                                "--provider", "fake"]) == 0
    assert (workspace / ".antigravity" / "semgate" / "replay_ledger.jsonl").is_file()


def test_replay_main_without_a_session_is_an_error(tmp_path, capsys):
    from semgate import replay_offline
    workspace = _workspace_with_grant(tmp_path)
    empty = tmp_path / "empty-agy"; empty.mkdir()
    rc = replay_offline.main(["--workspace", str(workspace), "--agy-dir", str(empty), "--provider", "fake"])
    assert rc == 2
    assert "no agy session with a transcript" in capsys.readouterr().err
    assert not (workspace / ".antigravity" / "semgate" / "replay_ledger.jsonl").exists()


def test_replay_default_policy_is_the_packaged_dev_policy():
    from semgate import replay_offline
    from semgate.gate import policy_dir
    assert Path(replay_offline.DEFAULT_POLICY) == policy_dir() / "router_policy_dev.json"
    assert Path(replay_offline.DEFAULT_POLICY).is_file()
    assert not Path(replay_offline.DEFAULT_GRANT).is_absolute()
    assert not Path(replay_offline.DEFAULT_LEDGER).is_absolute()


def test_typesafe_provider_failure_is_not_replaced_by_fake(monkeypatch):
    from semgate import replay_offline

    def boom(*a, **k):
        raise RuntimeError("no key")
    monkeypatch.setattr(replay_offline, "TypeSafeProvider", boom)
    with pytest.raises(RuntimeError):
        replay_offline.get_default_provider("typesafe")


def test_hook_event_workspace_defaults_to_current_directory(tmp_path, synthetic_session, monkeypatch):
    monkeypatch.chdir(tmp_path)
    action = synthetic_session.extract_session(SESSION_ID)[0]
    assert action.to_hook_event()["workspacePaths"] == [str(tmp_path)]
    assert action.to_hook_event(workspace_path="/w")["workspacePaths"] == ["/w"]


def test_extractor_default_folder_follows_home(tmp_path, monkeypatch):
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(tmp_path))
    assert AgySessionExtractor().agy_dir == tmp_path / ".gemini" / "antigravity-cli"


def test_policy_dir_is_the_tree_under_test():
    """The shipped policies come from the checkout whose semgate is imported,
    not from the checkout an editable install points to (a git worktree on
    PYTHONPATH read the main checkout's dev policy before 2026-09-27)."""
    from semgate.gate import policy_dir
    root = Path(__file__).resolve().parents[1]
    assert policy_dir() == root / "policies"
    from semgate.gate import POLICY_ALIASES
    assert POLICY_ALIASES["dev"] == root / "policies" / "router_policy_dev.json"
