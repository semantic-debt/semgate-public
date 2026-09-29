"""`semgate eval` exits 3 when a live run does not measure the judge.

Found 2026-09-24: during a TypeSafe credit outage every case of a live eval
abstained to ask. The report looked cautious ("0 false allows") but the
model never answered. A live run now exits 3 with the reason on stderr when
any case got no model answer or the judge answered 0 cases, unless
--allow-provider-errors. --provider none and scripted have no live judge and
keep their exit codes (CI's deterministic steps)."""
import json
from pathlib import Path

import pytest

from semgate import cli
from semgate.eval.runner import JudgeCallCounter, validity_problems
from semgate.providers.fake import FakeProvider

ROOT = Path(__file__).resolve().parent.parent
DEV = str(ROOT / "policies" / "router_policy_dev.json")
DRIFT = str(ROOT / "fixtures" / "eval" / "trace-drift.jsonl")
INJECTION = str(ROOT / "fixtures" / "eval" / "injection.jsonl")
CHAT = str(ROOT / "fixtures" / "eval" / "chat-approval.jsonl")
CHAT_POLICY = str(ROOT / "policies" / "router_policy_dev_chatapprove.json")


def _live(monkeypatch, provider):
    """--provider openrouter builds `provider` (no network, no key)."""
    from semgate.providers import registry
    provider.name = "openrouter"
    monkeypatch.setattr(registry, "live_provider", lambda name, model=None: provider)
    return provider


def _run(args, tmp_path):
    out = tmp_path / "report.json"
    rc = cli.main(["eval", *args, "--output", str(out)])
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_live_run_with_provider_outage_exits_3_and_says_why(monkeypatch, tmp_path, capsys):
    _live(monkeypatch, FakeProvider({}, fail=True))
    rc, report = _run(["--provider", "openrouter", "--policy", DEV, "--cases", DRIFT], tmp_path)
    err = capsys.readouterr().err
    assert rc == 3
    # Every case that reaches the failing provider is a provider error; cases
    # decided by the deterministic layer first do not, so this ties to the
    # number of judge calls, not len(cases).
    assert report["provider_errors"] == report["judge_calls"]["asked"] > 0
    assert report["judge_calls"]["answered"] == 0 and report["judge_calls"]["asked"] > 0
    assert "INVALID RUN" in err and "got no model answer" in err and "answered 0 times" in err
    assert report["invalid_run"]


def test_allow_provider_errors_keeps_the_normal_exit_code(monkeypatch, tmp_path, capsys):
    _live(monkeypatch, FakeProvider({}, fail=True))
    rc, report = _run(["--provider", "openrouter", "--policy", DEV, "--cases", DRIFT, "--allow-provider-errors"], tmp_path)
    assert rc in (0, 2) and report["invalid_run"]
    assert "--allow-provider-errors given" in capsys.readouterr().err


def test_live_run_where_the_judge_answers_is_valid(monkeypatch, tmp_path, capsys):
    _live(monkeypatch, FakeProvider({}))
    rc, report = _run(["--provider", "openrouter", "--policy", DEV, "--cases", DRIFT], tmp_path)
    assert rc in (0, 2)
    assert report["provider_errors"] == 0 and report["judge_calls"]["answered"] > 0
    assert "invalid_run" not in report and "INVALID RUN" not in capsys.readouterr().err


def test_live_run_that_never_reaches_the_judge_exits_3(monkeypatch, tmp_path, capsys):
    """A run where no case reached the judge (e.g. every case stopped at a
    deterministic layer, or the provider was never wired) measures nothing."""
    _live(monkeypatch, FakeProvider({}))
    monkeypatch.setattr(cli, "evaluate_cases", lambda cases, policy, provider=None, scripted=False: {
        "cases": [{"case_id": c.case_id} for c in cases], "provider_errors": 0, "boundary_violations": []})
    rc, report = _run(["--provider", "openrouter", "--policy", DEV, "--cases", DRIFT], tmp_path)
    assert rc == 3 and report["judge_calls"] == {"asked": 0, "answered": 0, "failed": 0}
    assert "0 calls" in capsys.readouterr().err


def test_chat_approval_live_outage_exits_3(monkeypatch, tmp_path):
    _live(monkeypatch, FakeProvider({}, fail=True))
    rc, report = _run(["--provider", "openrouter", "--policy", CHAT_POLICY, "--cases", CHAT], tmp_path)
    assert rc == 3 and report["provider_errors"] > 0


@pytest.mark.parametrize("cases", [INJECTION, DRIFT])
def test_provider_none_still_exits_0(cases, tmp_path):
    """The CI deterministic steps (.github/workflows/ci.yml): no judge, no error."""
    rc, report = _run(["--provider", "none", "--policy", DEV, "--cases", cases], tmp_path)
    assert rc == 0 and "judge_calls" not in report and "invalid_run" not in report


def test_scripted_chat_approval_still_exits_0(tmp_path):
    rc, _ = _run(["--provider", "scripted", "--policy", CHAT_POLICY, "--cases", CHAT], tmp_path)
    assert rc == 0


def test_counter_forwards_attributes_and_counts():
    inner = FakeProvider({}, fail=False)
    inner.model = "m-1"
    c = JudgeCallCounter(inner)
    assert c.name == "fake" and c.model == "m-1" and c.inner is inner
    c.evaluate({}, {})
    assert c.counts() == {"asked": 1, "answered": 1, "failed": 0}
    inner.fail = True
    with pytest.raises(Exception):
        c.evaluate({}, {})
    assert c.counts() == {"asked": 2, "answered": 1, "failed": 1}


def test_validity_problems_rules():
    rep = {"cases": [{}, {}], "provider_errors": 0}
    assert validity_problems(rep, None) == []                       # no live judge expected
    assert validity_problems(rep, {"asked": 2, "answered": 2}) == []
    assert validity_problems({"cases": [], "provider_errors": 0}, {"asked": 0, "answered": 0}) == []
    assert "0 calls" in validity_problems(rep, {"asked": 0, "answered": 0})[0]
    assert "1 of 2" in validity_problems({**rep, "provider_errors": 1}, {"asked": 2, "answered": 1})[0]
