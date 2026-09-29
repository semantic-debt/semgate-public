"""The judge must never execute the proposed action or mutate anything
besides its own ledger."""
import tempfile
import os
import subprocess
from pathlib import Path

import pytest

from semgate.judge import judge
from semgate.ledger import Ledger
from semgate.providers.fake import FakeProvider

from conftest import make_envelope

MARKER = Path("/tmp/semgate-must-never-exist")


def teardown_module():
    MARKER.unlink(missing_ok=True)


def test_proposed_command_is_never_executed(policy, tmp_path):
    MARKER.unlink(missing_ok=True)
    env = make_envelope(tool="bash", arguments={"command": f"touch {MARKER}"})
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    judge(env, policy, provider=FakeProvider(script={}), ledger=ledger)
    assert not MARKER.exists()


def test_judge_writes_only_the_ledger(policy, tmp_path, monkeypatch):
    # Watch folders the test controls: Python's temp dir is pointed at a fresh
    # folder, and the ledger's own folder must end up holding only the ledger.
    # (Listing the real OS temp dir is not portable: /tmp does not exist on
    # Windows and C:\WINDOWS\TEMP may not be listable.)
    watched = tmp_path / "tempdir"
    watched.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(watched))
    for var in ("TMP", "TEMP", "TMPDIR"):
        monkeypatch.setenv(var, str(watched))
    env = make_envelope(tool="write", arguments={"path": "/home/me/proj/src/new.py", "content": "print('hi')"})
    ledger = Ledger(str(tmp_path / "ledger.jsonl"))
    judge(env, policy, provider=FakeProvider(script={}), ledger=ledger)
    assert list(watched.iterdir()) == []
    # ledger.jsonl.lock: the empty sidecar that carries the ledger's cross-process lock
    assert sorted(p.name for p in tmp_path.iterdir()) == ["ledger.jsonl", "ledger.jsonl.lock", "tempdir"]
    assert (tmp_path / "ledger.jsonl.lock").stat().st_size == 0
    assert not Path("/home/me/proj/src/new.py").exists()


def test_judge_spawns_no_subprocess(policy, monkeypatch, tmp_path):
    def boom(*args, **kwargs):
        raise AssertionError("judge must not spawn subprocesses")

    monkeypatch.setattr(subprocess, "run", boom)
    monkeypatch.setattr(subprocess, "Popen", boom)
    monkeypatch.setattr(os, "system", boom)
    env = make_envelope(tool="bash", arguments={"command": "echo hello"})
    judge(env, policy, provider=FakeProvider(script={}), ledger=Ledger(str(tmp_path / "l.jsonl")))
