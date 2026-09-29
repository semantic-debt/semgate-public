"""Keyed fingerprints of exposed secrets (semgate.fingerprints).

A plain sha256 of a short password can be reversed by hashing guesses. The
exposure store keeps HMAC-SHA256 with a random per-install key instead. Every
fake secret is built at runtime (string concatenation)."""
import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from semgate import exposures, fingerprints

ROOT = Path(__file__).parents[1]
ENV_PW = "hunter" + "2abcXY"
GH = "ghp_" + "A1b2C3d4" * 4 + "Zz9Y"
KW = dict(host="claude", manifest_host="claude", tool="Bash", detail="cat .env", step="t1")


@pytest.fixture(autouse=True)
def _isolated(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE"):
        monkeypatch.setenv(var, str(home))
    monkeypatch.delenv("SEMGATE_CONFIG", raising=False)
    fingerprints.clear_cache()
    yield
    fingerprints.clear_cache()


def _cfg(tmp_path, **extra):
    cfg = {"ledger_file": str(tmp_path / "state" / "ledger.jsonl")}
    cfg.update(extra)
    return cfg


def _records(cfg, sid="s1"):
    path = exposures.session_path(exposures.store_dir(cfg), sid)
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()]


def _incidents(cfg):
    path = Path(cfg["ledger_file"])
    if not path.exists():
        return []
    return [r for r in (json.loads(l) for l in path.read_text(encoding="utf-8").splitlines()) if r.get("record_type") == "incident"]


def _all_bytes(root):
    return b"\n".join(p.read_bytes() for p in Path(root).rglob("*") if p.is_file())


def test_short_password_is_not_recoverable_by_hashing_a_guess(tmp_path):
    cfg = _cfg(tmp_path)
    exposures.on_tool_output(cfg, session_id="s1", output="DB_PASSWORD=" + ENV_PW, **KW)
    fp = _records(cfg)[0]["fingerprint"]
    alg, kid, digest = fp.split(":")
    assert alg == "hmac-sha256" and len(kid) == 8 and len(digest) == 64
    # Someone with the files but not the key hashes the right guess: no match anywhere.
    blob = _all_bytes(tmp_path / "state").decode("utf-8", "replace")
    assert hashlib.sha256(ENV_PW.encode()).hexdigest() not in blob
    assert hmac.new(os.urandom(32), ENV_PW.encode(), hashlib.sha256).hexdigest() != digest
    # With the key (only on this machine) the same guess matches: the fingerprint is keyed, not random.
    key = (tmp_path / "state" / "fingerprint.key").read_bytes()
    assert len(key) == 32 and hmac.new(key, ENV_PW.encode(), hashlib.sha256).hexdigest() == digest
    assert key not in _all_bytes(tmp_path / "state" / "exposures")


def test_same_secret_same_fingerprint_across_processes(tmp_path):
    cfg = _cfg(tmp_path)
    exposures.on_tool_output(cfg, session_id="s1", output="TOKEN=" + GH, **KW)
    mine = _records(cfg)[0]["fingerprint"]
    code = ("import sys; from pathlib import Path; from semgate import fingerprints as f; "
            "print(f.fingerprint(f.load_key(Path(sys.argv[1]))[0], sys.argv[2]))")
    outs = {subprocess.run([sys.executable, "-c", code, str(tmp_path / "state" / "fingerprint.key"), GH], cwd=str(ROOT),
                           capture_output=True, text=True, timeout=60, check=True).stdout.strip() for _ in range(2)}
    assert outs == {mine}
    # another session of the same install: same fingerprint; the agent is told again (per session)
    assert exposures.on_tool_output(cfg, session_id="s2", output=GH, **KW)
    assert _records(cfg, "s2")[0]["fingerprint"] == mine


@pytest.mark.skipif(os.name == "nt", reason="POSIX file mode")
def test_key_file_mode_is_0600(tmp_path):
    key, note = fingerprints.load_key(tmp_path / "k" / "fingerprint.key")
    assert note == "" and len(key) == 32
    assert (tmp_path / "k" / "fingerprint.key").stat().st_mode & 0o777 == 0o600


RACE = r"""
import sys, time
from pathlib import Path
from semgate import fingerprints
go = Path(sys.argv[2])
while not go.exists():
    time.sleep(0.001)
print(fingerprints.load_key(Path(sys.argv[1]))[0].hex())
"""


def test_two_processes_creating_the_key_at_once_get_one_key(tmp_path):
    path = tmp_path / "race" / "fingerprint.key"
    go = tmp_path / "go"
    procs = [subprocess.Popen([sys.executable, "-c", RACE, str(path), str(go)], cwd=str(ROOT), stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, text=True) for _ in range(4)]
    time.sleep(1.0)                          # let every process start and wait at the barrier
    go.write_text("x")
    outs = [p.communicate(timeout=60) for p in procs]
    assert all(p.returncode == 0 for p in procs), [o[1] for o in outs]
    keys = {o[0].strip() for o in outs}
    assert len(keys) == 1 and bytes.fromhex(keys.pop()) == path.read_bytes()
    assert sorted(p.name for p in path.parent.iterdir()) == ["fingerprint.key", "fingerprint.key.lock"]   # no temp files left


def test_unusable_key_file_is_moved_aside_and_replaced(tmp_path):
    cfg = _cfg(tmp_path)
    kp = tmp_path / "state" / "fingerprint.key"
    kp.parent.mkdir(parents=True)
    kp.write_bytes(b"short")
    exposures.on_tool_output(cfg, session_id="s1", output="TOKEN=" + GH, **KW)
    assert len(kp.read_bytes()) == 32 and _records(cfg)[0]["fingerprint"]
    assert [p.read_bytes() for p in kp.parent.glob("fingerprint.key.bad-*")] == [b"short"]
    inc = _incidents(cfg)
    assert inc[-1]["kind"] == "fingerprint_key_replaced" and "holds 5 bytes" in inc[-1]["detail"]["reason"]


def test_no_key_records_without_fingerprint_dedups_by_masked_preview_and_never_blocks(tmp_path):
    blocker = tmp_path / "not_a_dir"
    blocker.write_text("a file where the key folder should be")
    cfg = _cfg(tmp_path, secret_exposures={"key_file": str(blocker / "fingerprint.key")})
    first = exposures.on_tool_output(cfg, session_id="s1", output="TOKEN=" + GH, **KW)
    assert "GitHub token ghp_…Zz9Y" in first
    assert exposures.on_tool_output(cfg, session_id="s1", output="again " + GH, **KW) == ""    # de-dup by type + masked
    recs = _records(cfg)
    assert len(recs) == 1 and recs[0]["fingerprint"] is None
    assert exposures.dedup_key(recs[0]) == "masked:GitHub token:ghp_…Zz9Y"
    inc = _incidents(cfg)
    assert inc and all(i["kind"] == "fingerprint_key_unavailable" for i in inc)
    assert GH.encode() not in _all_bytes(tmp_path / "state")


def test_earlier_plain_sha256_records_stay_readable_and_are_not_rewritten(tmp_path, capsys):
    cfg = _cfg(tmp_path)
    path = exposures.session_path(exposures.store_dir(cfg), "s1")
    path.parent.mkdir(parents=True)
    legacy = {"record_type": "exposure", "schema": 1, "session_id": "s1", "host": "claude", "type": "GitHub token",
              "masked": "ghp_…Zz9Y", "sha256": hashlib.sha256(GH.encode()).hexdigest(),
              "where": {"tool": "Bash", "detail": "env", "step": "t0"}, "first_seen": "2026-09-22T10:00:00Z",
              "epoch": 1790071200, "told_agent": True}
    shown = {"record_type": "summary_shown", "session_id": "s1", "sha256": [legacy["sha256"]], "ts": "2026-09-22T10:00:01Z"}
    first_lines = (json.dumps(legacy) + "\n" + json.dumps(shown) + "\n").encode()
    path.write_bytes(first_lines)
    # The Stop summary honors the old summary_shown list: nothing new to show.
    assert exposures.stop_summary(cfg, "s1") == ""
    # A new-format fingerprint is another namespace: the agent is told once more, and the old lines stay as they were.
    assert "GitHub token ghp_…Zz9Y" in exposures.on_tool_output(cfg, session_id="s1", output=GH, **KW)
    assert path.read_bytes().startswith(first_lines)
    rep = exposures.collect([exposures.store_dir(cfg)])
    fps = [e["fingerprint"] for e in rep["sessions"][0]["exposures"]]
    assert fps[0] == "sha256:" + legacy["sha256"] and fps[1].startswith("hmac-sha256:")
