"""scripts/publish_scan.py and scripts/make-public-snapshot.sh."""
import argparse
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("publish_scan", ROOT / "scripts" / "publish_scan.py")
ps = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(ps)


def test_glob_rules_match_git_glob():
    assert ps.matches("docs/upstream/a/b.md", ["docs/upstream/"])
    assert not ps.matches("docs/upstreamx.md", ["docs/upstream/"])
    assert ps.matches("evals/agenttrust-heldout-v3c-report.json", ["evals/agenttrust-heldout-v*-report.json"])
    assert not ps.matches("evals/x/agenttrust-heldout-v1-report.json", ["evals/agenttrust-heldout-v*-report.json"])
    assert ps.matches("a/b/c.json", ["**/c.json"]) and ps.matches("c.json", ["**/c.json"])
    assert ps.matches("results/codex-0.153.1.json", ["results/codex-*.json"])


def test_attribution_pattern_finds_trailers_but_not_its_own_source():
    assert ps.AI_ATTR.search("Co-" + "Authored-By: Someone <x@y>")
    assert ps.AI_ATTR.search("Generated " + "with [Claude Code](https://claude.com)")
    assert not ps.AI_ATTR.search((ROOT / "scripts" / "publish_scan.py").read_text(encoding="utf-8"))


def test_user_path_pattern():
    names = [next(g for g in m.groups() if g) for m in ps.USER_PATH.finditer(
        r'C:\Users\alice\x "C:\\Users\\bob\\y" /home/jane/z /c/Users/jdoe/w C:/Users/<user>/ok')]
    assert names == ["alice", "bob", "jane", "jdoe"]


def test_email_pattern_skips_decorators_and_file_names():
    text = r'"\n@pytest.fixture" 0.10.0@setup.py real.person@corp.example.org'
    hits = [m.group(0) for m in ps.EMAIL.finditer(text) if m.group(1).lower() not in ps.NOT_TLD]
    assert hits == ["real.person@corp.example.org"]


def _heldout_row(tmp_path, snap_files):
    """Run only the held-out check: private cases sit in a sub-folder, next to another sub-folder."""
    case = json.dumps({"case_id": "launch-0001", "prompt": "held-out prompt " + "x" * 200})
    private = tmp_path / "private"
    (private / "launch-2026-09" / "sources").mkdir(parents=True)
    (private / "launch-2026-09" / "cases.jsonl").write_text(case + "\n", encoding="utf-8")
    snap = tmp_path / "snap"
    snap.mkdir()
    for name, text in snap_files.items():
        (snap / name).write_text(text.format(case=case), encoding="utf-8")
    a = argparse.Namespace(snapshot=str(snap), source_repo=str(tmp_path), source_commit="0" * 40, exclude=None,
                           private_dir=str(private))
    scan = ps.Scan(a)
    scan.check_heldout()
    return scan.rows[-1]


def test_heldout_check_finds_a_case_from_a_nested_private_file(tmp_path):
    row = _heldout_row(tmp_path, {"leak.jsonl": "{case}\n"})
    assert row["status"] == "FAIL"
    assert row["summary"].startswith("1 private case lines: 1 found; 1 case ids: 1 found")
    assert "whole private file in snapshot: cases.jsonl" in row["details"]


def test_heldout_check_skips_nested_folders(tmp_path):
    row = _heldout_row(tmp_path, {"ok.txt": "hello\n"})     # sub-folders must not be opened as files
    assert row["status"] == "PASS"
    assert row["summary"].startswith("1 private case lines: 0 found")


def _fake_tokens():
    """One fake per PUSH_PROTECTION format, built from parts so this file holds no match."""
    return {
        "Slack token": "xoxb-" + "0" * 12 + "-" + "0" * 12 + "-" + "EXAMPLE" * 3,
        "Slack webhook": "hooks.slack.com/services/" + "T00000000/B00000000/" + "X" * 24,
        "Stripe live key": "sk_" + "live_" + "0" * 24,
        "Google API key": "AIza" + "0" * 35,
        "SendGrid key": "SG." + "a" * 22 + "." + "b" * 43,
        "Anthropic key": "sk-ant-" + "api03-" + "a" * 40,
        "OpenAI key": "sk-" + "proj-" + "a" * 20 + "T3Blbk" + "FJ" + "b" * 20,
        "Hugging Face token": "hf_" + "a" * 34,
        "PyPI token": "pypi-" + "AgEIcHlwaS5vcmc" + "a" * 50,
        "Shopify token": "shpat_" + "0" * 32,
        "Databricks token": "dapi" + "0" * 32,
        "private key block": "-----BEGIN RSA " + "PRIVATE KEY-----\n" + ("A" * 64 + "\n") * 3,
        "Azure storage key": "AccountKey=" + "A" * 86 + "==",
    }


def _scan(tmp_path, files, cfg):
    snap = tmp_path / "snap"
    for name, text in files.items():
        (snap / name).parent.mkdir(parents=True, exist_ok=True)
        (snap / name).write_text(text, encoding="utf-8")
    a = argparse.Namespace(snapshot=str(snap), source_repo=str(tmp_path), source_commit="0" * 40, exclude=None,
                           secretfinder_root=str(ROOT))
    scan = ps.Scan(a)
    scan.cfg = cfg
    return scan


def test_push_protection_patterns_find_each_format_but_not_github_classic_tokens():
    for kind, fake in _fake_tokens().items():
        assert [k for _, k, _ in ps.push_protection_hits(f'x = "{fake}"\n')] == [kind], kind
    assert ps.push_protection_hits("ghp_" + "A" * 36 + " gho_" + "0" * 36) == []   # CRC32 checksum: GitHub lets fakes pass
    assert ps.push_protection_hits('SLACK = "xoxb-" + "' + "0" * 12 + '-EXAMPLE"') == []   # split after the prefix


def test_push_protection_check_fails_on_a_reviewed_fake_and_never_prints_it(tmp_path):
    """2026-09-29: the reviewed fake Slack token passed the secret check, and GitHub rejected the push."""
    fake = _fake_tokens()["Slack token"]
    scan = _scan(tmp_path, {"evals/gen.py": f'A = 1\n\nSLACK = "{fake}"\n',
                            "evals/split.py": f'SLACK = "xoxb-" + "{fake[5:]}"\n'},
                 {"reviewed_secrets": [{"sha16": ps.sha16(fake), "why": "a fake"}]})
    scan.check_secrets()
    scan.check_push_protection()
    secrets, push = scan.rows
    assert secrets["status"] == "PASS"                     # reviewed as a fake: the old check lets it through
    assert push["status"] == "FAIL"
    assert push["details"] == [f"evals/gen.py:3 Slack token len={len(fake)}"]
    assert fake[5:] not in json.dumps(scan.rows)            # file:line and length only, never the value


def test_push_protection_check_passes_a_clean_snapshot(tmp_path):
    scan = _scan(tmp_path, {"ok.py": 'KEY = "ghp_" + "A" * 36\n'}, {})
    scan.check_push_protection()
    assert scan.rows[-1]["status"] == "PASS"


def test_tracked_files_hold_no_push_protection_match():
    """The same formats in this repo's tracked files (minus .publish/exclude.txt), so a
    commit made straight in the public clone is checked before GitHub checks the push."""
    r = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True)
    if r.returncode != 0 or not r.stdout:
        pytest.skip("no git checkout here (the WSL copy of scripts/test-local.sh has only the files)")
    exclude = ROOT / ".publish" / "exclude.txt"
    excludes = ps.read_excludes(exclude.read_text(encoding="utf-8")) if exclude.is_file() else []
    hits = []
    for rel in r.stdout.decode("utf-8").split("\0"):
        if rel and (ROOT / rel).is_file() and not ps.matches(rel, excludes):
            text = (ROOT / rel).read_bytes().decode("utf-8", "replace")
            hits += [f"{rel}:{line} {kind} len={n}" for line, kind, n in ps.push_protection_hits(text)]
    assert hits == []


WHEEL_CFG = {"wheel_test": {"test": "tests/test_wheel_install.py", "wheel_dir_env": "SEMGATE_WHEEL_DIR"}}


def _wheel_row(tmp_path, monkeypatch, cfg=WHEEL_CFG, build_rc=0, test_rc=0, counts=(2, 0, 0, 0)):
    """Run only the wheel check, with the clone / build / test commands faked."""
    scan = _scan(tmp_path, {"pyproject.toml": "[project]\n", "tests/test_wheel_install.py": "def test(): pass\n"}, cfg)
    calls = []

    def fake_run(cmd, cwd, env, timeout):
        calls.append({"cmd": cmd, "cwd": Path(cwd), "env": env})
        if cmd[0] == "git":
            Path(cmd[-1]).mkdir()
            return 0, ""
        if "pip" in cmd:
            if build_rc:
                return build_rc, "ERROR: backend failed\n"
            wheels = Path(cmd[cmd.index("-w") + 1])
            wheels.mkdir()
            (wheels / "semgate-9.9.9-py3-none-any.whl").write_bytes(b"")
            return 0, ""
        junit = next(a.split("=", 1)[1] for a in cmd if a.startswith("--junitxml="))
        t, f, e, s = counts
        Path(junit).write_text(f'<testsuites><testsuite name="pytest" tests="{t}" failures="{f}" errors="{e}" '
                               f'skipped="{s}"/></testsuites>', encoding="utf-8")
        return test_rc, "E   AssertionError: assert 'deny' == 'ask'\n1 failed, 1 passed\n"
    monkeypatch.setattr(ps, "run_step", fake_run)
    scan.check_wheel_install()
    return scan.rows[-1], calls


def test_wheel_check_builds_from_a_clone_and_runs_the_test_with_the_wheel_dir(tmp_path, monkeypatch):
    row, calls = _wheel_row(tmp_path, monkeypatch)
    assert row["status"] == "PASS", row
    assert row["summary"] == "semgate-9.9.9-py3-none-any.whl: 2 passed, 0 failed, 0 errors, 0 skipped (exit 0)"
    clone, build, test = calls
    assert clone["cmd"][:2] == ["git", "clone"] and clone["cmd"][-2] == str(tmp_path / "snap")
    src = Path(clone["cmd"][-1])
    assert build["cwd"] == src and test["cwd"] == src          # never builds inside the snapshot folder
    assert build["cmd"][:6] == [sys.executable, "-m", "pip", "wheel", ".", "--no-deps"]
    assert test["cmd"][:7] == [sys.executable, "-m", "pytest", "-q", "tests/test_wheel_install.py", "-p", "no:cacheprovider"]
    assert test["env"]["SEMGATE_WHEEL_DIR"] == build["cmd"][build["cmd"].index("-w") + 1]
    assert "PYTHONPATH" not in test["env"]                   # conftest sets it; the test must import the clone
    assert sorted(p.name for p in (tmp_path / "snap").iterdir()) == ["pyproject.toml", "tests"]


def test_wheel_check_fails_on_a_failed_test(tmp_path, monkeypatch):
    row, _ = _wheel_row(tmp_path, monkeypatch, test_rc=1, counts=(2, 1, 0, 0))
    assert row["status"] == "FAIL"
    assert "1 passed, 1 failed" in row["summary"]
    assert "E   AssertionError: assert 'deny' == 'ask'" in row["details"]


def test_wheel_check_fails_when_the_test_only_skips(tmp_path, monkeypatch):
    """A wrong wheel_dir_env makes the test skip with exit 0; that must not pass."""
    row, _ = _wheel_row(tmp_path, monkeypatch, counts=(2, 0, 0, 2))
    assert row["status"] == "FAIL" and "2 skipped" in row["summary"]


def test_wheel_check_fails_on_a_failed_build_and_does_not_run_the_test(tmp_path, monkeypatch):
    row, calls = _wheel_row(tmp_path, monkeypatch, build_rc=1)
    assert row["status"] == "FAIL" and row["summary"] == "build failed (exit 1)"
    assert "ERROR: backend failed" in row["details"]
    assert len(calls) == 2


def test_wheel_check_skips_without_config_and_fails_on_a_missing_test_file(tmp_path, monkeypatch):
    row, calls = _wheel_row(tmp_path / "a", monkeypatch, cfg={})
    assert row["status"] == "SKIP" and calls == []
    missing = {"wheel_test": {"test": "tests/test_gone.py", "wheel_dir_env": "SEMGATE_WHEEL_DIR"}}
    row, calls = _wheel_row(tmp_path / "b", monkeypatch, cfg=missing)
    assert row["status"] == "FAIL" and calls == []


def _bash():
    if os.name != "nt":
        return shutil.which("bash")
    git = shutil.which("git")          # Git for Windows: <git>/cmd/git.exe or <git>/mingw64/bin/git.exe
    if git:
        for parent in Path(git).resolve().parents[:3]:
            cand = parent / "bin" / "bash.exe"
            if cand.exists():
                return str(cand)
    return None


@pytest.mark.skipif(_bash() is None, reason="needs bash (Git Bash on Windows)")
def test_snapshot_end_to_end(tmp_path, monkeypatch):
    home = tmp_path / "home"
    home.mkdir()
    env = dict(os.environ, HOME=str(home), USERPROFILE=str(home), PYTHON=sys.executable,
               GIT_CONFIG_GLOBAL=str(home / "gitconfig"), GIT_CONFIG_NOSYSTEM="1", USERNAME="ownername")
    src = tmp_path / "src"
    src.mkdir()
    (src / "LICENSE").write_text("                                 Apache License\n"
                                 "                           Version 2.0, January 2004\n", encoding="utf-8")
    (src / "ok.txt").write_text("hello\n", encoding="utf-8")
    (src / "run.sh").write_text("#!/bin/sh\necho hi\n", encoding="utf-8")
    (src / "leak.txt").write_text("key=NOT-A-REAL-KEY-0123456789\n", encoding="utf-8")
    (src / "docs" / "upstream").mkdir(parents=True)
    (src / "docs" / "upstream" / "draft.md").write_text("draft\n", encoding="utf-8")
    (src / ".publish").mkdir()
    (src / ".publish" / "exclude.txt").write_text("# comment\ndocs/upstream/\n", encoding="utf-8")
    (src / ".publish" / "scan.json").write_text(json.dumps({"license": {"spdx": "Apache-2.0", "require": ["LICENSE"]}}),
                                                encoding="utf-8")
    dotenv = tmp_path / "k.env"
    dotenv.write_text("FAKE_KEY=NOT-A-REAL-KEY-0123456789\n", encoding="utf-8")

    def git(*a, cwd=src):
        subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@t.test", "-c", "core.hooksPath=/dev/null", *a],
                       cwd=cwd, env=env, check=True, capture_output=True)
    git("init", "-q", "-b", "main")
    git("add", "-A")
    git("update-index", "--chmod=+x", "run.sh")
    git("commit", "-q", "-m", "src")

    out = tmp_path / "out"
    r = subprocess.run([_bash(), str(ROOT / "scripts" / "make-public-snapshot.sh"), "--repo", str(src), "--name", "demo",
                        "--out", str(out), "--date", "20000101", "--author", "Owner Name <owner@owner.test>",
                        "--env-file", str(dotenv), "--private-dir", str(tmp_path / "none"),
                        "--agpl-data", str(tmp_path / "none")],
                       env=env, capture_output=True, text=True, encoding="utf-8", errors="replace")
    assert r.returncode == 1, r.stdout + r.stderr          # the planted key must fail the scan
    assert "NOT-A-REAL-KEY" not in r.stdout + r.stderr     # the key value is never printed
    snap = out / "demo-20000101"
    rows = {row["check"]: row for row in json.loads((out / "demo-20000101.scan.json").read_text(encoding="utf-8"))}
    assert rows["real keys from .env (hash-only)"]["status"] == "FAIL"
    assert rows["git: one commit, owner identity, no remote"]["status"] == "PASS"
    assert rows["tree = source commit minus exclude list"]["status"] == "PASS"
    assert rows["license files"]["status"] == "PASS"
    assert not (snap / "docs" / "upstream").exists() and not (snap / ".publish").exists()
    log = subprocess.run(["git", "-C", str(snap), "log", "--format=%an <%ae>|%cn <%ce>"], env=env,
                         capture_output=True, text=True, check=True).stdout.splitlines()
    assert log == ["Owner Name <owner@owner.test>|Owner Name <owner@owner.test>"]
    mode = subprocess.run(["git", "-C", str(snap), "ls-files", "-s", "run.sh"], env=env,
                          capture_output=True, text=True, check=True).stdout
    assert mode.startswith("100755")
    # a second run into the same folder is refused without --replace
    r2 = subprocess.run([_bash(), str(ROOT / "scripts" / "make-public-snapshot.sh"), "--repo", str(src), "--name", "demo",
                         "--out", str(out), "--date", "20000101", "--no-scan"], env=env, capture_output=True, text=True)
    assert r2.returncode == 2 and "refusing" in r2.stderr
