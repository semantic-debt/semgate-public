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
