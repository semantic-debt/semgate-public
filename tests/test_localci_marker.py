"""Tree marker canary for scripts/test-local.sh.

Found 2026-09-25: WSL tested another copy of the code (the tar path was
mangled) while the script printed "all passed". The script now writes a
marker (git HEAD, a sha256 over the tracked files' content, the file list, a
random nonce) and starts pytest with SEMGATE_TREE_MARKER, SEMGATE_TREE_ACK
and SEMGATE_TREE_ROOT. This test checks that
  - the tree pytest runs from is the tree the script meant (SEMGATE_TREE_ROOT:
    the worktree locally, the fresh copy in WSL);
  - `semgate` is imported from that tree;
  - the files in that tree hash to the marker's value;
then writes the nonce to the ack file. The script fails the run when this
test did not pass or the ack does not carry its nonce.

Outside the script (plain pytest, CI) there is no marker: the test skips
with a reason listed in tests/.allowed_skips.
"""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _localci():
    spec = importlib.util.spec_from_file_location("_localci", ROOT / "scripts" / "localci.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _same(a, b) -> bool:
    return os.path.normcase(os.path.realpath(str(a))) == os.path.normcase(os.path.realpath(str(b)))


def _inside(path, root) -> bool:
    p = os.path.normcase(os.path.realpath(str(path)))
    r = os.path.normcase(os.path.realpath(str(root)))
    return p == r or p.startswith(r.rstrip(os.sep) + os.sep)


def test_tree_marker():
    marker_path = os.environ.get("SEMGATE_TREE_MARKER", "")
    if not marker_path:
        pytest.skip("no tree marker: not started by scripts/test-local.sh")
    marker = json.loads(Path(marker_path).read_text(encoding="utf-8"))
    expected_root = os.environ.get("SEMGATE_TREE_ROOT", "")
    assert expected_root, "SEMGATE_TREE_MARKER is set but SEMGATE_TREE_ROOT is not"
    assert _same(ROOT, expected_root), f"pytest runs the tests of {ROOT}, the script meant {expected_root}"
    import semgate
    assert _inside(semgate.__file__, ROOT), f"semgate imported from {semgate.__file__}, not from the tested tree {ROOT}"
    got = _localci().tree_hash(ROOT, marker["files"])
    assert got == marker["tree_hash"], (
        f"the tree under test ({ROOT}) does not match the marker: {got[:16]} != {marker['tree_hash'][:16]} "
        f"({len(marker['files'])} tracked files, HEAD {marker.get('head', '')[:12]})")
    if (ROOT / ".git").exists() and marker.get("head"):
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True).stdout.strip()
        assert head == marker["head"], f"git HEAD {head[:12]} != marker HEAD {marker['head'][:12]}"
    ack = os.environ.get("SEMGATE_TREE_ACK", "")
    assert ack, "SEMGATE_TREE_MARKER is set but SEMGATE_TREE_ACK is not"
    Path(ack).write_text(json.dumps({"nonce": marker["nonce"], "root": str(ROOT), "semgate": semgate.__file__}),
                         encoding="utf-8")


# ---------------------------------------------------------------- the checks in scripts/localci.py

def _junit(tmp_path, cases):
    """cases: (name, outcome, message)."""
    rows = []
    for name, outcome, msg in cases:
        inner = {"passed": "", "failed": f'<failure message="{msg}"/>', "error": f'<error message="{msg}"/>',
                 "skipped": f'<skipped type="pytest.skip" message="{msg}"/>'}[outcome]
        rows.append(f'<testcase classname="tests.x" name="{name}">{inner}</testcase>')
    p = tmp_path / "junit.xml"
    p.write_text('<?xml version="1.0"?><testsuites><testsuite name="pytest">' + "".join(rows)
                 + "</testsuite></testsuites>", encoding="utf-8")
    return p


def _rules(lc, text):
    import re
    return [(s.strip(), re.compile(r.strip())) for s, _, r in (l.partition(":") for l in text.splitlines() if l.strip())]


def test_check_passes_a_healthy_report(tmp_path):
    lc = _localci()
    j = _junit(tmp_path, [("a", "passed", ""), ("b", "passed", ""), ("c", "skipped", "langgraph not installed")])
    ok, line, counts = lc.check("windows", "tests", j, floors={"windows.tests": 2},
                                rules=_rules(lc, "any: langgraph not installed"))
    assert ok and "PASS" in line and counts["ran"] == 2 and counts["skipped"] == 1


def test_check_fails_below_the_floor(tmp_path):
    lc = _localci()
    j = _junit(tmp_path, [("a", "passed", "")])
    ok, line, _ = lc.check("wsl", "tests", j, floors={"wsl.tests": 2}, rules=[])
    assert not ok and "only 1 tests ran, floor is 2" in line


def test_check_fails_on_an_unlisted_skip_reason(tmp_path):
    lc = _localci()
    j = _junit(tmp_path, [("a", "passed", ""), ("b", "skipped", "network down")])
    ok, line, _ = lc.check("windows", "tests", j, floors={"windows.tests": 1},
                           rules=_rules(lc, "wsl: network down"))           # allowed on another side only
    assert not ok and "skip reason not in tests/.allowed_skips: network down" in line


def test_check_fails_on_failures_and_missing_report(tmp_path):
    lc = _localci()
    j = _junit(tmp_path, [("a", "failed", "boom")])
    ok, line, _ = lc.check("windows", "tests", j, floors={"windows.tests": 0}, rules=[])
    assert not ok and "1 failed" in line
    ok, line, _ = lc.check("windows", "tests", tmp_path / "nope.xml", floors={}, rules=[])
    assert not ok and "no junit report" in line


def test_check_fails_when_the_marker_test_did_not_pass_or_the_nonce_differs(tmp_path):
    lc = _localci()
    marker = tmp_path / "marker.json"
    marker.write_text(json.dumps({"nonce": "n1"}), encoding="utf-8")
    ack = tmp_path / "ack.json"
    floors = {"windows.tests": 1}
    j = _junit(tmp_path, [("test_tree_marker", "skipped", "no tree marker")])
    ok, line, _ = lc.check("windows", "tests", j, marker=marker, ack=ack, floors=floors,
                           rules=_rules(lc, "any: no tree marker"))
    assert not ok and "tree marker test skipped" in line and "ack missing" in line
    j = _junit(tmp_path, [("test_tree_marker", "passed", "")])
    ack.write_text(json.dumps({"nonce": "old"}), encoding="utf-8")
    ok, line, _ = lc.check("windows", "tests", j, marker=marker, ack=ack, floors=floors, rules=[])
    assert not ok and "does not carry this run's nonce" in line
    ack.write_text(json.dumps({"nonce": "n1"}), encoding="utf-8")
    ok, line, _ = lc.check("windows", "tests", j, marker=marker, ack=ack, floors=floors, rules=[])
    assert ok, line


def test_tree_hash_changes_with_content_and_missing_files(tmp_path):
    lc = _localci()
    (tmp_path / "a.txt").write_bytes(b"one")
    base = lc.tree_hash(tmp_path, ["a.txt"])
    (tmp_path / "a.txt").write_bytes(b"two")
    assert lc.tree_hash(tmp_path, ["a.txt"]) != base
    assert lc.tree_hash(tmp_path, ["a.txt", "b.txt"]) != lc.tree_hash(tmp_path, ["a.txt"])


def test_floor_and_skip_files_parse():
    lc = _localci()
    floors = lc.read_floors()
    for key in ("windows.tests", "wsl.tests", "windows.integration", "wsl.integration"):
        assert floors[key] > 0
    rules = lc.read_allowed_skips()
    assert rules and all(sides == "any" or set(sides.split(",")) <= {"windows", "wsl", "posix"} for sides, _ in rules)
    assert lc.skip_allowed("no tree marker: not started by scripts/test-local.sh", "posix", rules)


def test_collection_skip_reason_is_read_from_the_text(tmp_path):
    """A file skipped at import is one junit entry with message "collection
    skipped"; the real reason is in its text."""
    lc = _localci()
    p = tmp_path / "junit.xml"
    text = """('C:\\\\t\\\\test_x.py', 2, "Skipped: could not import 'typesafe_sdk': No module named 'typesafe_sdk'")"""
    p.write_text('<?xml version="1.0"?><testsuites><testsuite><testcase classname="" name="test_x">'
                 f'<skipped message="collection skipped">{text}</skipped></testcase></testsuite></testsuites>',
                 encoding="utf-8")
    [case] = lc.load_junit(p)
    assert case["message"] == "could not import 'typesafe_sdk': No module named 'typesafe_sdk'"


def test_skip_rule_with_a_side_list():
    lc = _localci()
    rules = _rules(lc, "wsl,posix: node not installed")
    assert lc.skip_allowed("node not installed", "wsl", rules)
    assert lc.skip_allowed("node not installed", "posix", rules)
    assert not lc.skip_allowed("node not installed", "windows", rules)
