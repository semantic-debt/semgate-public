"""Checks for scripts/test-local.sh: the test run proves what it tested.

Stdlib only. Two commands:

  localci.py marker --out FILE [--tamper]
      Writes the tree marker: git HEAD, a sha256 over the tracked files'
      content as they are on disk now (the bytes the WSL copy gets), the
      tracked file list and a random nonce. tests/test_localci_marker.py
      hashes the same files in the tree it runs from and must get the same
      value; it writes the nonce back to an ack file. --tamper changes the
      hash on purpose (proves the canary fails).

  localci.py check --side windows|wsl|posix --suite tests|integration
                   --junit FILE [--marker FILE --ack FILE]
      Reads pytest's --junitxml report and fails (exit 1) when
        - a test failed or errored, or the report is missing or empty;
        - fewer tests ran than the floor in tests/.min_counts;
        - a test was skipped for a reason not listed in tests/.allowed_skips;
        - (with --marker) test_tree_marker did not pass, or the ack file
          does not carry this run's nonce.
      Prints one summary line either way.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import secrets
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

ROOT = Path(__file__).resolve().parent.parent
FLOORS = ROOT / "tests" / ".min_counts"
ALLOWED_SKIPS = ROOT / "tests" / ".allowed_skips"
MARKER_TEST = "test_tree_marker"


# ---------------------------------------------------------------- tree marker

def tree_hash(root: Path, files: Iterable[str]) -> str:
    """sha256 over (path, sha256(content)) of each file, in sorted order. A
    missing file hashes as <missing>, so a partial copy never matches."""
    h = hashlib.sha256()
    for rel in sorted(files):
        p = root / rel
        try:
            digest = hashlib.sha256(p.read_bytes()).hexdigest()
        except OSError:
            digest = "<missing>"
        h.update(rel.encode("utf-8") + b"\0" + digest.encode("ascii") + b"\n")
    return h.hexdigest()


def tracked_files(root: Path) -> List[str]:
    out = subprocess.run(["git", "ls-files", "-z"], cwd=str(root), capture_output=True, check=True).stdout
    return sorted(p for p in out.decode("utf-8").split("\0") if p)


def git_head(root: Path) -> str:
    r = subprocess.run(["git", "rev-parse", "HEAD"], cwd=str(root), capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ""


def make_marker(root: Path, tamper: bool = False) -> Dict[str, object]:
    files = tracked_files(root)
    value = tree_hash(root, files)
    if tamper:
        value = "0" * 64
    return {"schema": "semgate-localci-marker/1", "head": git_head(root), "tree_hash": value,
            "nonce": secrets.token_hex(16), "files": files}


# ---------------------------------------------------------------- junit report

def load_junit(path: Path) -> List[Dict[str, str]]:
    """One dict per testcase: name, classname, outcome (passed, failed,
    error, skipped), message (skip reason or failure message)."""
    root = ET.parse(str(path)).getroot()
    cases = []
    for tc in root.iter("testcase"):
        outcome, message = "passed", ""
        for child in tc:
            if child.tag in ("failure", "error", "skipped"):
                outcome = {"failure": "failed", "error": "error", "skipped": "skipped"}[child.tag]
                message = child.get("message") or (child.text or "")
                if child.tag == "skipped" and child.get("type") == "pytest.xfail":
                    message = "xfail: " + message
                if child.tag == "skipped" and message == "collection skipped":
                    # A whole file skipped at import (pytest.importorskip): the
                    # reason is in the text, "(path, line, 'Skipped: <reason>')".
                    m = re.search(r"Skipped: (.*?)['\"]\)\s*$", child.text or "", re.S)
                    message = m.group(1) if m else (child.text or message)
                break
        cases.append({"name": tc.get("name", ""), "classname": tc.get("classname", ""),
                      "outcome": outcome, "message": message})
    return cases


def read_floors(path: Path = FLOORS) -> Dict[str, int]:
    floors: Dict[str, int] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            key, _, value = line.partition("=")
            floors[key.strip()] = int(value.strip())
    return floors


def read_allowed_skips(path: Path = ALLOWED_SKIPS) -> List[Tuple[str, "re.Pattern[str]"]]:
    """Lines `<sides>: <regex>`; sides: any, or a comma list of windows,
    wsl, posix. '#' lines are comments."""
    rules = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        sides, _, regex = raw.partition(":")
        rules.append((sides.replace(" ", ""), re.compile(regex.strip())))
    return rules


def skip_allowed(reason: str, side: str, rules) -> bool:
    return any((sides == "any" or side in sides.split(",")) and rx.search(reason) for sides, rx in rules)


def check(side: str, suite: str, junit: Path, marker: Optional[Path] = None, ack: Optional[Path] = None,
          floors: Optional[Dict[str, int]] = None, rules=None) -> Tuple[bool, str, Dict[str, int]]:
    """(ok, summary line, counts)."""
    label = f"{side} {suite}"
    problems: List[str] = []
    try:
        cases = load_junit(junit)
    except (OSError, ET.ParseError) as exc:
        return False, f"{label}: FAIL no junit report ({type(exc).__name__}: {exc})", {}
    floors = read_floors() if floors is None else floors
    rules = read_allowed_skips() if rules is None else rules
    counts = {k: sum(1 for c in cases if c["outcome"] == k) for k in ("passed", "failed", "error", "skipped")}
    ran = counts["passed"] + counts["failed"] + counts["error"]
    counts["ran"] = ran
    if counts["failed"] or counts["error"]:
        problems.append(f"{counts['failed']} failed, {counts['error']} errors")
    key = f"{side}.{suite}"
    floor = floors.get(key)
    if floor is None:
        problems.append(f"no floor for {key} in tests/.min_counts")
    elif ran < floor:
        problems.append(f"only {ran} tests ran, floor is {floor} ({key} in tests/.min_counts)")
    bad = sorted({c["message"].strip()[:200] for c in cases
                  if c["outcome"] == "skipped" and not skip_allowed(c["message"], side, rules)})
    if bad:
        problems.append("skip reason not in tests/.allowed_skips: " + " | ".join(bad))
    if marker is not None:
        mine = [c for c in cases if c["name"] == MARKER_TEST]
        if not mine or any(c["outcome"] != "passed" for c in mine):
            why = mine[0]["message"].strip().splitlines()[0][:300] if mine and mine[0]["message"].strip() else "not run"
            problems.append(f"tree marker test {mine[0]['outcome'] if mine else 'missing'}: {why}")
        try:
            want = json.loads(marker.read_text(encoding="utf-8"))["nonce"]
            got = json.loads(ack.read_text(encoding="utf-8")) if ack is not None else {}
        except (OSError, ValueError, KeyError) as exc:
            problems.append(f"tree marker ack missing ({type(exc).__name__})")
        else:
            if got.get("nonce") != want:
                problems.append("tree marker ack does not carry this run's nonce")
    line = (f"{label}: {'PASS' if not problems else 'FAIL'} ran={ran} (floor {floor}) passed={counts['passed']} "
            f"failed={counts['failed']} errors={counts['error']} skipped={counts['skipped']}")
    if problems:
        line += " -- " + "; ".join(problems)
    return not problems, line, counts


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="localci.py")
    sub = ap.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("marker")
    m.add_argument("--out", required=True)
    m.add_argument("--tamper", action="store_true")
    c = sub.add_parser("check")
    c.add_argument("--side", required=True, choices=["windows", "wsl", "posix"])
    c.add_argument("--suite", required=True, choices=["tests", "integration"])
    c.add_argument("--junit", required=True)
    c.add_argument("--marker", default="")
    c.add_argument("--ack", default="")
    args = ap.parse_args(argv)
    if args.cmd == "marker":
        Path(args.out).write_text(json.dumps(make_marker(ROOT, tamper=args.tamper)), encoding="utf-8")
        return 0
    ok, line, _ = check(args.side, args.suite, Path(args.junit),
                        marker=Path(args.marker) if args.marker else None,
                        ack=Path(args.ack) if args.ack else None)
    print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
