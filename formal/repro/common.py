"""Shared helpers for the formal/repro stress tests.

Isolation: every script calls `isolate()` first. It points HOME, USERPROFILE,
SEMGATE_CONFIG, SEMGATE_ANTIGRAVITY_CONFIG and SEMGATE_FEEDBACK_FILE at a
fresh temp directory, so nothing reads or writes the real ~/.semgate,
~/.claude or ~/.gemini. Child processes inherit this environment. Every store
path (ledger_file, history_file, feedback_file, agent_files.dir, deny-streak
state_file) is also set explicitly to a file under that temp directory.
No network: the hook tests use the fake provider only.
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


def isolate(prefix: str = "semgate-formal-") -> Path:
    tmp = Path(tempfile.mkdtemp(prefix=prefix))
    home = tmp / "home"
    home.mkdir()
    for var in ("HOME", "USERPROFILE"):
        os.environ[var] = str(home)
    os.environ["SEMGATE_CONFIG"] = str(tmp / "no-such-config.json")
    os.environ["SEMGATE_ANTIGRAVITY_CONFIG"] = str(tmp / "no-such-config.json")
    os.environ["SEMGATE_FEEDBACK_FILE"] = str(tmp / "no-such-feedback.jsonl")
    os.environ["PYTHONPATH"] = str(REPO)
    return tmp


def scan_jsonl(path: Path) -> Tuple[List[Dict[str, Any]], List[str]]:
    """Parse a JSONL file the way semgate's readers do: text mode, UTF-8,
    universal newlines (a lone CR also ends a line), strip, json.loads.
    Returns (records, bad_lines). A bad line is any non-empty line that is
    not one JSON object; semgate's Ledger.records / ToolHistory.records raise
    on it, AgentFiles.records / FeedbackStore.latest skip it."""
    good: List[Dict[str, Any]] = []
    bad: List[str] = []
    if not path.exists():
        return good, bad
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad.append(line[:120])
                continue
            if isinstance(obj, dict):
                good.append(obj)
            else:
                bad.append(line[:120])
    return good, bad


def lone_cr_record_starts(path: Path) -> int:
    """Byte-level count of CR directly followed by '{': a record whose LF was
    overwritten by the next record (seen in the Windows append race)."""
    if not path.exists():
        return 0
    return path.read_bytes().count(b"\r{")


def rate(n: int, d: int) -> str:
    return f"{n}/{d} ({(100.0 * n / d) if d else 0.0:.1f}%)"
