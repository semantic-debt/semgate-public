"""Shared helpers for the eval importers 9-12: public/private split and output.

Held-out rule (frozen, same for every set): a case is private when
int(sha256(source_id), 16) % 5 == 0, otherwise public. About 20% private.
The split depends only on the source id, never on the label, the text, or a
result, so it cannot be tuned after the fact.

Public cases go to fixtures/eval/<name>.jsonl (committed) only when the source
license allows redistribution; otherwise they stay in evals/data/<name>/.
Private cases always go to evals/private/<name>.jsonl, which is git-ignored and
is never used for tuning (see EVALS.md).
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path
from typing import Iterable, List, Sequence, Tuple

ROOT = Path(__file__).resolve().parents[1]
PUBLIC_DIR = ROOT / "fixtures" / "eval"
PRIVATE_DIR = ROOT / "evals" / "private"
LABELS = ("allow", "ask", "deny")
DATA_ROOT_ENV = "SEMGATE_EVAL_DATA_ROOT"


def data_root() -> Path:
    """The checkout that holds the git-ignored caches (evals/data/) and private
    splits (evals/private/). A git worktree has neither, so the default is the
    main checkout of this repo. Order: $SEMGATE_EVAL_DATA_ROOT; the main
    checkout (parent of `git rev-parse --git-common-dir`); this checkout."""
    env = os.environ.get(DATA_ROOT_ENV, "").strip()
    if env:
        return Path(env).resolve()
    try:
        out = subprocess.run(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"],
                             cwd=str(ROOT), capture_output=True, text=True, timeout=10)
        common = Path(out.stdout.strip())
        if out.returncode == 0 and common.name == ".git" and common.is_dir():
            return common.parent.resolve()
    except (OSError, subprocess.SubprocessError):
        pass
    return ROOT


def rel_to(path: Path, base: Path) -> str:
    """path relative to base, with forward slashes (for a committed manifest:
    no machine-specific absolute path)."""
    try:
        return Path(path).resolve().relative_to(Path(base).resolve()).as_posix()
    except ValueError:
        return Path(path).as_posix()


def is_private(source_id: str) -> bool:
    return int(hashlib.sha256(source_id.encode("utf-8")).hexdigest(), 16) % 5 == 0


def split_cases(cases: Sequence) -> Tuple[list, list]:
    """(public, private), each in input order."""
    public = [c for c in cases if not is_private(c.source_id)]
    private = [c for c in cases if is_private(c.source_id)]
    return public, private


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(Path(path).read_bytes())


def write_jsonl(path: Path, cases: Iterable) -> str:
    """Write cases as sorted-key JSON lines with LF endings; return sha256."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = "".join(json.dumps(c.to_dict(), sort_keys=True) + "\n" for c in cases)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return sha256_bytes(text.encode("utf-8"))


def label_counts(cases: Iterable) -> dict:
    cases = list(cases)
    return {label: sum(1 for c in cases if c.label == label) for label in LABELS}


def rel(path: Path) -> str:
    try:
        return Path(path).resolve().relative_to(ROOT).as_posix()
    except ValueError:
        return str(path)


def write_split(name: str, cases: List, *, redistributable: bool, data_dir: Path) -> dict:
    """Write the public and private files; return manifest fields."""
    public, private = split_cases(cases)
    public_path = (PUBLIC_DIR if redistributable else data_dir) / f"{name}.jsonl"
    private_path = PRIVATE_DIR / f"{name}.jsonl"
    public_sha = write_jsonl(public_path, public)
    private_sha = write_jsonl(private_path, private)
    return {
        "split_rule": "private when int(sha256(source_id), 16) % 5 == 0",
        "public": {"path": rel(public_path), "committed": redistributable, "sha256": public_sha,
                   "count": len(public), "label_counts": label_counts(public)},
        "private": {"path": rel(private_path), "committed": False, "sha256": private_sha,
                    "count": len(private), "label_counts": label_counts(private)},
    }


def write_manifest(path: Path, manifest: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(json.dumps(manifest, indent=2, sort_keys=False) + "\n")
