"""Files the agent created in this session, with a hash and a snapshot.

Why: `rm reproduce_issue.py` deletes an untracked file, so git cannot bring it
back and the destructive gate asks a human. When semgate saw the agent create
that exact file earlier in the SAME session, and the file still has the same
content, the file is restorable from a snapshot semgate kept. Code checks
this; the model is only told the result.

Two per-step records, written by the hooks (never by the judge):

  pre   (PreToolUse, after the decision)  every path the action writes, and
        whether it existed before; for a file tool that carries the full
        content (Write, create_file, write_to_file), the sha256 of that content
        (`expected_sha256`); the sha256 of any local script the command runs
        (F4, for the post-run comparison).
  post  (PostToolUse, only when the tool ran without an error)  for each path
        that did not exist before and now is a regular file of at most
        `max_bytes` WHOSE sha256 IS ONE OF THE EXPECTED HASHES: sha256, size,
        and a snapshot copy of the content. A file whose content differs from
        what the tool wrote (the user or another process changed it before the
        post hook ran) gets a `not_recorded` record instead. A shell write
        (content unknown at decision time) is never recorded.

Layout under `base_dir` (default ~/.semgate):

  agent_files/<session key>.jsonl         pre / created / script_changed records
  snapshots/<session key>/<sha256>        snapshot copies (content-addressed)

`<session key>` is sha256(host session id)[:32], so a session id never becomes
a path component. The session id always comes from the host event, never from
the command.

A path is eligible (restorable) at decision time only when all hold:
  - a `created` record for this session and this resolved path exists;
  - the path is inside project_root after resolving symlinks, and the path
    itself is not a symlink;
  - the file's current sha256 equals the hash recorded right after creation
    (any later change, by the user or the agent, makes it not eligible);
  - the snapshot exists and its sha256 equals that hash.

Limits (documented, not hidden):
  - TOCTOU: the file is re-hashed when semgate decides, not when the command
    runs. It can change in between.
  - An agent that can run arbitrary code as the same OS user can write to
    ~/.semgate. Shell writes to it are hard-denied (rules.py), but code run
    through an interpreter is not. Eligibility still requires a snapshot whose
    content equals the current file, so a forged record only ever claims a
    file is restorable when a copy of its exact content exists.
  - Snapshots are not cleaned up automatically. Delete ~/.semgate/snapshots/
    to reclaim space.
"""
from __future__ import annotations

import hashlib
import os
import random
import shutil
import time
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, Optional

from . import filelock
from .envelope import utcnow_iso

MAX_BYTES = 5 * 1024 * 1024


def session_key(session_id: str) -> str:
    return hashlib.sha256(session_id.encode("utf-8")).hexdigest()[:32]


def sha256_file(path: str, max_bytes: int = MAX_BYTES) -> Optional[str]:
    """sha256 of a regular file of at most max_bytes, else None."""
    try:
        if not os.path.isfile(path) or os.path.getsize(path) > max_bytes:
            return None
        digest = hashlib.sha256()
        with open(path, "rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None


def expected_hashes(content: Any) -> List[str]:
    """sha256 values a file written with `content` (a str from the tool
    input) can have: the UTF-8 bytes as given, and the same text with LF
    line ends turned into CRLF (a Windows host may write those). Both are
    content the agent asked for; nothing else is accepted."""
    if not isinstance(content, str):
        return []
    variants = {content}
    if "\n" in content and "\r\n" not in content:
        variants.add(content.replace("\n", "\r\n"))
    try:
        return sorted(hashlib.sha256(v.encode("utf-8")).hexdigest() for v in variants)
    except UnicodeEncodeError:
        return []


def resolve(path: str, cwd: str) -> str:
    """Absolute, symlink-resolved, case-normalized path (same form as gitstate)."""
    return os.path.normcase(os.path.realpath(os.path.join(cwd or "", os.path.expanduser(path))))


def inside(path: str, root: str) -> bool:
    if not root:
        return False
    base = os.path.normcase(os.path.realpath(os.path.expanduser(root)))
    return path != base and path.startswith(base.rstrip(os.sep) + os.sep)


class AgentFiles:
    def __init__(self, base_dir: str = "", max_bytes: int = MAX_BYTES, snapshots: bool = True) -> None:
        self.base = Path(os.path.expanduser(base_dir or "~/.semgate"))
        self.max_bytes = int(max_bytes)
        self.snapshots = snapshots

    # ---------- storage ----------

    def _records_path(self, session_id: str) -> Path:
        return self.base / "agent_files" / f"{session_key(session_id)}.jsonl"

    def _snapshot_path(self, session_id: str, sha: str) -> Path:
        return self.base / "snapshots" / session_key(session_id) / sha

    def _append(self, session_id: str, record: Dict[str, Any]) -> None:
        """One line, one write, under the cross-process lock (filelock)."""
        filelock.append_record(self._records_path(session_id), record)

    def records(self, session_id: str) -> Iterable[Dict[str, Any]]:
        path = self._records_path(session_id)
        if not session_id or not path.exists():
            return []
        try:
            result = filelock.read_jsonl(path)
        except OSError:
            return []
        filelock.warn_malformed(path, result, "agent_files")
        return [rec for rec in result.records if rec.get("session_id") == session_id]

    # ---------- PreToolUse ----------

    def record_pre(self, session_id: str, step_idx: Any, *, project_root: str, cwd: str,
                   targets: Iterable[str], scripts: Iterable[Mapping[str, Any]] = (),
                   expected: Optional[Mapping[str, Iterable[str]]] = None) -> Optional[Dict[str, Any]]:
        """Remember, per step, which in-project paths the action writes and
        whether each existed. Paths outside project_root are dropped.

        `expected` maps a target (as given in `targets`) to the sha256 values
        the tool's own input says the file will have (a Write tool carries the
        full content). Only a path with expected hashes can later be recorded
        as agent-created; a shell write (content unknown) never is."""
        if not session_id or step_idx is None or not project_root:
            return None
        paths = []
        expected = expected or {}
        for t in targets:
            full = resolve(str(t), cwd or project_root)
            if inside(full, project_root) and full not in [p["path"] for p in paths]:
                raw = os.path.join(cwd or project_root, os.path.expanduser(str(t)))
                shas = sorted({str(h) for h in (expected.get(t) or expected.get(str(t)) or ()) if h})
                paths.append({"path": full, "existed": os.path.lexists(raw) or os.path.lexists(full),
                              "expected_sha256": shas})
        script_list = [{"path": str(s.get("path", "")), "sha256": str(s.get("sha256", ""))} for s in scripts if s.get("sha256")]
        if not paths and not script_list:
            return None
        record = {"record_type": "pre", "session_id": session_id, "step_idx": step_idx,
                  "project_root": project_root, "paths": paths, "scripts": script_list, "ts": utcnow_iso()}
        self._append(session_id, record)
        return record

    # ---------- PostToolUse ----------

    def record_post(self, session_id: str, step_idx: Any, error: str = "") -> Dict[str, List[Dict[str, Any]]]:
        """Join with the pre record of the same step. When the tool ran without
        an error, record each newly created regular file (hash + snapshot), and
        report scripts whose content changed since the decision."""
        result: Dict[str, List[Dict[str, Any]]] = {"created": [], "script_changed": []}
        if not session_id or step_idx is None:
            return result
        pre = None
        for rec in self.records(session_id):
            if rec.get("record_type") == "pre" and rec.get("step_idx") == step_idx:
                pre = rec
        if pre is None:
            return result
        for script in pre.get("scripts") or []:
            now = sha256_file(str(script.get("path", "")), self.max_bytes)
            if now != script.get("sha256"):
                entry = {"record_type": "script_changed", "session_id": session_id, "step_idx": step_idx,
                         "path": script.get("path"), "sha256_at_decision": script.get("sha256"),
                         "sha256_after_run": now, "ts": utcnow_iso()}
                self._append(session_id, entry)
                result["script_changed"].append(entry)
        if error:
            return result
        root = str(pre.get("project_root", ""))
        for item in pre.get("paths") or []:
            path = str(item.get("path", ""))
            if item.get("existed") or not inside(path, root):
                continue
            expected = [str(h) for h in item.get("expected_sha256") or [] if h]
            if not expected:
                # Content unknown at decision time (shell write, or a pre
                # record written before expected hashes existed): the file is
                # never recorded as agent-created.
                continue
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            if resolve(path, "") != path:        # a symlinked parent changed where it points
                continue
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size > self.max_bytes:
                continue
            sha = sha256_file(path, self.max_bytes)
            if sha is None:
                continue
            if sha not in expected:
                # The file is not what the tool wrote: someone (the user, a
                # formatter, another process) changed it before this hook ran.
                self._append(session_id, {"record_type": "not_recorded", "session_id": session_id, "step_idx": step_idx,
                                          "path": path, "reason": "content differs from what the tool wrote",
                                          "sha256_now": sha, "ts": utcnow_iso()})
                continue
            snapshot = ""
            if self.snapshots:
                snapshot = self._snapshot(session_id, path, sha)
                if not snapshot:
                    continue
            entry = {"record_type": "created", "session_id": session_id, "step_idx": step_idx, "path": path,
                     "sha256": sha, "size": size, "created": True, "snapshot": snapshot, "ts": utcnow_iso()}
            self._append(session_id, entry)
            result["created"].append(entry)
        return result

    def _snapshot(self, session_id: str, path: str, sha: str) -> str:
        """Keep a copy of `path` whose content has sha256 `sha`. The temp name
        is unique per process (no two writers share it, formal/REPORT.md S4).
        An existing snapshot with the right hash counts as success (another
        hook of this session stored the same content). "" on failure."""
        snap = self._snapshot_path(session_id, sha)
        if sha256_file(str(snap), self.max_bytes) == sha:
            return str(snap)
        tmp = snap.with_name(f"{sha}.{os.getpid()}.{random.getrandbits(32):08x}.tmp")
        try:
            snap.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, tmp)
            if sha256_file(str(tmp), self.max_bytes) != sha:   # the file changed while copying
                return ""
            try:
                os.replace(tmp, snap)
            except OSError:
                # Windows: the target is open in another process (it is
                # hashing a snapshot of the same content). Fine if it is right.
                pass
            # Another process may be replacing the same snapshot right now
            # (same content, same name): look again a few times.
            for attempt in range(4):
                if sha256_file(str(snap), self.max_bytes) == sha:
                    return str(snap)
                time.sleep(0.01 * (attempt + 1))
            return ""
        except OSError:
            return ""
        finally:
            try:
                if tmp.exists():
                    tmp.unlink()
            except OSError:
                pass

    # ---------- decision time ----------

    def eligible(self, session_id: str, path: str, project_root: str, raw_path: str = "") -> bool:
        """True when `path` (resolved, as gitstate computes it) was created by
        the agent in this session, is unchanged since (re-hashed now), and a
        matching snapshot exists. `raw_path` is the unresolved path; a symlink
        there is never eligible."""
        if not session_id or not inside(path, project_root):
            return False
        if raw_path and os.path.islink(raw_path):
            return False
        latest = None
        for rec in self.records(session_id):
            if rec.get("record_type") == "created" and rec.get("path") == path:
                latest = rec
        if latest is None:
            return False
        sha = str(latest.get("sha256", ""))
        if not sha or sha256_file(path, self.max_bytes) != sha:
            return False
        snap = self._snapshot_path(session_id, sha)
        return sha256_file(str(snap), self.max_bytes) == sha
