"""Extractor for real Google Antigravity (agy) session history.

Extracts:
  - Every proposed tool call (from brain/<id>/.system_generated/logs/transcript.jsonl)
  - Every user approval point where agy asked for confirmation (from log/cli-*.log and conversations/<id>.db)
  - Canonical tool, args, conversation_id, step_idx, user prompts, and agy approval status.
"""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


def default_agy_dir() -> str:
    """agy's data folder: ~/.gemini/antigravity-cli, read when called (so a test's HOME applies)."""
    return os.path.join(os.path.expanduser("~"), ".gemini", "antigravity-cli")


@dataclass
class ExtractedAction:
    conversation_id: str
    proposed_step_idx: int
    execution_step_idx: int
    tool: str
    arguments: Dict[str, Any]
    user_prompt: str = ""
    session_title: str = ""
    timestamp: str = ""
    was_agy_approval_point: bool = False
    agy_approval_response: str = "none"  # "approved", "rejected", "cancelled", "none" (auto-run)
    raw_tool_call: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

    def to_hook_event(self, workspace_path: Optional[str] = None) -> Dict[str, Any]:
        """Convert to the PreToolUse event format expected by Semgate's adapter.
        workspace_path not given: the current directory."""
        if workspace_path is None:
            workspace_path = os.getcwd()
        return {
            "conversationId": self.conversation_id,
            "stepIdx": self.proposed_step_idx,
            "toolCall": {
                "name": self.tool,
                "args": dict(self.arguments),
            },
            "workspacePaths": [workspace_path],
        }


def _normalize_arg_val(val: Any) -> Any:
    if isinstance(val, str):
        s = val.strip()
        if (s.startswith('"') and s.endswith('"')) or (s.startswith('{') and s.endswith('}')) or (s.startswith('[') and s.endswith(']')):
            try:
                return json.loads(s)
            except Exception:
                pass
    return val


def normalize_args(args: Dict[str, Any]) -> Dict[str, Any]:
    return {k: _normalize_arg_val(v) for k, v in args.items()}


class AgySessionExtractor:
    def __init__(self, agy_dir: Optional[str] = None):
        self.agy_dir = Path(agy_dir or default_agy_dir())
        self.conv_dir = self.agy_dir / "conversations"
        self.brain_dir = self.agy_dir / "brain"
        self.log_dir = self.agy_dir / "log"
        self._summaries: Dict[str, Dict[str, Any]] = {}
        self._log_confirmations: Dict[Tuple[str, int], Dict[str, Any]] = {}
        self._db_permissions: Dict[Tuple[str, int], Dict[str, Any]] = {}

    def load_index(self) -> None:
        """Load conversation summaries and CLI log confirmation points."""
        # 1. Load conversation summaries
        sum_db = self.agy_dir / "conversation_summaries.db"
        if sum_db.exists():
            try:
                conn = sqlite3.connect(sum_db)
                cur = conn.cursor()
                for row in cur.execute("SELECT conversation_id, title, last_modified_time FROM conversation_summaries"):
                    self._summaries[row[0]] = {
                        "title": row[1],
                        "last_modified": str(row[2]) if row[2] else "",
                    }
                conn.close()
            except Exception:
                pass

        # 2. Parse CLI logs for surfaced confirmations & user responses / cancellations
        surface_pat = re.compile(r'Surfacing tool confirmation:\s*"([^"]+)"\s*at step\s*(\d+)')
        resp_pat = re.compile(r'Responding to tool confirmation:\s*convID=([^,]+),\s*stepIdx=(\d+),\s*approved=(true|false)')
        conv_switch_pat = re.compile(r'Streaming conversation\s+([a-f0-9\-]+)')
        cancel_pat = re.compile(r'Cancelling in-progress response for conversation\s+([a-f0-9\-]+)')

        for log_file in sorted(self.log_dir.glob("cli-*.log")):
            active_cid = None
            surfaced_in_file: List[Tuple[int, str]] = []
            try:
                with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        m_c = conv_switch_pat.search(line)
                        if m_c:
                            active_cid = m_c.group(1)

                        m_s = surface_pat.search(line)
                        if m_s:
                            sidx = int(m_s.group(2))
                            tname = m_s.group(1)
                            surfaced_in_file.append((sidx, tname))
                            if active_cid:
                                self._log_confirmations[(active_cid, sidx)] = {
                                    "tool": tname,
                                    "status": "surfaced",
                                    "log": log_file.name,
                                }

                        m_r = resp_pat.search(line)
                        if m_r:
                            cid = m_r.group(1)
                            sidx = int(m_r.group(2))
                            approved = m_r.group(3) == "true"
                            status = "approved" if approved else "rejected"
                            info = self._log_confirmations.get((cid, sidx), {})
                            info.update({
                                "status": status,
                                "approved": approved,
                                "log": log_file.name,
                            })
                            self._log_confirmations[(cid, sidx)] = info

                        m_can = cancel_pat.search(line)
                        if m_can:
                            cid = m_can.group(1)
                            # If a confirmation was surfaced recently in this log for this conversation
                            # and not responded to, mark as cancelled
                            for sidx, tname in surfaced_in_file:
                                key = (cid, sidx)
                                if key in self._log_confirmations:
                                    if self._log_confirmations[key].get("status") == "surfaced":
                                        self._log_confirmations[key]["status"] = "cancelled"
            except Exception:
                pass

        # 3. Parse SQLite conversation databases for permission records
        for db_file in self.conv_dir.glob("*.db"):
            cid = db_file.stem
            try:
                conn = sqlite3.connect(db_file)
                cur = conn.cursor()
                cur.execute("SELECT idx, status, permissions FROM steps WHERE permissions IS NOT NULL;")
                for idx, status, perm in cur.fetchall():
                    self._db_permissions[(cid, idx)] = {
                        "status": status,
                        "permissions": perm,
                    }
                conn.close()
            except Exception:
                pass

    def list_sessions(self) -> List[Dict[str, Any]]:
        """List all discoverable sessions."""
        self.load_index()
        sessions = []
        found_cids = set()

        # From brain transcripts
        for tp in self.brain_dir.glob("*/.system_generated/logs/transcript.jsonl"):
            cid = tp.parent.parent.parent.name
            found_cids.add(cid)

        # From conversation summaries
        found_cids.update(self._summaries.keys())

        # From conversation dbs
        for db in self.conv_dir.glob("*.db"):
            found_cids.add(db.stem)

        for cid in sorted(found_cids):
            meta = self._summaries.get(cid, {})
            has_transcript = (self.brain_dir / cid / ".system_generated" / "logs" / "transcript.jsonl").exists()
            has_db = (self.conv_dir / f"{cid}.db").exists()
            sessions.append({
                "conversation_id": cid,
                "title": meta.get("title", ""),
                "last_modified": meta.get("last_modified", ""),
                "has_transcript": has_transcript,
                "has_db": has_db,
            })
        return sessions

    def extract_session(self, conversation_id: str) -> List[ExtractedAction]:
        """Extract all proposed tool calls and approval points for a single session."""
        self.load_index()
        meta = self._summaries.get(conversation_id, {})
        title = meta.get("title", "")
        last_mod = meta.get("last_modified", "")

        transcript_file = self.brain_dir / conversation_id / ".system_generated" / "logs" / "transcript.jsonl"
        if not transcript_file.exists():
            return []

        actions: List[ExtractedAction] = []
        last_user_prompt = ""

        with open(transcript_file, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                try:
                    data = json.loads(line)
                except Exception:
                    continue

                stype = data.get("type")
                sidx = data.get("step_index", 0)

                if stype == "USER_INPUT":
                    content = data.get("content", "")
                    if isinstance(content, str):
                        # Clean XML tags if present
                        cleaned = re.sub(r"<USER_REQUEST>([\s\S]*?)</USER_REQUEST>", r"\1", content).strip()
                        last_user_prompt = cleaned

                elif stype == "PLANNER_RESPONSE":
                    tool_calls = data.get("tool_calls") or []
                    for tc in tool_calls:
                        tname = tc.get("name", "")
                        raw_args = tc.get("args") or {}
                        norm_args = normalize_args(raw_args)

                        # In agy's execution loop, the tool call proposed at step P
                        # is surfaced / confirmed / executed at step P + 1
                        exec_step_idx = sidx + 1

                        # Check if agy asked the user for approval
                        was_approval = False
                        response_val = "none"

                        # Check CLI logs at exec_step_idx or sidx
                        log_info = self._log_confirmations.get((conversation_id, exec_step_idx)) or self._log_confirmations.get((conversation_id, sidx))
                        if log_info:
                            was_approval = True
                            response_val = log_info.get("status", "approved")

                        # Check DB permissions
                        db_info = self._db_permissions.get((conversation_id, exec_step_idx)) or self._db_permissions.get((conversation_id, sidx))
                        if db_info:
                            was_approval = True
                            if response_val == "none":
                                response_val = "approved"

                        action = ExtractedAction(
                            conversation_id=conversation_id,
                            proposed_step_idx=sidx,
                            execution_step_idx=exec_step_idx,
                            tool=tname,
                            arguments=norm_args,
                            user_prompt=last_user_prompt,
                            session_title=title,
                            timestamp=last_mod,
                            was_agy_approval_point=was_approval,
                            agy_approval_response=response_val,
                            raw_tool_call=tc,
                        )
                        actions.append(action)

        return actions

    def extract_all(self) -> List[ExtractedAction]:
        """Extract all actions across all sessions with transcripts."""
        self.load_index()
        all_actions = []
        for s in self.list_sessions():
            if s["has_transcript"]:
                actions = self.extract_session(s["conversation_id"])
                all_actions.extend(actions)
        return all_actions
