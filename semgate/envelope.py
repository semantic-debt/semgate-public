"""Canonical, language-neutral envelope: proposed action + immutable user
grant + environment/trajectory context.

Every harness adapter (OpenCode, others later) translates its native
permission request into this envelope. The judge only ever sees envelopes.
"""
from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import MappingProxyType
from typing import Any, Mapping, Optional, Tuple

SCHEMA_VERSION = "semgate-envelope/1"

# Task-context bounds applied by adapters and importers (see bound_user_messages,
# short_result). The router applies its own, smaller render caps.
RESULT_MAX = 300               # chars of TrajectoryEntry.result
USER_MESSAGES_MAX = 20         # user turns kept in Envelope.user_messages (first + newest)
USER_MESSAGE_CHARS_MAX = 4000  # chars kept per user turn
AGENT_INTENT_MAX = 2000        # chars of Envelope.agent_intent kept by adapters


def bound_user_messages(messages: Any, max_count: int = USER_MESSAGES_MAX,
                        max_chars: int = USER_MESSAGE_CHARS_MAX) -> Tuple[str, ...]:
    """Oldest first. Keeps the first turn (usually the task statement) and the
    newest max_count-1 turns; each turn cut to max_chars. Empty turns dropped."""
    msgs = [str(m).strip() for m in (messages or ()) if str(m or "").strip()]
    if len(msgs) > max_count:
        msgs = msgs[:1] + msgs[-(max_count - 1):] if max_count > 1 else msgs[-1:]
    return tuple(m[:max_chars] for m in msgs)


_RUN_RE = re.compile(r"([=\-_*#~.+])\1{3,}")


def short_result(text: str = "", *, exit_code: Any = None, error: bool = False, limit: int = RESULT_MAX) -> str:
    """TrajectoryEntry.result: "exit N: <first lines>" when the exit code is
    known, "error: <first lines>" when the host flags an error, otherwise
    "ok: <first lines>". Whitespace is collapsed and lines are joined with
    " | "; at most `limit` chars. "" when there is nothing to say."""
    # Separator lines ("=====", "-----") are shortened to three characters.
    lines = [_RUN_RE.sub(r"\1\1\1", " ".join(line.split())) for line in str(text or "").splitlines()]
    body = " | ".join(line for line in lines if line)
    if exit_code is not None and str(exit_code).strip() != "":
        head = f"exit {str(exit_code).strip()}"
    elif error:
        head = "error"
    elif body:
        head = "ok"
    else:
        return ""
    out = f"{head}: {body}" if body else head
    return out if len(out) <= limit else out[: max(0, limit - 3)] + "..."


def canonical_json(obj: Any) -> str:
    """Deterministic JSON used for digests, ledger records and state hashing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def envelope_digest(obj: Any) -> str:
    return hashlib.sha256(canonical_json(obj).encode("utf-8")).hexdigest()


def parse_ts(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _frozen_mapping(d: Optional[Mapping[str, Any]]) -> Mapping[str, Any]:
    return MappingProxyType(dict(d or {}))


@dataclass(frozen=True)
class UserGrant:
    """Immutable record of what the user authorized.

    A grant never creates permission by proximity: scope is matched exactly
    against tools, path prefixes, domains and forbidden patterns. Immutability
    is enforced (frozen dataclass + immutable field types) so a judged grant
    cannot be edited after the fact to launder an approval.
    """

    grant_id: str
    principal: str
    purpose: str
    allowed_tools: Tuple[str, ...] = ()
    allowed_path_prefixes: Tuple[str, ...] = ()
    allowed_domains: Tuple[str, ...] = ()
    forbidden_patterns: Tuple[str, ...] = ()
    issued_at: str = ""
    expires_at: Optional[str] = None
    provenance: str = ""

    def is_expired(self, at: Optional[str] = None) -> bool:
        exp = parse_ts(self.expires_at)
        if exp is None:
            return False
        now = parse_ts(at) or datetime.now(timezone.utc)
        return now >= exp

    def to_dict(self) -> dict:
        return {
            "grant_id": self.grant_id,
            "principal": self.principal,
            "purpose": self.purpose,
            "allowed_tools": list(self.allowed_tools),
            "allowed_path_prefixes": list(self.allowed_path_prefixes),
            "allowed_domains": list(self.allowed_domains),
            "forbidden_patterns": list(self.forbidden_patterns),
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "provenance": self.provenance,
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "UserGrant":
        return UserGrant(
            grant_id=str(d.get("grant_id", "")),
            principal=str(d.get("principal", "")),
            purpose=str(d.get("purpose", "")),
            allowed_tools=tuple(d.get("allowed_tools") or ()),
            allowed_path_prefixes=tuple(d.get("allowed_path_prefixes") or ()),
            allowed_domains=tuple(d.get("allowed_domains") or ()),
            forbidden_patterns=tuple(d.get("forbidden_patterns") or ()),
            issued_at=str(d.get("issued_at", "")),
            expires_at=d.get("expires_at"),
            provenance=str(d.get("provenance", "")),
        )


@dataclass(frozen=True)
class ProposedAction:
    tool: str
    arguments: Mapping[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        object.__setattr__(self, "arguments", _frozen_mapping(self.arguments))

    def to_dict(self) -> dict:
        return {"tool": self.tool, "arguments": dict(self.arguments)}

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "ProposedAction":
        return ProposedAction(tool=str(d.get("tool", "")), arguments=d.get("arguments") or {})


@dataclass(frozen=True)
class Environment:
    project_root: str = ""
    cwd: str = ""
    harness: str = ""
    harness_version: str = ""
    session_id: str = ""
    # EVAL-ONLY synthetic fact (see EVALS.md, nonsense-steps): True when the
    # commit(s) a history-rewriting command changes existed before the session
    # started. Only semgate.eval.runner reads it (as gitstate.SyntheticHistory);
    # live hooks never set it and the judge never reads it from the envelope:
    # live, gitstate.GitHistory asks git. Omitted from to_dict when None, so
    # existing digests do not change; never sent to the provider.
    git_head_predates_session: Optional[bool] = None
    # EVAL-ONLY synthetic fact (see EVALS.md, slow-drift): the on_task
    # probabilities of this session's earlier steps since the latest user
    # turn, oldest first, as the eval set assumes the model gave them. Only
    # semgate.eval.runner reads it (passed to judge as prior_on_task); live,
    # the judge reads the real values from the ledger. Omitted from to_dict
    # when None, so existing digests do not change; never sent to the provider.
    prior_on_task_p: Optional[Tuple[float, ...]] = None

    def to_dict(self) -> dict:
        d = {
            "project_root": self.project_root,
            "cwd": self.cwd,
            "harness": self.harness,
            "harness_version": self.harness_version,
            "session_id": self.session_id,
        }
        if self.git_head_predates_session is not None:
            d["git_head_predates_session"] = self.git_head_predates_session
        if self.prior_on_task_p is not None:
            d["prior_on_task_p"] = list(self.prior_on_task_p)
        return d

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Environment":
        raw = d.get("git_head_predates_session")
        prior = d.get("prior_on_task_p")
        return Environment(
            project_root=str(d.get("project_root", "")),
            cwd=str(d.get("cwd", "")),
            harness=str(d.get("harness", "")),
            harness_version=str(d.get("harness_version", "")),
            session_id=str(d.get("session_id", "")),
            git_head_predates_session=raw if isinstance(raw, bool) else None,
            prior_on_task_p=(tuple(float(x) for x in prior if isinstance(x, (int, float)) and not isinstance(x, bool))
                             if isinstance(prior, (list, tuple)) else None),
        )


@dataclass(frozen=True)
class TrajectoryEntry:
    tool: str
    decision: str
    summary: str = ""
    # What the tool returned (file content, web page, command output), truncated
    # by the adapter. Untrusted data: the judge scans it for instructions the
    # agent may be following; it is never itself an instruction to the judge.
    output: str = ""
    # Task context (optional). `result`: a short outcome of the call written by
    # the adapter (exit code and first lines of output or error, <= RESULT_MAX
    # chars). `files_changed`: files the call wrote, when the host reports them.
    # Both are untrusted data like `output`. Omitted from to_dict when empty.
    result: str = ""
    files_changed: Tuple[str, ...] = ()

    def __post_init__(self) -> None:
        object.__setattr__(self, "files_changed", tuple(str(f) for f in (self.files_changed or ()) if str(f)))
        if len(self.result) > RESULT_MAX:
            object.__setattr__(self, "result", self.result[:RESULT_MAX])

    def to_dict(self) -> dict:
        d = {"tool": self.tool, "decision": self.decision, "summary": self.summary}
        if self.output:  # omitted when empty so existing digests do not change
            d["output"] = self.output
        if self.result:
            d["result"] = self.result
        if self.files_changed:
            d["files_changed"] = list(self.files_changed)
        return d

    @staticmethod
    def from_dict(e: Mapping[str, Any]) -> "TrajectoryEntry":
        return TrajectoryEntry(tool=str(e.get("tool", "")), decision=str(e.get("decision", "")), summary=str(e.get("summary", "")),
                               output=str(e.get("output", "")), result=str(e.get("result", "") or ""),
                               files_changed=tuple(str(f) for f in (e.get("files_changed") or ())))


@dataclass(frozen=True)
class Trajectory:
    recent: Tuple[TrajectoryEntry, ...] = ()

    def to_dict(self) -> dict:
        return {"recent": [e.to_dict() for e in self.recent]}

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Trajectory":
        entries = tuple(TrajectoryEntry.from_dict(e) for e in (d.get("recent") or ()))
        return Trajectory(recent=entries)


@dataclass(frozen=True)
class Envelope:
    schema: str
    action: ProposedAction
    grant: UserGrant
    environment: Environment = field(default_factory=Environment)
    trajectory: Trajectory = field(default_factory=Trajectory)
    evaluated_at: str = ""
    # The user's latest message, copied by the adapter from the host's own
    # record of user input. Never taken from tool arguments or model output.
    user_message: str = ""
    # Every user turn of the session, oldest first, from the same host record
    # as `user_message` (bounded by bound_user_messages). `user_message` stays
    # the latest turn. Empty means "only user_message is known".
    user_messages: Tuple[str, ...] = ()
    # The agent's latest stated explanation of what it is doing and why
    # (assistant text). UNTRUSTED: written by the agent, which may be wrong or
    # steered by injected content. Never evidence of what the user asked.
    agent_intent: str = ""

    def __post_init__(self) -> None:
        object.__setattr__(self, "user_messages", tuple(str(m) for m in (self.user_messages or ())))

    def all_user_messages(self) -> Tuple[str, ...]:
        """user_messages, or (user_message,) for envelopes that only carry the
        latest turn, or () when neither is set."""
        if self.user_messages:
            return self.user_messages
        return (self.user_message,) if self.user_message else ()

    def to_dict(self) -> dict:
        d = {
            "schema": self.schema,
            "action": self.action.to_dict(),
            "grant": self.grant.to_dict(),
            "environment": self.environment.to_dict(),
            "trajectory": self.trajectory.to_dict(),
            "evaluated_at": self.evaluated_at,
        }
        if self.user_message:  # omitted when empty so existing digests do not change
            d["user_message"] = self.user_message
        if self.user_messages:  # task context fields: omitted when empty (same reason)
            d["user_messages"] = list(self.user_messages)
        if self.agent_intent:
            d["agent_intent"] = self.agent_intent
        return d

    def digest(self) -> str:
        return envelope_digest(self.to_dict())

    def provider_state(self) -> dict:
        """State object sent to the semantic provider. Content is data here:
        nothing in it is treated as an instruction by the judge."""
        return {
            "action": self.action.to_dict(),
            "grant": {
                "purpose": self.grant.purpose,
                "allowed_tools": list(self.grant.allowed_tools),
                "allowed_path_prefixes": list(self.grant.allowed_path_prefixes),
                "allowed_domains": list(self.grant.allowed_domains),
            },
            "environment": {k: v for k, v in self.environment.to_dict().items()
                            if k not in ("git_head_predates_session", "prior_on_task_p")},
            "trajectory": self.trajectory.to_dict(),
        }

    @staticmethod
    def from_dict(d: Mapping[str, Any]) -> "Envelope":
        return Envelope(
            schema=str(d.get("schema", SCHEMA_VERSION)),
            action=ProposedAction.from_dict(d.get("action") or {}),
            grant=UserGrant.from_dict(d.get("grant") or {}),
            environment=Environment.from_dict(d.get("environment") or {}),
            trajectory=Trajectory.from_dict(d.get("trajectory") or {}),
            evaluated_at=str(d.get("evaluated_at", "")),
            user_message=str(d.get("user_message", "")),
            user_messages=tuple(str(m) for m in (d.get("user_messages") or ())),
            agent_intent=str(d.get("agent_intent", "") or ""),
        )
