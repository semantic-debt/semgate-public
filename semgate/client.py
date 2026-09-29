"""A small client for semgate's harness API, and `guard`: the check -> run /
ask a human / refuse loop every framework example uses (LangGraph, the
OpenAI Agents SDK, a plain function-calling loop, n8n does the same with
nodes). Standard library only.

    from semgate.client import HttpClient, guard

    gate = HttpClient("http://127.0.0.1:8787", token=CHECK_TOKEN, approve_token=APPROVE_TOKEN)
    result = guard(gate, request, run=lambda: my_tool(**args), ask_human=ask_in_my_ui)
    result.ran        # True: result.output is the tool's output
    result.message    # when not ran: the text to give the model

`LocalClient` does the same in-process (semgate.check / semgate.approve), no server.

Fail closed. HttpClient.check never raises: a network error, a timeout, a
non-JSON body or an unknown decision is an "ask" without approval_id, and
guard never runs a tool on it.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Mapping, Optional, Sequence, Union


class ApprovalFailed(RuntimeError):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


def _ask(reason: str) -> Dict[str, Any]:
    return {"schema": "semgate-decision/1", "decision": "ask", "reason": reason, "reason_code": "client_failure",
            "stage": "", "judgment_id": ""}


class HttpClient:
    """POST /v1/check and /v1/approve of `semgate serve --http`."""

    def __init__(self, url: str = "http://127.0.0.1:8787", *, token: str = "", approve_token: str = "",
                 timeout_s: float = 30.0) -> None:
        self.url = url.rstrip("/")
        self.token = token
        self.approve_token = approve_token
        self.timeout_s = float(timeout_s)
        # A loopback server is never reached through an HTTP proxy from the
        # environment (the token would pass through the proxy).
        from urllib.parse import urlsplit
        host = (urlsplit(self.url).hostname or "").lower()
        local = host == "localhost" or host.startswith("127.") or host == "::1"
        self._open = (urllib.request.build_opener(urllib.request.ProxyHandler({})).open if local
                      else urllib.request.urlopen)

    def _post(self, path: str, body: Mapping[str, Any], token: str) -> tuple:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(self.url + path, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
        if token:
            req.add_header("Authorization", "Bearer " + token)
        try:
            with self._open(req, timeout=self.timeout_s) as resp:
                return resp.status, resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read()

    def check(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        try:
            status, raw = self._post("/v1/check", request, self.token)
            obj = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            return _ask(f"semgate could not be reached ({type(exc).__name__}); the tool was not run")
        if not isinstance(obj, dict) or obj.get("decision") not in ("allow", "ask", "deny"):
            return _ask(f"semgate answered HTTP {status} without a decision; the tool was not run")
        if status != 200 and obj.get("decision") == "allow":      # never trust an allow on an error status
            return _ask(f"semgate answered HTTP {status}; the tool was not run")
        return obj

    def approve(self, approval_id: str, approved: bool, by: str, note: str = "") -> Dict[str, Any]:
        """HUMAN SIDE ONLY. Raises ApprovalFailed (status 404 unknown/expired,
        409 already answered, 401/403 token)."""
        try:
            status, raw = self._post("/v1/approve", {"approval_id": approval_id, "approved": bool(approved), "by": by,
                                                     "note": note}, self.approve_token or self.token)
        except Exception as exc:
            raise ApprovalFailed(f"semgate could not be reached ({type(exc).__name__})") from exc
        try:
            obj = json.loads(raw.decode("utf-8"))
        except ValueError:
            obj = {}
        if status != 200:
            raise ApprovalFailed(str(obj.get("error") or f"HTTP {status}"), status)
        return obj


class LocalClient:
    """The same calls in-process (semgate.harness), no server."""

    def __init__(self, config: Optional[str] = None, timeout_ms: Optional[int] = None) -> None:
        self.config = config
        self.timeout_ms = timeout_ms

    def check(self, request: Mapping[str, Any]) -> Dict[str, Any]:
        from .harness import check
        return check(request, config=self.config, timeout_ms=self.timeout_ms)

    def approve(self, approval_id: str, approved: bool, by: str, note: str = "") -> Dict[str, Any]:
        from .approvals import ApprovalError
        from .harness import approve
        try:
            return approve(approval_id, approved, by, config=self.config, note=note)
        except ApprovalError as exc:
            raise ApprovalFailed(str(exc), {"not_found": 404, "conflict": 409}.get(exc.code, 400)) from exc


Client = Union[HttpClient, LocalClient, Any]


@dataclass
class GuardResult:
    ran: bool
    output: Any = None                   # the tool's output (ran is True)
    message: str = ""                    # for the model (ran is False)
    decision: Dict[str, Any] = field(default_factory=dict)     # semgate's last answer
    approval: Dict[str, Any] = field(default_factory=dict)     # the human's answer, when one was asked


def blocked_message(d: Mapping[str, Any]) -> str:
    code = d.get("reason_code") or d.get("decision")
    return f"semgate blocked this tool call ({code}): {d.get('reason', '')}"


def human_answer(value: Any, default_by: str = "human") -> Dict[str, Any]:
    """{"approved": bool, "by": str, "already_recorded": bool} from what
    ask_human returned: a bool, a "yes"/"no" string, or a dict with
    approved / by / already_recorded. Anything else is a no."""
    if isinstance(value, bool):
        return {"approved": value, "by": default_by, "already_recorded": False}
    if isinstance(value, str):
        return {"approved": value.strip().lower() in ("y", "yes", "approve", "approved", "allow"), "by": default_by,
                "already_recorded": False}
    if isinstance(value, Mapping):
        return {"approved": value.get("approved") is True, "by": str(value.get("by") or default_by),
                "already_recorded": value.get("already_recorded") is True}
    return {"approved": False, "by": default_by, "already_recorded": False}


def resolve(client: Client, request: Mapping[str, Any], asked: Mapping[str, Any], answer: Any, *,
            default_by: str = "human") -> Dict[str, Any]:
    """After an ask: record the human's answer (approve(), unless the human
    side already did: {"already_recorded": true}) and check the same request
    again. Returns semgate's new answer; run the tool only if it is "allow".
    A human no, or an answer that could not be recorded, returns a "deny"
    answer made here (the tool must not run)."""
    a = human_answer(answer, default_by)
    if not asked.get("approval_id"):
        return dict(_ask("no approval id: a human cannot approve this call now"), decision="deny")
    if not a["already_recorded"]:
        try:
            client.approve(str(asked["approval_id"]), a["approved"], a["by"])
        except ApprovalFailed as exc:
            if exc.status != 409:           # 409: recorded before (a resumed run): check again
                return dict(_ask(f"the human's answer could not be recorded ({exc})"), decision="deny",
                            reason_code="approval_not_recorded")
    if not a["approved"]:
        return dict(asked, decision="deny", reason_code="human_denied",
                    reason=f"a human said no to this tool call: {asked.get('reason', '')}")
    return client.check(request)


def guard(client: Client, request: Mapping[str, Any], run: Callable[[], Any],
          ask_human: Callable[[Dict[str, Any]], Any], *, default_by: str = "human") -> GuardResult:
    """check -> allow: run. deny: do not run; message for the model. ask:
    ask_human(answer) returns the person's answer (a bool, "yes"/"no", or
    {"approved", "by"}), resolve() records it and checks again, and the
    tool runs only on that allow. The tool never runs on an ask."""
    d = client.check(request)
    if d.get("decision") == "allow":
        return GuardResult(True, run(), "", d)
    if d.get("decision") != "ask":
        return GuardResult(False, None, blocked_message(d), d)
    if not d.get("approval_id"):
        return GuardResult(False, None, "semgate could not decide and no human can approve this call now; the tool was "
                                        "not run: " + str(d.get("reason", "")), d)
    raw = ask_human(d)
    answer = human_answer(raw, default_by)
    again = resolve(client, request, d, raw, default_by=default_by)
    if again.get("decision") == "allow":
        return GuardResult(True, run(), "", again, answer)
    if again.get("reason_code") == "human_denied":
        return GuardResult(False, None, again["reason"], again, answer)
    return GuardResult(False, None, blocked_message(again), again, answer)


def safe_id(text: Any, limit: int = 128) -> str:
    """A session or call id semgate accepts ([A-Za-z0-9._:-], at most 256
    characters): other characters become "_"; a long or empty id becomes a
    hash."""
    import hashlib
    raw = str(text or "")
    clean = re.sub(r"[^A-Za-z0-9._:-]", "_", raw)
    if not clean or len(clean) > limit or set(clean) == {"."}:
        return "id-" + hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:32]
    return clean


def request_for(tool: str, arguments: Mapping[str, Any], *, session_id: str, cwd: str,
                user_messages: Sequence[str] = (), recent: Sequence[Mapping[str, Any]] = (), call_id: str = "",
                agent_intent: str = "", harness: str = "custom", **extra: Any) -> Dict[str, Any]:
    """A semgate-check/1 request."""
    req: Dict[str, Any] = {"tool": tool, "arguments": dict(arguments), "session_id": session_id, "cwd": cwd,
                           "user_messages": list(user_messages), "recent": [dict(r) for r in recent],
                           "harness": harness}
    if call_id:
        req["call_id"] = call_id
    if agent_intent:
        req["agent_intent"] = agent_intent
    req.update(extra)
    return req
