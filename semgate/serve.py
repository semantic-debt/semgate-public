"""`semgate serve --stdio`: a long-running judge for plugins.

A plugin (OpenCode, Roomote's OpenCode, Pi, ...) starts this once and sends one
JSON request per line on stdin; each answer is one JSON line on stdout:

    -> {"id": 7, "host": "opencode" | "pi", "timeout_ms": 20000, "request": {"tool": "bash", "args": {...}, "sessionID": "...", "cwd": "...", "messages": [...]}}
    <- {"id": 7, "decision": "allow" | "ask" | "deny", "reason": "..."}

A post-tool event (OpenCode V1 `tool.execute.after`, Pi `tool_result`) only records (F6 created
files, F4 script changes, and the tool's output for the next judge request,
semgate.tooloutputs) and answers {"id": ..., "recorded": true}:

    -> {"id": 8, "host": "opencode", "event": "after", "request": {"sessionID": "...", "callID": "...",
        "tool": "webfetch", "args": {...}, "output": "..."}}

When the output shows a secret this session has not shown before
(semgate.exposures; fingerprint only, never the value), the answer also
carries "notice": the text for the model. The plugin appends it to the
tool's output (OpenCode V1 manifest C33). Post events have their own worker
thread, so a slow judgment never delays them.

Concurrency (formal/REPORT.md S5). Requests are judged by a bounded pool of
worker threads (`serve.workers`, default 4), so one slow model call no longer
delays every request behind it. Answers are written as they finish; the
plugin matches them by id. Every judge request has a deadline: its budget
(the plugin's `timeout_ms`, default 20000) minus a margin (1500 ms), counted
from when serve read the line. At the deadline serve answers "ask" for that id
(never "allow"). A request still waiting for a worker at its deadline is
dropped without being judged. A judgment still running at its deadline is
abandoned: its late result is discarded. Python cannot stop a thread, so an
abandoned judgment keeps its worker. When every worker is held by an
abandoned judgment, or when serve is idle except for abandoned judgments,
serve exits (code 75); the plugin starts a new serve on the next call and
also restarts it after several timeouts in a row.

Every judge request gets one `host_response` record in the ledger, with the
answer the plugin got (like the hooks). A config that cannot be read, a
request that fails its checks and any error while judging fail closed
(semgate.enforcement.fail_closed): OpenCode and Pi cannot show an ask, so
the answer is "deny" with what the user can do (the developer shadow switch
keeps "ask"); a malformed line without an id answers with id null. A
deadline or a restart answers "ask" (the plugin refuses it). When stdin closes, serve
waits for the answers still due (each is bounded by its deadline) and exits.
Nothing is printed to stdout except answer lines.

Input checks (semgate.hookinput, same as the hooks). Each line is read up to
`hook_max_payload_bytes` (default 64 MiB); a longer line is read to its end,
thrown away and answered "ask" (with its id when the line starts with
{"id": N) plus a ledger incident `hook_input_rejected`. A request whose
sessionID is not a plain short token is answered "ask" with the same
incident. The line size and the tool input size are recorded as
evidence.payload on the judgment (semgate.payloadsize).

Hot reload (semgate.codestamp). OpenCode's service keeps one serve process
for days; an update of semgate must reach it without a host restart. At
start serve takes a fingerprint of its package (sha256 of the *.py, *.json,
*.js, *.ts, *.md files; about 12 ms, once). A thread re-checks every
`serve.reload_check_s` seconds (default 2; 0 turns hot reload off) with a
list + stat of the folder (about 1 ms) and hashes again only when a size,
mtime or the file set changed and then stayed the same for
`serve.reload_settle_s` seconds (default 2: pip writes files one by one).
A plugin that can reload sends `"client": {"stamp": "<its asset stamp>",
"reload": 1}` with each request. When the code changed, serve writes one
line

    <- {"id": null, "reload": true, "reason": "semgate code changed ..."}

and keeps judging: every request already sent (and any in flight) is
answered by this process with the old code. On that line the plugin sends
its next call to a new serve and closes this process's stdin; serve answers
what is still open and exits with RELOAD_EXIT_CODE. No request is dropped
and none is answered by a failure, so the host never sees the reload.
A plugin that sends no `client.reload` (a copy written before hot reload)
treats any exit as a crash of the open calls; serve then does NOT exit: it
keeps answering with the old code and records why (serve_event `reload`),
and `semgate doctor` says to refresh the plugin and restart the host.

Every serve process records the plugin stamp it sees first (serve_event
`client`, once per process and stamp): whether the plugin loaded in the
host is older than the asset installed now. The host loads the plugin file
once; `semgate init <host> --refresh` rewrites the file, the host must
restart to load it. `semgate doctor` reads the latest record.
"""
from __future__ import annotations

import argparse
import heapq
import inspect
import json
import os
import queue
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import codestamp, enforcement, exposures, hookinput, payloadsize, storepaths, tooloutputs
from .antigravity_hook import load_json, record_host_response, record_post_event, remember_sent, run_core
from .chatapproval import HostChat

_TO_HOST = {"allow": "allow", "ask": "ask", "force_ask": "ask", "deny": "deny", "deny_unless_prior_grant": "deny"}
DEFAULT_BUDGET_MS = 20000          # the plugin's TIMEOUT_MS
DEFAULT_MARGIN_MS = 1500           # answer before the plugin's own timer fires
DEFAULT_WORKERS = 4
RESTART_EXIT_CODE = 75
RELOAD_EXIT_CODE = 76              # exited after a reload line: the plugin already uses a new serve
DEFAULT_RELOAD_CHECK_S = 2.0
DEFAULT_RELOAD_SETTLE_S = 2.0


def judge_request(host: str, request: Dict[str, Any], config: Dict[str, Any],
                  meta: Optional[Dict[str, Any]] = None, line_bytes: int = 0) -> Dict[str, str]:
    if host not in ("opencode", "pi"):
        raise ValueError(f"unsupported host {host!r}")
    from .adapters import opencode_tool, pi

    adapter = pi if host == "pi" else opencode_tool
    hookinput.require_session_id(request.get("sessionID"))
    model = str(request.get("model") or "") or hookinput.model_from_messages(request.get("messages"))
    records, problem = tooloutputs.load_for_pre(config, str(request.get("sessionID") or ""))
    merge_stats: Dict[str, Any] = {}
    result = run_core(
        config,
        payload=payloadsize.describe(line_bytes, request.get("args"), model),
        build_envelope=lambda grant: adapter.envelope_from_request(request, grant, tool_outputs=records,
                                                                   merge_stats=merge_stats),
        store_problems=[problem] if problem else [],
        extra_evidence={"tool_outputs": merge_stats},
        session_id=str(request.get("sessionID", "")),
        step_idx=request.get("callID"),
        user_messages=lambda: adapter.user_messages(request),
        session_started_at=lambda: (pi.session_started_at(request) if host == "pi"
                                    else opencode_tool.messages_started_at(request.get("messages"))),
        meta=meta,
        # Approval by chat reply (policy router.chat_approval; manifest C35:
        # OpenCode V1 messages yes; V2 yes with the plugin's prompt-hook
        # record `prompts`, only sent for a session without a parent). The
        # plugin refuses every ask.
        chat=HostChat("pi" if host == "pi" else opencode_tool.manifest_host(request.get("messages"), request.get("api")),
                      (lambda: pi.chat_conversation(request)) if host == "pi" else
                      (lambda: opencode_tool.chat_conversation(request.get("messages"), request.get("prompts"))),
                      call_id=str(request.get("callID") or "")),
    )
    return {"decision": _TO_HOST.get(str(result.get("decision")), "ask"), "reason": str(result.get("reason", ""))[:1000]}


def _ask(reason: str) -> Dict[str, str]:
    return {"decision": "ask", "reason": reason[:1000]}


def _failed(host: Any, config: Any, problem: str) -> Dict[str, str]:
    """A failure before or during a judgment (enforcement.fail_closed):
    OpenCode and Pi cannot show an ask, so a deny that says what to do; the
    developer shadow switch keeps its ask."""
    out = enforcement.fail_closed(problem, str(host or "opencode"), config)
    return {"decision": _TO_HOST.get(out["decision"], "ask"), "reason": out["reason"][:1000]}


def _state_key(value: Any) -> str:
    """The sessionID as a store key, or "" when hookinput rejects it (the
    request was already answered ask; nothing is keyed by the bad id)."""
    return "" if hookinput.session_id_problem(value) else str(value or "")


def _settings(config: Any) -> Tuple[int, int, int]:
    s = config.get("serve") if isinstance(config, dict) and isinstance(config.get("serve"), dict) else {}

    def num(key: str, default: int, low: int, high: int) -> int:
        try:
            v = int(s.get(key, default))
        except (TypeError, ValueError):
            return default
        return min(max(v, low), high)
    return (num("workers", DEFAULT_WORKERS, 1, 32), num("budget_ms", DEFAULT_BUDGET_MS, 1000, 600000),
            num("margin_ms", DEFAULT_MARGIN_MS, 0, 10000))


def _reload_settings(config: Any) -> Tuple[float, float]:
    """(check seconds, settle seconds) from semgate.json serve.reload_check_s /
    serve.reload_settle_s. check 0 turns hot reload off."""
    s = config.get("serve") if isinstance(config, dict) and isinstance(config.get("serve"), dict) else {}

    def num(key: str, default: float, high: float) -> float:
        try:
            v = float(s.get(key, default))
        except (TypeError, ValueError):
            return default
        return default if v != v else min(max(v, 0.0), high)       # NaN -> default
    return num("reload_check_s", DEFAULT_RELOAD_CHECK_S, 3600.0), num("reload_settle_s", DEFAULT_RELOAD_SETTLE_S, 60.0)


class _Slot:
    __slots__ = ("rid", "msg", "config", "deadline", "is_judge", "lock", "answered", "started", "finished", "abandoned", "meta",
                 "size")

    def __init__(self, rid: Any, msg: Dict[str, Any], config: Any, deadline: float, is_judge: bool, size: int = 0) -> None:
        self.rid, self.msg, self.config, self.deadline, self.is_judge = rid, msg, config, deadline, is_judge
        self.size = size                            # bytes of the request line (evidence.payload)
        self.lock = threading.Lock()
        self.answered = self.started = self.finished = self.abandoned = False
        self.meta: Dict[str, Any] = {}


class Server:
    def __init__(self, config_path: str, stdout: Any, workers: int = DEFAULT_WORKERS, budget_ms: int = DEFAULT_BUDGET_MS,
                 margin_ms: int = DEFAULT_MARGIN_MS, on_restart: Optional[Callable[[str], None]] = None,
                 judge_fn: Callable[..., Dict[str, str]] = judge_request,
                 watcher: Optional[codestamp.CodeWatcher] = None, reload_check_s: float = DEFAULT_RELOAD_CHECK_S) -> None:
        self.config_path = config_path
        self.stdout = stdout
        self.workers = max(1, int(workers))
        self.budget_ms, self.margin_ms = int(budget_ms), int(margin_ms)
        self.on_restart = on_restart
        self.judge_fn = judge_fn
        try:        # judge_request takes the line size; a test's judge_fn may not
            self.pass_size = "line_bytes" in inspect.signature(judge_fn).parameters
        except (TypeError, ValueError):
            self.pass_size = False
        self.out_lock = threading.Lock()
        self.state = threading.Condition()
        self.work: "queue.Queue[_Slot]" = queue.Queue()
        self.post_work: "queue.Queue[_Slot]" = queue.Queue()     # post events: one thread, never behind a judgment
        self.open: Dict[int, _Slot] = {}          # not yet answered
        self.stuck = 0                              # abandoned judgments still running
        self.restart_reason = ""
        self.timers: List[Tuple[float, int, _Slot]] = []
        self.seq = 0
        self.closed = False
        # hot reload (module docstring)
        self.watcher = watcher
        self.reload_reason = ""                     # the code on disk changed; this process answers what it gets
        self.client_reload = False                  # the plugin handles {"reload": true}
        self.marker_sent = False
        self.clients_seen: set = set()              # (host, stamp) already recorded
        self.last_host = "opencode"
        self._stop = threading.Event()
        if watcher is not None and reload_check_s > 0:
            threading.Thread(target=self._reloader, args=(float(reload_check_s),), name="semgate-reload",
                             daemon=True).start()
        for i in range(self.workers):
            threading.Thread(target=self._worker, name=f"semgate-judge-{i}", daemon=True).start()
        threading.Thread(target=self._worker, args=(self.post_work,), name="semgate-post", daemon=True).start()
        threading.Thread(target=self._watchdog, name="semgate-deadlines", daemon=True).start()

    # ---------- output ----------
    def _write(self, obj: Dict[str, Any]) -> None:
        with self.out_lock:
            self.stdout.write(json.dumps(obj) + "\n")
            self.stdout.flush()

    def _answer(self, slot: _Slot, payload: Dict[str, Any]) -> bool:
        """Answer `slot` once. The first caller (worker or deadline) wins; the
        other one's answer is discarded. Judge answers get a host_response
        record with exactly what the plugin receives."""
        with slot.lock:
            if slot.answered:
                return False
            slot.answered = True
        if slot.is_judge:
            payload = self._record(slot, payload)
        self._write({"id": slot.rid, **payload})
        with self.state:
            self.open.pop(id(slot), None)
            self.state.notify_all()
        self._maybe_restart_when_idle()
        return True

    def _record(self, slot: _Slot, payload: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(slot.config, dict):
            return payload
        req = slot.msg.get("request") if isinstance(slot.msg.get("request"), dict) else {}
        sid = req.get("sessionID")
        # An invalid id goes in as is so record_host_response stores only its
        # length and sha256_12 (never the id); a valid one as its store key.
        key = sid if hookinput.session_id_problem(sid) else _state_key(sid)
        final = record_host_response({"conversationId": key, "stepIdx": req.get("callID")},
                                     slot.config, payload, slot.meta)
        out = dict(payload, decision=_TO_HOST.get(str(final.get("decision")), "ask"), reason=str(final.get("reason", ""))[:1000])
        # The exact text the plugin gets for a blocked call (ownmessages.py).
        remember_sent(slot.config, _state_key(sid), slot.meta, out.get("decision"), out.get("reason"))
        return out

    # ---------- intake ----------
    def _config_or_none(self, host: str = "opencode") -> Any:
        try:
            return storepaths.load(self.config_path, host)
        except Exception:
            return None

    def reject_oversize(self, line: "hookinput.OversizeLine") -> None:
        """A line above hook_max_payload_bytes: not parsed, answered ask (id
        recovered from its first characters when possible), ledger incident."""
        exc = hookinput.InputRejected(
            f"request line is {line.size} characters, above hook_max_payload_bytes ({line.limit}); not parsed",
            "payload_over_limit", {"bytes": line.size, "limit": line.limit})
        config = self._config_or_none()
        hookinput.note_rejection(config if config is not None else self.config_path, exc, "opencode")
        slot = _Slot(line.request_id, {}, config, time.monotonic(), is_judge=True, size=line.size)
        with self.state:
            self.open[id(slot)] = slot
        self._answer(slot, _failed("opencode", config, f"semgate failure: InputRejected: {exc}"))

    def submit(self, line: str, size: int = 0) -> None:
        received = time.monotonic()
        rid: Any = None
        msg: Dict[str, Any] = {}
        config: Any = None
        try:
            parsed = json.loads(line)
            if isinstance(parsed, dict):
                msg = parsed
                rid = msg.get("id")
            if not isinstance(parsed, dict) or not isinstance(msg.get("request"), dict):
                raise ValueError("expected {id, host, request}")
            config = storepaths.load(self.config_path, str(msg.get("host") or "opencode"))
        except Exception as exc:
            host = str(msg.get("host") or "opencode")
            if config is None:
                config = self._config_or_none(host)         # for the host_response record only
            hookinput.note_rejection(config if config is not None else self.config_path, exc, host)
            slot = _Slot(rid, msg, config, received, is_judge=True, size=size)
            with self.state:
                self.open[id(slot)] = slot
            self._answer(slot, _failed(host, config, f"semgate failure: {type(exc).__name__}: {exc}"))
            return
        self._note_client(msg, config)
        is_judge = msg.get("event") != "after"
        budget = self.budget_ms
        try:
            if msg.get("timeout_ms") is not None:
                budget = min(max(int(msg["timeout_ms"]), 1000), 600000)
        except (TypeError, ValueError):
            pass
        deadline = received + max(budget - self.margin_ms, 500) / 1000.0
        slot = _Slot(rid, msg, config, deadline, is_judge, size=size)
        with self.state:
            self.open[id(slot)] = slot
            if is_judge:
                self.seq += 1
                heapq.heappush(self.timers, (deadline, self.seq, slot))
                self.state.notify_all()
        (self.work if is_judge else self.post_work).put(slot)

    # ---------- hot reload ----------
    def _note_client(self, msg: Dict[str, Any], config: Any) -> None:
        """The plugin's client field: can it reload, which asset stamp. A new
        (host, stamp) is recorded once (serve_event `client`)."""
        client = msg.get("client") if isinstance(msg.get("client"), dict) else {}
        host = str(msg.get("host") or "opencode")
        stamp = client.get("stamp") if isinstance(client.get("stamp"), str) else ""
        flag = client.get("reload")
        can_reload = isinstance(flag, (int, float)) and flag >= 1
        key = (host, stamp[:300])
        with self.state:
            self.last_host = host
            if can_reload:
                self.client_reload = True
            send = bool(self.client_reload and self.reload_reason and not self.marker_sent)
            new = key not in self.clients_seen
            self.clients_seen.add(key)
        if new:
            self._record_event(config, "client", self._client_detail(host, stamp, can_reload))
        if send:
            self._send_reload_line()

    @staticmethod
    def _client_detail(host: str, stamp: str, can_reload: bool) -> Dict[str, Any]:
        asset = codestamp.ASSETS.get(host, "")
        detail: Dict[str, Any] = {"pid": os.getpid(), "host": host, "plugin_stamp": stamp[:300], "reload_supported": can_reload,
                                  "asset": asset}
        if asset:
            try:
                current = codestamp.asset_sha256(asset)
            except Exception:
                current = ""
            seen = codestamp.parse_stamp(stamp)
            detail.update(current_sha256=current, current_version=codestamp.installed_version() or "",
                          outdated=bool(current) and (seen is None or seen["asset"] != asset or seen["sha256"] != current))
        return detail

    def _record_event(self, config: Any, event: str, detail: Dict[str, Any]) -> None:
        """Best effort: a ledger problem never changes an answer."""
        if not isinstance(config, dict):
            return
        try:
            from .ledger import Ledger
            Ledger(storepaths.ledger_file(config)).record_serve_event(event, detail)
        except Exception as exc:
            print(f"semgate serve: could not record serve_event {event}: {type(exc).__name__}: {exc}", file=sys.stderr)

    def _send_reload_line(self) -> None:
        with self.state:
            if self.marker_sent or self.closed:
                return
            self.marker_sent = True
            reason = self.reload_reason
        self._write({"id": None, "reload": True, "reason": reason[:1000]})

    def _reloader(self, every: float) -> None:
        while not self._stop.wait(every):
            reason = self.watcher.check() if self.watcher is not None else None
            if reason:
                self._begin_reload(reason)

    def _begin_reload(self, reason: str) -> None:
        with self.state:
            if self.reload_reason or self.closed:
                return
            self.reload_reason = reason
            capable = self.client_reload
            seen_any = bool(self.clients_seen)
            host = self.last_host
        if capable:
            how = "reload line sent: the plugin starts a new serve for its next call and closes this one's input"
        elif seen_any:
            how = ("none: the plugin loaded in the host sends no client.reload (a copy from before hot reload); this process "
                   "keeps answering with the old code. Run `semgate init <host> --refresh` and restart the host")
        else:
            how = "waiting: no request yet; the first request says whether the plugin can reload"
        w = self.watcher
        self._record_event(self._config_or_none(host), "reload", {
            "pid": os.getpid(), "reason": reason[:1000], "how": how, "from": w.fingerprint if w else "",
            "to": w.changed_to if w else "", "version": w.version if w else ""})
        if capable:
            self._send_reload_line()

    # ---------- workers ----------
    def _worker(self, work: "Optional[queue.Queue[_Slot]]" = None) -> None:
        work = self.work if work is None else work
        while True:
            slot = work.get()
            if slot is None:                 # close()
                return
            with slot.lock:
                if slot.answered:            # its deadline passed while it waited: dropped, never judged
                    continue
                stopping = bool(self.restart_reason or self.closed)
                slot.started = not stopping
            if stopping:                     # serve is going away: never judge, answer ask
                self._answer(slot, _ask(f"semgate serve is restarting ({self.restart_reason or 'closed'}); asking human"))
                continue
            try:
                if slot.is_judge:
                    extra = {"line_bytes": slot.size} if self.pass_size else {}
                    payload: Dict[str, Any] = self.judge_fn(str(slot.msg.get("host", "opencode")), slot.msg["request"],
                                                            slot.config, slot.meta, **extra)
                else:
                    req = slot.msg["request"]
                    # An invalid sessionID is not a usable state key: record nothing (as claude_hook._post).
                    record_post_event(slot.config, _state_key(req.get("sessionID")), req.get("callID"), str(req.get("error") or ""))
                    notice = ""
                    if "output" in req:     # the tool's output, for the next judge request (tooloutputs)
                        from .adapters.opencode_tool import _summary
                        tooloutputs.record_post(slot.config, _state_key(req.get("sessionID")), req.get("callID"),
                                                str(req.get("tool") or ""), req.get("output"), summary=_summary(req.get("args")),
                                                is_error=bool(req.get("error")))
                        # Secrets in the output: fingerprint only; the notice goes back to the plugin.
                        host = str(slot.msg.get("host") or "opencode")
                        notice = exposures.on_tool_output(slot.config, host=host,
                                                          manifest_host="pi" if host == "pi" else "opencode-v1",
                                                          session_id=_state_key(req.get("sessionID")),
                                                          tool=str(req.get("tool") or ""), detail=_summary(req.get("args")),
                                                          step=req.get("callID"), output=req.get("output"))
                    payload = {"recorded": True}
                    if notice:
                        payload["notice"] = notice
            except Exception as exc:
                hookinput.note_rejection(slot.config if slot.config is not None else self.config_path, exc,
                                         str(slot.msg.get("host") or "opencode"))
                payload = _failed(slot.msg.get("host"), slot.config, f"semgate failure: {type(exc).__name__}: {exc}")
            with slot.lock:
                slot.finished = True
                was_abandoned = slot.abandoned
            if was_abandoned:
                with self.state:
                    self.stuck -= 1
            self._answer(slot, payload)

    # ---------- deadlines ----------
    def _watchdog(self) -> None:
        while True:
            with self.state:
                while not self.closed and (not self.timers or self.timers[0][0] > time.monotonic()):
                    wait = max(0.0, self.timers[0][0] - time.monotonic()) if self.timers else None
                    self.state.wait(timeout=wait)
                if self.closed:
                    return
                _, _, slot = heapq.heappop(self.timers)
            with slot.lock:
                late = not slot.answered
                running = slot.started and not slot.finished
                if late and running:
                    slot.abandoned = True
            if not late:
                continue
            if running:
                with self.state:
                    self.stuck += 1
            self._answer(slot, dict(_ask("semgate did not decide in time (serve deadline); asking human"), timeout=True))
            with self.state:
                all_stuck = self.stuck >= self.workers
            if all_stuck:
                self._restart("every worker is held by a judgment that passed its deadline")

    def _maybe_restart_when_idle(self) -> None:
        with self.state:
            idle_but_stuck = self.stuck > 0 and not self.open and self.work.empty() and self.post_work.empty()
        if idle_but_stuck:
            self._restart("idle with an abandoned judgment still running")

    def _restart(self, why: str) -> None:
        """Every open request gets "ask" now (what the plugin answers when
        the process exits), then on_restart (main: exit the process). A
        queued request is never judged after this; a late result of a
        running one is discarded."""
        with self.state:
            if self.restart_reason:
                return
            self.restart_reason = why
            self.state.notify_all()
            still_open = list(self.open.values())
        print(f"semgate serve: restarting ({why})", file=sys.stderr)
        self._answer_all(still_open, f"semgate serve is restarting ({why}); asking human")
        if self.on_restart is not None:
            with self.out_lock:
                try:
                    self.stdout.flush()
                except Exception:
                    pass
            self.on_restart(why)

    def drain(self) -> None:
        """Wait until every open request is answered: judge requests are
        bounded by their deadlines, post events are quick, and a restart
        answers everything still open."""
        with self.state:
            while self.open:
                self.state.wait(timeout=0.5)

    def _answer_all(self, slots: List[_Slot], reason: str) -> None:
        for slot in slots:
            with slot.lock:
                running = slot.started and not slot.finished and not slot.abandoned
                if running and not slot.answered:
                    slot.abandoned = True
            if running:
                with self.state:
                    self.stuck += 1
            self._answer(slot, dict(_ask(reason), timeout=True) if slot.is_judge else {"recorded": False})

    def close(self) -> None:
        """Answer anything still open with ask, stop the idle workers and the
        deadline thread (abandoned judgments keep running as daemon threads
        until the process ends)."""
        with self.state:
            self.closed = True
            self.state.notify_all()
            still_open = list(self.open.values())
        self._stop.set()
        self._answer_all(still_open, "semgate serve stopped before deciding; asking human")
        for _ in range(self.workers):
            self.work.put(None)  # type: ignore[arg-type]
        self.post_work.put(None)  # type: ignore[arg-type]


def serve(config_path: str, stdin=sys.stdin, stdout=sys.stdout, *, on_restart: Optional[Callable[[str], None]] = None,
          judge_fn: Callable[..., Dict[str, str]] = judge_request, settings: Optional[Tuple[int, int, int]] = None,
          watcher: Optional[codestamp.CodeWatcher] = None, reload: Optional[Tuple[float, float]] = None) -> int:
    """Read requests until stdin closes. Returns 0, RESTART_EXIT_CODE when
    serve decided to restart (the caller exits; see main), or
    RELOAD_EXIT_CODE after a reload line (the plugin closed stdin because
    it moved to a new serve). `watcher`: the code watcher (tests inject one;
    default: this package, unless serve.reload_check_s is 0)."""
    try:
        loaded = load_json(config_path)
    except Exception:
        loaded = {}
    if settings is None:
        try:
            settings = _settings(loaded)
        except Exception:
            settings = (DEFAULT_WORKERS, DEFAULT_BUDGET_MS, DEFAULT_MARGIN_MS)
    check_s, settle_s = reload if reload is not None else _reload_settings(loaded)
    if watcher is None and check_s > 0:
        watcher = codestamp.CodeWatcher(interval=check_s, settle=settle_s)
    workers, budget_ms, margin_ms = settings
    server = Server(config_path, stdout, workers=workers, budget_ms=budget_ms, margin_ms=margin_ms,
                    on_restart=on_restart, judge_fn=judge_fn, watcher=watcher, reload_check_s=check_s)
    limit = hookinput.max_payload_bytes(config_path)   # memory guard per line (hook_max_payload_bytes)
    for line in hookinput.bounded_lines(stdin, limit):
        if server.restart_reason:
            break
        if isinstance(line, hookinput.OversizeLine):
            server.reject_oversize(line)
            continue
        size = len(line.encode("utf-8", "replace"))
        line = line.strip()
        if line:
            server.submit(line, size)
    server.drain()
    server.close()
    if server.restart_reason:
        return RESTART_EXIT_CODE
    return RELOAD_EXIT_CODE if server.marker_sent else 0


def _exit_now(why: str) -> None:
    # Hung judgment threads cannot be stopped; leave the process at once.
    # The plugin sees the exit, answers its open calls with "ask" and starts
    # a new serve on the next call.
    try:
        sys.stdout.flush()
    finally:
        os._exit(RESTART_EXIT_CODE)


def main(argv=None) -> int:
    from . import httpserve
    parser = argparse.ArgumentParser(prog="semgate serve")
    transport = parser.add_mutually_exclusive_group(required=True)
    transport.add_argument("--stdio", action="store_true", help="JSON lines on stdin/stdout (OpenCode and Pi plugins)")
    transport.add_argument("--http", action="store_true", help="HTTP API for any harness: POST /v1/check, POST /v1/approve, "
                                                               "GET /v1/health (semgate.httpserve)")
    parser.add_argument("--config", default="", help="semgate.json (default: $SEMGATE_CONFIG, else "
                                                     "~/.semgate/opencode/semgate.json for --stdio and "
                                                     "~/.semgate/http/semgate.json for --http)")
    group = parser.add_argument_group("--http options")
    httpserve.add_arguments(group)
    args = parser.parse_args(argv)
    if args.http:
        from .harness import default_config_path
        args.config = args.config or default_config_path()
        return httpserve.main(args)
    args.config = args.config or os.environ.get("SEMGATE_CONFIG", os.path.expanduser("~/.semgate/opencode/semgate.json"))
    code = serve(args.config, on_restart=_exit_now)
    sys.stdout.flush()
    os._exit(code)        # do not wait for abandoned (daemon) judgment threads


if __name__ == "__main__":
    raise SystemExit(main())
