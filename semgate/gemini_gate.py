"""Experimental no-fork Gemini BeforeTool gateway: DENY or opt-in ASK only.

No tool execution, native ALLOW, feedback writes, learned permissions or caches.
A valid Semgate ALLOW still requires host confirmation. This is a Phase 0/1
foundation, not a production enforcement boundary. See docs/gemini-v2-foundation.md.
"""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import unicodedata
from typing import Any, Mapping, Optional

from .action_identity import canonical_json, request_identity
from . import proc

CONFIG_SCHEMA = "semgate-gemini-config/1"
WORKER_SCHEMA = "semgate-gemini-result/1"
MAX_INPUT = 131072
MAX_OUTPUT = 16384
CONFIG_KEYS = {"schema", "project_root", "grant_file", "policy_file", "shell",
               "harness_version", "provider", "model", "deadline_seconds",
               "confirmation_probe"}
GRANT_KEYS = {"grant_id", "principal", "purpose", "allowed_tools",
              "allowed_path_prefixes", "allowed_domains", "forbidden_patterns",
              "issued_at", "expires_at", "provenance"}


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(_):
    raise ValueError("non-finite JSON number")


def parse_object(text: str) -> dict:
    if len(text.encode("utf-8")) > MAX_INPUT:
        raise ValueError("input too large")
    value = json.loads(text, object_pairs_hook=_pairs, parse_constant=_bad_constant)
    if type(value) is not dict:
        raise ValueError("expected a JSON object")
    canonical_json(value)  # Reject non-JSON values and excessive nesting.
    return value


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value.strip() or "\x00" in value:
        raise ValueError("missing or invalid " + label)
    return value


def _path(value: Any, label: str, directory: bool = False) -> Path:
    path = Path(_text(value, label))
    if not path.is_absolute():
        raise ValueError(label + " must be absolute")
    path = path.resolve(strict=True)
    if directory and not path.is_dir():
        raise ValueError(label + " must be a directory")
    if not directory and not path.is_file():
        raise ValueError(label + " must be a file")
    return path


def _within(path: Path, root: Path) -> bool:
    return path == root or root in path.parents


def _expiry(value: Any, now: Optional[datetime] = None) -> datetime:
    text = _text(value, "expires_at")
    stamp = datetime.fromisoformat(text[:-1] + "+00:00" if text.endswith("Z") else text)
    if stamp.tzinfo is None:
        raise ValueError("expiry must include a timezone")
    current = now or datetime.now(timezone.utc)
    remaining = (stamp - current).total_seconds()
    if not 0 < remaining <= 86400:
        raise ValueError("grant must expire within the next 24 hours")
    return stamp


def _read_object(path: Path) -> dict:
    with path.open("r", encoding="utf-8-sig") as handle:
        return parse_object(handle.read(MAX_INPUT + 1))


def load_config(filename: str) -> dict:
    config_path = _path(filename, "config")
    config = _read_object(config_path)
    if config.get("schema") != CONFIG_SCHEMA or set(config) - CONFIG_KEYS:
        raise ValueError("unsupported config schema or fields")
    root = _path(config.get("project_root"), "project_root", directory=True)
    grant_file = _path(config.get("grant_file"), "grant_file")
    policy_file = _path(config.get("policy_file"), "policy_file")
    # Necessary hygiene, not proof of OS isolation. Same-user agents may still
    # write outside the workspace; no approval authority is granted by this.
    if any(_within(path, root) for path in (config_path, grant_file, policy_file)):
        raise ValueError("config, grant and policy must be outside the agent workspace")
    if config.get("shell") not in {"powershell", "pwsh", "cmd", "bash", "zsh"}:
        raise ValueError("explicit supported shell required")
    _text(config.get("harness_version"), "harness_version")
    provider = config.get("provider", "none")
    if provider not in {"none", "typesafe", "openrouter"}:
        raise ValueError("unsupported provider")
    if provider in ("typesafe", "openrouter"):
        _text(config.get("model"), "model")
    deadline = config.get("deadline_seconds", 5.0)
    if type(deadline) not in (int, float) or not 0.1 <= deadline <= 30:
        raise ValueError("deadline_seconds must be between 0.1 and 30")
    probe = config.get("confirmation_probe", False)
    if type(probe) is not bool:
        raise ValueError("confirmation_probe must be a boolean")
    return {**config, "project_root": str(root), "grant_file": str(grant_file),
            "policy_file": str(policy_file), "provider": provider,
            "deadline_seconds": float(deadline), "confirmation_probe": probe}


def prepare_request(event: Mapping[str, Any], config: Mapping[str, Any]) -> dict:
    if event.get("hook_event_name") != "BeforeTool":
        raise ValueError("expected BeforeTool")
    if event.get("tool_name") != "run_shell_command":
        raise ValueError("unsupported tool; no implicit pass-through")
    arguments = event.get("tool_input")
    if type(arguments) is not dict:
        raise ValueError("tool_input must be an object")
    if set(arguments) - {"command", "description", "dir_path", "is_background"}:
        raise ValueError("unverified shell arguments")
    _text(arguments.get("command"), "command")  # Do NOT strip or lowercase it.
    if "description" in arguments and type(arguments["description"]) is not str:
        raise ValueError("description must be a string")
    if "dir_path" in arguments and arguments["dir_path"] not in (None, ""):
        raise ValueError("dir_path overrides require separate conformance tests")
    if "is_background" in arguments and arguments["is_background"] is not False:
        raise ValueError("background execution is not supported by this probe")
    root = Path(config["project_root"])
    cwd = _path(event.get("cwd"), "cwd", directory=True)
    if not _within(cwd, root):
        raise ValueError("cwd is outside the configured project")
    session = _text(event.get("session_id"), "session_id")
    grant = _read_object(Path(config["grant_file"]))
    if set(grant) - GRANT_KEYS:
        raise ValueError("unsupported grant fields")
    for field in ("grant_id", "principal", "purpose", "provenance"):
        _text(grant.get(field), field)
    _expiry(grant.get("expires_at"))
    for field in ("allowed_tools", "allowed_path_prefixes", "allowed_domains", "forbidden_patterns"):
        values = grant.get(field, [])
        if type(values) is not list or any(type(x) is not str or not x.strip() for x in values):
            raise ValueError("grant lists must contain nonempty strings")
    if "bash" not in grant.get("allowed_tools", []) or "*" in grant["allowed_tools"]:
        raise ValueError("grant requires an explicit bash tool scope, no wildcard")
    prefixes = [_path(p, "scope prefix", directory=True) for p in grant.get("allowed_path_prefixes", [])]
    if not prefixes or any(not _within(p, root) for p in prefixes) or not any(_within(cwd, p) for p in prefixes):
        raise ValueError("grant requires project-bounded path scope covering cwd")
    # Grant, provider, shell and policy come only from operator config, NEVER
    # from event/tool arguments, transcript text or an agent's approval claims.
    context = {"harness": "gemini-cli", "harness_version": config["harness_version"],
               "session_id": session, "cwd": str(cwd), "project_root": str(root),
               "shell": config["shell"], "reported_cwd": event["cwd"]}
    return {"arguments": arguments, "context": context, "grant": grant,
            "policy_file": config["policy_file"], "provider": config["provider"],
            "model": config.get("model", "")}


def evaluate_request(request: Mapping[str, Any]) -> dict:
    """Reuse the real judge, without either legacy authority store."""
    from .envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant
    from .judge import judge
    from .policy import Policy

    _expiry(request["grant"]["expires_at"])
    policy = Policy.load(request["policy_file"])
    context = request["context"]
    envelope = Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction("bash", dict(request["arguments"])),
        grant=UserGrant.from_dict(request["grant"]),
        environment=Environment(**{key: context[key] for key in (
            "project_root", "cwd", "harness", "harness_version", "session_id")}),
    )
    provider = None
    if request["provider"] == "typesafe":
        if not os.environ.get("TYPESAFE_API_KEY"):
            raise ValueError("explicit provider credentials required")
        from .providers.typesafe import TypeSafeProvider
        provider = TypeSafeProvider(model=request["model"])
    elif request["provider"] == "openrouter":
        # Same rule as typesafe: the key must be in this process's environment.
        if not os.environ.get("OPENROUTER_API_KEY"):
            raise ValueError("explicit provider credentials required")
        from .providers.openrouter import OpenRouterDecisionsProvider
        provider = OpenRouterDecisionsProvider(model=request["model"], api_key=os.environ["OPENROUTER_API_KEY"])
    elif request["provider"] != "none":
        raise ValueError("unsupported provider")
    decision = judge(envelope, policy, provider=provider, history=None, feedback=None,
                     path_env=os.environ.get("PATH", ""))
    identity = request_identity(tool="run_shell_command", arguments=request["arguments"],
                                context=context, grant=request["grant"],
                                policy_version=policy.version,
                                provider=request["provider"] + ":" + request["model"])
    return {"schema": WORKER_SCHEMA, "request_identity": identity,
            "decision": decision.decision, "stage": decision.stage,
            "reasons": [_safe(str(r)) for r in decision.reasons[:5]],
            "failed": bool(decision.error), "missing_evidence": bool(decision.missing_evidence)}


def _safe(text: str) -> str:
    return "".join("\\u%04x" % ord(c) if unicodedata.category(c).startswith("C") else c
                   for c in text[:500])[:1000]


def blocked(message: str) -> dict:
    reason = "semgate: " + _safe(message)
    return {"decision": "deny", "reason": reason, "systemMessage": reason}


def map_result(result: Mapping[str, Any], confirmation_probe: bool) -> dict:
    if result.get("schema") != WORKER_SCHEMA:
        raise ValueError("unsupported worker schema")
    if result.get("decision") not in {"allow", "ask", "deny"}:
        raise ValueError("invalid judge decision")
    if result.get("stage") not in {"hard_rules", "grant_validity", "human_gate", "semantic"}:
        raise ValueError("unexpected or legacy approval stage")
    valid_outcomes = {"hard_rules": {"allow", "deny"}, "grant_validity": {"ask"},
                      "human_gate": {"ask"}, "semantic": {"allow", "ask", "deny"}}
    if result["decision"] not in valid_outcomes[result["stage"]]:
        raise ValueError("inconsistent judge stage and decision")
    if type(result.get("failed")) is not bool or type(result.get("missing_evidence")) is not bool:
        raise ValueError("invalid worker failure fields")
    identity = result.get("request_identity", "")
    if type(identity) is not str or not identity.startswith("semgate-action/2:") or len(identity) != 81:
        raise ValueError("missing versioned identity")
    if any(c not in "0123456789abcdef" for c in identity.split(":", 1)[1]):
        raise ValueError("invalid identity digest")
    reasons = result.get("reasons")
    if type(reasons) is not list or any(type(r) is not str for r in reasons):
        raise ValueError("invalid reasons")
    stage, decision = result["stage"], result["decision"]
    if stage == "grant_validity" or result["failed"] or result["missing_evidence"]:
        return blocked("invalid/expired grant, missing evidence or provider failure; no execution")
    if stage == "hard_rules" and decision == "deny":
        return blocked("hard denial; no approval is available")
    if confirmation_probe is not True:
        return blocked("confirmation probe is disabled; native enforcement remains unverified")
    reason = _safe("semgate " + stage + "/" + decision + ": " + "; ".join(reasons))
    # Deliberately never output ALLOW, even when the model clears a command.
    return {"decision": "ask", "reason": reason,
            "systemMessage": reason + " | Experimental one-shot review. Choose proceed once only. "
                             "No approval is persisted. Request " + identity}


def run_worker(request: Mapping[str, Any], deadline: float) -> dict:
    # Keep -I isolation (ignore env, no user site) but re-add the semgate package
    # location explicitly. -I hides the user site, where semgate is often
    # installed on Windows (pip install --user) and it is absent entirely when
    # run from source, so a plain "-I -m semgate.gemini_gate" cannot import the
    # package and the gateway would deny every command. The payload still arrives
    # on stdin, never argv.
    bootstrap = (
        "import sys; sys.path.insert(0, %r); "
        "from semgate.gemini_gate import main; sys.exit(main(['--worker']))"
        % str(Path(__file__).resolve().parents[1])
    )
    process = proc.run(
        [sys.executable, "-I", "-c", bootstrap],
        input=canonical_json(request), capture_output=True, encoding="utf-8",
        timeout=deadline, shell=False,
    )
    if process.returncode != 0 or len(process.stdout.encode("utf-8")) > MAX_OUTPUT:
        raise ValueError("judge process failed or returned oversized output")
    return parse_object(process.stdout)


def main(argv=None) -> int:
    try:
        parser = argparse.ArgumentParser(prog="semgate-gemini-gate", add_help=False)
        parser.add_argument("--config")
        parser.add_argument("--worker", action="store_true")
        args = parser.parse_args(argv)
        if bool(args.config) == bool(args.worker):
            raise ValueError("select exactly one of --config or --worker")
        payload = parse_object(sys.stdin.read(MAX_INPUT + 1))
        if args.worker:
            with redirect_stdout(sys.stderr):
                result = evaluate_request(payload)
        else:
            config = load_config(args.config)
            request = prepare_request(payload, config)
            result = run_worker(request, config["deadline_seconds"])
            _expiry(request["grant"]["expires_at"])  # Recheck after model latency.
            result = map_result(result, config["confirmation_probe"])
        print(canonical_json(result))
        return 0
    except (Exception, KeyboardInterrupt, SystemExit) as exc:
        # Do not leak exceptions, payloads or credentials into the UI. Valid
        # denial JSON plus code 2 avoids the host's generic warning/pass path.
        message = "gateway failure (" + type(exc).__name__ + "); blocked"
        print(canonical_json(blocked(message)))
        print("semgate: " + message, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
