"""`semgate doctor`: read-only check of every detected host.

One line per detected host, then the details of every WARN/FAIL, then a
summary. For each host:

- installed? version (`<binary> --version`, skipped with --no-exec)
- every installed copy of semgate's plugin / extension / hook entry
  (hosts.builtin installed_files): user level, project level (--project, else
  the current folder: OpenCode .opencode/plugin(s)/semgate.js, Pi
  .pi/extensions/semgate.ts) and the files `semgate init` recorded in
  <semgate dir>/installed_files.json. WARN when a copy is older than this
  semgate (its stamp line differs from the source asset, or it has none; a
  JSON hook entry differs from what init writes now), with the
  `semgate init <host> --refresh ...` command that rewrites it; WARN when
  the latest serve_event `client` in the ledger says the running host
  loaded an older plugin (restart the host)
- Pi: WARN for a project-level extension (<project>/.pi/extensions/
  semgate.ts) unless Pi's trust.json or defaultProjectTrust trusts the
  project; `pi -p` skips it without a message (hosts/pitrust.py). Also WARN
  when the trust status is unknown. Pi's files are only read
- semgate's hook/plugin present, pointing at an interpreter and a
  semgate.json that exist; fail-closed settings in semgate.json (enforce,
  block_when_unsure, bash not auto-allowed, grant present and not expired)
- host settings that turn off the host's own prompts (then semgate is the
  only gate): Claude defaultMode bypassPermissions, VS Code
  chat.tools.autoApprove, OpenCode permission bash "*": "allow", Gemini/agy
  yolo / auto_edit, Codex approval_policy never
- the manifest's conformance line and ask mapping; version drift (installed
  version differs from the measured one -> "not measured")
- the TypeSafe key and the OpenRouter key: found / not found and where
  (never the key or its length)
- one `stores:` line per host with a semgate.json: the absolute store paths
  its hook uses (semgate.storepaths; never relative to the current directory)
- the hook's python can `import semgate` (runs `<python> -c "import semgate"`;
  skipped with --no-exec)
- whether a bare `semgate` is on PATH, and the command the agent skill uses
  instead (skill.command())

Never writes anything: no file, no folder, no ledger.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from .hosts import ADAPTERS
from .hosts.base import Finding, HostEnv
from .providers import keys

_RANK = {"OK": 0, "INFO": 0, "UNGATED": 1, "WARN": 2, "FAIL": 3}
SOURCE_ENV = keys.CHECKOUT_ENV    # the providers' second .env location


def typesafe_key(env: HostEnv) -> Dict[str, Any]:
    """Where TYPESAFE_API_KEY would come from, in the order the provider reads it."""
    return provider_key(env, "typesafe")


def openrouter_key(env: HostEnv) -> Dict[str, Any]:
    """Where OPENROUTER_API_KEY would come from, in the order the provider reads it."""
    return provider_key(env, "openrouter")


def provider_key(env: HostEnv, provider: str) -> Dict[str, Any]:
    """{"found", "location"} for a provider's key (providers/keys.py: the
    environment, ~/.semgate/.env, the checkout .env, in a git worktree the main
    checkout's .env). Never the key or its length."""
    return keys.key_status(provider, environ=env.environ, home=env.home, checkout=SOURCE_ENV)


def _env_file_has_key(path: Path, name: str = "TYPESAFE_API_KEY") -> bool:
    return bool(keys.env_file_value(path, name))


def check_host(adapter, env: HostEnv) -> Optional[Dict[str, Any]]:
    det = adapter.detect(env)
    if not det.installed:
        return None
    manifest = adapter.manifest(det.version)
    try:
        findings, facts = adapter.verify(env)
    except Exception as exc:          # a check must never crash the report
        findings, facts = [Finding("FAIL", f"check failed: {type(exc).__name__}: {exc}")], {}
    try:
        findings = list(findings) + adapter.mode_warnings(env)
    except Exception as exc:
        findings.append(Finding("WARN", f"settings check failed: {type(exc).__name__}: {exc}"))
    if manifest.loaded:
        if manifest.measured_version and det.version and det.version != manifest.measured_version:
            findings.append(Finding("WARN", f"installed {det.version} is not measured (manifest measured {manifest.measured_version}); "
                                            "capabilities may differ"))
        elif manifest.measured_version and not det.version:
            findings.append(Finding("INFO", f"installed version unknown; manifest measured {manifest.measured_version}"))
        elif not manifest.measured_version:
            findings.append(Finding("INFO", "no measured version: every manifest cell is from docs"))
        if not manifest.supports("C2"):
            findings.append(Finding("INFO", f"ask {manifest.cap('C2').status} for this host: semgate's ask is a deny here"))
        c19 = manifest.cap("C19")
        if not c19.supported:
            findings.append(Finding("INFO", f"host fail-closed option: {c19.status} (C19); if the hook process cannot start, the host may run the tool"))
    elif adapter.manifest_names:
        findings.append(Finding("WARN", f"manifest not loaded ({manifest.error}); every capability counts as unsupported"))
    installable = adapter.installable
    worst = max((_RANK.get(f.level, 0) for f in findings), default=0)
    status = {0: "OK", 1: "UNGATED", 2: "WARN", 3: "FAIL"}[worst]
    hook_found = any(f.level == "OK" and f.text.startswith("hook installed") for f in findings)
    if not installable and worst < 2 and not hook_found and adapter.name != "vscode":
        status = "UNGATED"
    head = next((f.text for f in findings if f.level in ("OK", "FAIL")), "") or next((f.text for f in findings), "")
    return {
        "host": adapter.name, "display": adapter.display, "installed": True, "binary": det.binary, "version": det.version,
        "detected_by": det.how, "status": status, "headline": head,
        "conformance": manifest.conformance_line() if manifest.loaded else "no manifest",
        "manifest": {"measured_version": manifest.measured_version, "core_level": manifest.core_level,
                     "ask_maps_to": manifest.ask_maps_to, "loaded": manifest.loaded},
        "findings": [f.to_dict() for f in findings], "facts": facts,
    }


def run_doctor(env: HostEnv) -> Dict[str, Any]:
    hosts = [r for r in (check_host(a, env) for a in ADAPTERS.values()) if r is not None]
    key = typesafe_key(env)
    counts: Dict[str, int] = {}
    for h in hosts:
        counts[h["status"]] = counts.get(h["status"], 0) + 1
    providers = {(h.get("facts") or {}).get("semgate", {}).get("provider") for h in hosts}
    demo = sorted(h["host"] for h in hosts if (h.get("facts") or {}).get("semgate", {}).get("provider") == "recorded")
    return {"hosts": hosts, "typesafe_key": key, "openrouter_key": openrouter_key(env), "semgate_command": semgate_command(env),
            "summary": {"detected": len(hosts), "by_status": counts, "typesafe_needed": "typesafe" in providers,
                        "openrouter_needed": "openrouter" in providers, "demo_hosts": demo}}


def semgate_command(env: HostEnv) -> Dict[str, Any]:
    """Whether a bare `semgate` runs from this shell's PATH, and the command
    the agent skill uses (skill.command(): this install's absolute path).
    The agent's shell usually has the same PATH as the user's, without an
    activated venv."""
    from . import skill
    return {"on_path": env.which("semgate") or "", "skill_command": skill.command()}


def render(report: Dict[str, Any]) -> str:
    lines = ["semgate doctor (read only)"]
    for h in report["hosts"]:
        ver = h["version"] or "?"
        lines.append(f"{h['host']:<12} {ver:<10} {h['status']:<8} {h['headline']}  |  {h['conformance']}")
        stores = (h.get("facts") or {}).get("store_paths")
        if stores:
            lines.append(f"{'':<12} stores: " + "; ".join(f"{label} {path}" for label, path in stores))
    if not report["hosts"]:
        lines.append("no supported host detected")
    details = [(h["host"], f) for h in report["hosts"] for f in h["findings"] if f["level"] in ("WARN", "FAIL")]
    if details:
        lines.append("")
        lines.append("Details:")
        for host, f in details:
            lines.append(f"  [{f['level']}] {host}: {f['text']}")
    s = report["summary"]
    parts = ", ".join(f"{n} {k}" for k, n in sorted(s["by_status"].items()))
    key = report["typesafe_key"]
    key_text = f"found ({key['location']})" if key["found"] else "not found"
    orkey = report.get("openrouter_key") or {"found": False, "location": ""}
    or_text = f"found ({orkey['location']})" if orkey["found"] else "not found"
    lines.append("")
    lines.append(f"Summary: {s['detected']} host(s) detected" + (f": {parts}" if parts else "") + f". TypeSafe key: {key_text}."
                 f" OpenRouter key: {or_text}.")
    if not key["found"] and s["typesafe_needed"]:
        lines.append("  A semgate.json uses provider typesafe but no key was found: every semantic decision abstains (asks).")
    if not orkey["found"] and s.get("openrouter_needed"):
        lines.append("  A semgate.json uses provider openrouter but OPENROUTER_API_KEY was not found: every semantic "
                     "decision abstains (asks).")
    if s.get("demo_hosts"):
        lines.append(f"  DEMO mode ({', '.join(s['demo_hosts'])}): provider recorded, no key. Only the demo's recorded inputs "
                     "get a model answer; every other semantic decision asks. For live Jev: semgate init <host> --force "
                     "(with a key).")
    sc = report.get("semgate_command") or {}
    if sc and not sc.get("on_path"):
        if sc.get("skill_command", "semgate") == "semgate":
            lines.append("  WARN: `semgate` is not on PATH, and its install path cannot be written without quotes: an agent "
                         "cannot run `semgate trust ...`. Put semgate's scripts folder on PATH (or install it with pipx).")
        else:
            lines.append(f"  semgate is not on PATH; the agent skill runs it as {sc['skill_command']}.")
    if any(h["status"] == "UNGATED" for h in report["hosts"]):
        lines.append("  UNGATED: the host is installed, semgate has no hook for it yet.")
    return "\n".join(lines)


def main(args: argparse.Namespace) -> int:
    env = HostEnv.current(project=args.project or None, run_binaries=not args.no_exec)
    report = run_doctor(env)
    if args.json:
        json.dump(report, sys.stdout, indent=2, sort_keys=True)
        sys.stdout.write("\n")
    else:
        print(render(report))
    return 1 if any(h["status"] == "FAIL" for h in report["hosts"]) else 0


def add_parser(sub: argparse._SubParsersAction) -> None:
    p = sub.add_parser("doctor", help="Read-only check: detected hosts, semgate hook, fail-closed settings, prompt-disabling modes, key, conformance")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument("--project", default="", help="also check this project's host settings (e.g. .claude/settings.json)")
    p.add_argument("--no-exec", action="store_true", help="do not run `<host> --version` or the hook's python (the `import semgate` check)")
    p.set_defaults(func=main)
