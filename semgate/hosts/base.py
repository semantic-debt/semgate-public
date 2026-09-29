"""Host adapter interface and the typed capability manifest.

A host is an agent CLI semgate plugs into (Claude Code, Droid, agy, OpenCode,
Codex, Pi, ...). Each host has:

- a HostAdapter: name, detect() (installed? version?), config paths (user
  level; project level where the host has it), install() / uninstall() /
  verify() of semgate's hook or plugin;
- a Manifest (semgate/data/hosts/<name>.json): for each capability id of
  docs/harness-hooks-survey.md that semgate relies on, whether the host
  supports it (yes / no / partial / unknown), with the source (a hookconf
  result file + version, a live test note, or a doc URL) and whether it was
  measured.

Fail closed: only "yes" counts as supported. "partial", "no", "unknown", a
missing cell or a manifest that does not load all mean "not supported". In
particular, when C2 (ask) is not "yes", fit_decision() turns every ask into a
deny for that host and says so in the reason.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, List, Mapping, Optional, Tuple
from .. import proc

STATUSES = ("yes", "no", "partial", "unknown")

# The survey capabilities semgate relies on (docs/harness-hooks-survey.md).
CAPABILITIES: Dict[str, str] = {
    "C1": "deny + reason",
    "C2": "ask (reduce-only)",
    # Not a survey id: hookconf A2b, the ask of C2 again in every bypass /
    # YOLO mode the host has. Used by host_shows_ask().
    "C2b": "ask honored in bypass / YOLO modes",
    "C3": "allow / PermissionRequest",
    "C6": "headless semantics",
    "C8": "full input values",
    "C10": "stable ids (session id, tool call id)",
    "C11": "user prompt / transcript",
    "C12": "context incl. model id",
    "C14": "output hook",
    "C17": "subagent coverage",
    "C19": "fail-closed option",
    "C21": "tamper protection",
    "C26": "schema version",
    "C33": "post-tool context for the model",
    "C34": "message to the user at stop",
    "C35": "chat approval: ordered user turns after a block",
}

MANIFEST_SCHEMA = "semgate-host-manifest/1"
_DATA = Path(__file__).resolve().parent.parent / "data" / "hosts"


@dataclass(frozen=True)
class Capability:
    id: str
    status: str                      # yes | no | partial | unknown
    source: str = ""                 # e.g. "hookconf results/codex-0.153.1.json: A2=fail" or a URL
    verified: bool = False           # measured (kit or live test), not only read in docs
    note: str = ""

    @property
    def supported(self) -> bool:
        return self.status == "yes"


@dataclass(frozen=True)
class Manifest:
    host: str
    display: str
    measured_version: str            # "" when never measured
    measured_by: str                 # "hookconf 0.1.0 @ 3517a57, results/claude-code-2.1.280.json" / "live notes" / "docs only"
    core_level: str                  # "L4*", "L1", "none", "not measured"
    levels: Mapping[str, str]
    capabilities: Mapping[str, Capability]
    notes: Tuple[str, ...] = ()
    loaded: bool = True              # False: the file was missing or invalid (all cells unknown)
    error: str = ""

    def cap(self, cid: str) -> Capability:
        c = self.capabilities.get(cid)
        return c if c is not None else Capability(cid, "unknown", "not in the manifest")

    def supports(self, cid: str) -> bool:
        return self.cap(cid).supported

    @property
    def ask_maps_to(self) -> str:
        return "ask" if self.supports("C2") else "deny"

    @property
    def shows_ask(self) -> bool:
        """True when a semgate ask never runs the tool without a person: see
        host_shows_ask()."""
        c2b = self.cap("C2b")
        return self.supports("C2") and c2b.supported and c2b.verified

    def conformance_line(self) -> str:
        ver = self.measured_version or "(docs only)"
        ask = "ask supported" if self.supports("C2") else f"ask {self.cap('C2').status} -> ask maps to deny"
        return f"{self.display} {ver}: core {self.core_level}, {ask}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host": self.host, "display": self.display, "measured_version": self.measured_version,
            "measured_by": self.measured_by, "core_level": self.core_level, "levels": dict(self.levels),
            "capabilities": {k: {"status": c.status, "source": c.source, "verified": c.verified, "note": c.note}
                             for k, c in self.capabilities.items()},
            "ask_maps_to": self.ask_maps_to, "loaded": self.loaded, "error": self.error,
        }


def unknown_manifest(host: str, error: str) -> Manifest:
    caps = {cid: Capability(cid, "unknown", "manifest not loaded") for cid in CAPABILITIES}
    return Manifest(host, host, "", "", "unknown", {}, caps, (), False, error)


def parse_manifest(raw: Any, host: str) -> Manifest:
    """Build a Manifest from its JSON form. Raises ValueError on a wrong shape.
    A cell with an unknown status string, or a missing cell, becomes unknown."""
    if not isinstance(raw, dict) or raw.get("schema") != MANIFEST_SCHEMA:
        raise ValueError(f"not a {MANIFEST_SCHEMA} document")
    if raw.get("host") != host:
        raise ValueError(f"manifest is for host {raw.get('host')!r}, expected {host!r}")
    cells = raw.get("capabilities")
    if not isinstance(cells, dict):
        raise ValueError("capabilities must be an object")
    caps: Dict[str, Capability] = {}
    for cid in CAPABILITIES:
        cell = cells.get(cid)
        if not isinstance(cell, dict):
            caps[cid] = Capability(cid, "unknown", "not in the manifest")
            continue
        status = str(cell.get("status", "unknown"))
        if status not in STATUSES:
            status = "unknown"
        caps[cid] = Capability(cid, status, str(cell.get("source", "")), cell.get("verified") is True, str(cell.get("note", "")))
    measured = raw.get("measured") if isinstance(raw.get("measured"), dict) else {}
    conf = raw.get("conformance") if isinstance(raw.get("conformance"), dict) else {}
    levels = conf.get("levels") if isinstance(conf.get("levels"), dict) else {}
    return Manifest(
        host=host, display=str(raw.get("display") or host),
        measured_version=str(measured.get("version") or ""), measured_by=str(measured.get("by") or ""),
        core_level=str(conf.get("core") or "not measured"), levels={str(k): str(v) for k, v in levels.items()},
        capabilities=caps, notes=tuple(str(n) for n in raw.get("notes") or ()),
    )


_CACHE: Dict[str, Manifest] = {}


def load_manifest(host: str, directory: Optional[Path] = None) -> Manifest:
    """The host's manifest; a missing or invalid file gives an all-unknown
    manifest (fail closed), never an exception."""
    key = f"{directory}|{host}"
    if key in _CACHE:
        return _CACHE[key]
    path = Path(directory or _DATA) / f"{host}.json"
    try:
        m = parse_manifest(json.loads(path.read_text(encoding="utf-8")), host)
    except (OSError, ValueError) as exc:
        m = unknown_manifest(host, f"{path.name}: {type(exc).__name__}: {exc}")
    _CACHE[key] = m
    return m


# Hosts whose decision mapping predates the manifests and that have none
# (deprioritized or not measured): their rendering is left exactly as it was.
LEGACY_UNMANIFESTED = frozenset({"vscode", "copilot", "devin"})


def fit_decision(host: str, decision: str, reason: str, manifest: Optional[Manifest] = None) -> Tuple[str, str]:
    """Map semgate's allow/ask/deny to what `host` can honor. A host whose
    manifest does not say C2 = yes cannot show an ask prompt reliably, so an
    ask becomes a deny with the reason prefixed. allow and deny are unchanged.
    Hosts in LEGACY_UNMANIFESTED keep their existing mapping."""
    if decision != "ask" or (manifest is None and host in LEGACY_UNMANIFESTED):
        return decision, reason
    m = manifest or load_manifest(host)
    if m.supports("C2"):
        return decision, reason
    c2 = m.cap("C2")
    why = (f"semgate: {m.display} cannot show an ask prompt (manifest C2 = {c2.status}"
           + (f", measured on {m.measured_version}" if m.measured_version else "") + "), so this ask is a deny. ")
    return "deny", (why + reason)[:1000]


# ---------------------------------------------------------------- environment


_VERSION = re.compile(r"(\d+\.\d+\.\d+(?:[-.][0-9A-Za-z.]+)?)")


def parse_version(text: str) -> str:
    m = _VERSION.search(text or "")
    return m.group(1) if m else ""


def run_version(binary: str, timeout: float = 10.0) -> str:
    """`<binary> --version`, first x.y.z in the output; "" on any problem."""
    try:
        out = proc.run([binary, "--version"], capture_output=True, text=True, timeout=timeout,
                             stdin=subprocess.DEVNULL)
        return parse_version(out.stdout + " " + out.stderr)
    except (OSError, subprocess.SubprocessError, ValueError):
        return ""


@dataclass
class HostEnv:
    """Where to look. Tests give a temporary home and environment."""
    home: Path
    environ: Mapping[str, str] = field(default_factory=dict)
    project: Optional[Path] = None
    version_probe: Optional[Callable[[str], str]] = run_version   # None: do not run host binaries
    # The folder the command runs in. Used only to find project-level plugin
    # copies (e.g. <cwd>/.opencode/plugin/semgate.js) when there is no
    # --project; None in tests that build a HostEnv by hand.
    cwd: Optional[Path] = None

    @classmethod
    def current(cls, project: Optional[str] = None, run_binaries: bool = True) -> "HostEnv":
        try:
            cwd: Optional[Path] = Path.cwd()
        except OSError:            # the current folder was removed
            cwd = None
        return cls(Path.home(), dict(os.environ), Path(project).resolve() if project else None,
                   run_version if run_binaries else None, cwd)

    def project_dirs(self) -> List[Path]:
        """Where to look for project-level copies: --project, else the
        current folder."""
        if self.project is not None:
            return [self.project]
        return [self.cwd] if self.cwd is not None else []

    def which(self, name: str) -> Optional[str]:
        path = self.environ.get("PATH", self.environ.get("Path", ""))
        return shutil.which(name, path=path) if path else None

    def dir_from(self, var: str, default: Path) -> Path:
        value = self.environ.get(var, "")
        return Path(value).expanduser() if value else default

    def config_home(self) -> Path:
        """XDG config dir (OpenCode uses it on every OS)."""
        return self.dir_from("XDG_CONFIG_HOME", self.home / ".config")


@dataclass
class Detection:
    installed: bool
    binary: str = ""
    version: str = ""
    config_dir: str = ""
    how: str = ""                    # "binary on PATH", "config folder", ...


@dataclass
class Finding:
    level: str                       # OK | WARN | FAIL | INFO
    text: str

    def to_dict(self) -> Dict[str, str]:
        return {"level": self.level, "text": self.text}


@dataclass
class ConfigPaths:
    user: List[Path]
    project: List[Path] = field(default_factory=list)
    hooks_file: Optional[Path] = None   # the file semgate's hook/plugin lives in (user level)


class HostAdapter:
    """Base class. Subclasses set the class attributes and override what
    differs. install()/uninstall() live in semgate.hosts.builtin because they
    share the init flow."""
    name: str = ""
    display: str = ""
    binary_names: Tuple[str, ...] = ()
    manifest_names: Tuple[str, ...] = ()        # which manifest(s) describe this host
    installable: bool = False
    default_dir: str = ""                        # semgate's own config dir for this host
    default_hooks: str = ""                      # the user-level hooks/settings file semgate writes

    def manifest(self, version: str = "") -> Manifest:
        return load_manifest(self.manifest_names[0] if self.manifest_names else self.name)

    def config_paths(self, env: HostEnv) -> ConfigPaths:
        raise NotImplementedError

    def detect(self, env: HostEnv) -> Detection:
        binary = ""
        for name in self.binary_names:
            found = env.which(name)
            if found:
                binary = found
                break
        paths = self.config_paths(env)
        cfg_dir = next((p for p in paths.user if p.exists()), None)
        installed = bool(binary) or cfg_dir is not None
        version = ""
        if binary and env.version_probe is not None:
            try:
                version = env.version_probe(binary) or ""
            except Exception:
                version = ""
        how = "binary on PATH" if binary else ("config folder" if cfg_dir is not None else "")
        return Detection(installed, binary, version, str(cfg_dir or ""), how)

    def verify(self, env: HostEnv) -> Tuple[List[Finding], Dict[str, Any]]:
        """Findings about semgate's hook for this host and facts for --json."""
        return [Finding("INFO", "semgate has no installer for this host yet")], {"hook": None}

    def mode_warnings(self, env: HostEnv) -> List[Finding]:
        """Host settings that turn off the host's own prompts."""
        return []

    def hook_configs(self, env: HostEnv) -> List[str]:
        """The `--config <path>` of every semgate hook installed for this host
        at user level, as written in the hook (read only; [] when none, or
        when the hooks file is missing or unreadable). Used by
        `semgate feedback` to find the config without --config."""
        return []

    def installed_files(self, env: HostEnv) -> List[Path]:
        """Every existing file that holds semgate's hook or plugin for this
        host: user level, project level (env.project_dirs()) and the files
        `semgate init` recorded. Used by doctor and `init --refresh`."""
        return []
