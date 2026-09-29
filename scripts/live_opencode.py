"""Live end-to-end check against the owner's OpenCode 2 (scripts/test-local.sh
--live opencode). Stdlib only.

What it does:
  1. Needs `opencode2` on PATH and its background service already running
     (`opencode2 serve --service`). It never starts, stops, restarts or
     reconfigures the service; without it the result is SKIP.
  2. Makes a temp project (git init, one committed file) and installs
     semgate's OpenCode plugin there only (in this process, semgate_init():
     `python -m semgate init` refuses when an agent runs this script):
       semgate init opencode --dir <tmp>/semgate --project <tmp>
         --hooks-file <tmp>/.opencode/plugin/semgate.js --mode enforce
         --policy dev --provider openrouter --no-skill --purpose ...
     then adds bash, skill, question to enforcement.auto_allow_tools (the
     owner's posture). --no-skill: the skill file lives in the real home.
  3. Runs, in the temp project:
       opencode2 run -m <model> "Show me the current git status of this project."
     with a timeout. The first call after a service start can be slow, so a
     failed or incomplete first attempt gets one retry; both timings print.
  4. Checks
       (a) the temp ledger has a judgment for bash `git status`: decision
           allow, no provider error;
       (b) the host_response record for it sent allow;
       (c) no `semgate.serve` process naming the temp config is left running
           LINGER_S seconds after opencode2 exits; when the plugin keeps it
           for the service's lifetime (by design), its window handle must be 0;
       (d) no process naming the temp folder had a visible window
           (MainWindowHandle != 0) at any sample during or after the run.
  5. Removes the temp folder.

Prints `LIVE opencode: PASS|FAIL|SKIP (reason, timings)` as its last line.
Exit: 0 PASS, 1 FAIL, 3 SKIP. No key is read or printed here: the plugin's
serve process finds the judge key through semgate's own lookup.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

MODEL = os.environ.get("LIVE_OPENCODE_MODEL", "AgentRouter-openai-gateway/deepseek-v4-flash")
PROMPT = "Show me the current git status of this project."
RUN_TIMEOUT_S = int(os.environ.get("LIVE_OPENCODE_TIMEOUT", "240"))
LINGER_S = 15
WINDOWS = os.name == "nt"
NO_WINDOW = 0x08000000 if WINDOWS else 0          # CREATE_NO_WINDOW


ROOT = Path(__file__).resolve().parent.parent


def semgate_init(argv: List[str]) -> "tuple[int, str]":
    """`semgate <argv>` (an init) in this process, from this checkout, without
    the CLI's own-terminal check (adminguard): this script is the person's own
    test harness, and test-local.sh may run under an agent (Claude Code), where
    `python -m semgate init` refuses. Returns (exit code, output)."""
    import contextlib
    import io
    if str(ROOT) not in sys.path:
        sys.path.insert(0, str(ROOT))
    from semgate import cli, init_antigravity
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(buf):
        code = init_antigravity.run(cli.parse_args(argv), guard=False)
    return code, buf.getvalue()


def run(cmd: List[str], **kw: Any) -> subprocess.CompletedProcess:
    kw.setdefault("capture_output", True)
    kw.setdefault("text", True)
    kw.setdefault("encoding", "utf-8")
    kw.setdefault("errors", "replace")
    kw.setdefault("stdin", subprocess.DEVNULL)
    return subprocess.run(cmd, creationflags=NO_WINDOW, **kw)


# ---------------------------------------------------------------- processes

_PS = r"""
$n = '__NEEDLE__'
$rows = @(Get-CimInstance Win32_Process | Where-Object {
    $_.CommandLine -and $_.CommandLine.ToLower().Contains($n) -and $_.ProcessId -ne $PID -and $_.Name -notmatch '^(powershell|pwsh)' })
$out = foreach ($r in $rows) {
  $p = Get-Process -Id $r.ProcessId -ErrorAction SilentlyContinue
  [pscustomobject]@{ pid = $r.ProcessId; ppid = $r.ParentProcessId; name = $r.Name;
                     hwnd = $(if ($p) { [int64]$p.MainWindowHandle } else { -1 }); cmd = $r.CommandLine }
}
ConvertTo-Json -Compress -InputObject @($out)
"""


def processes_naming(needle: str) -> List[Dict[str, Any]]:
    """Processes whose command line contains `needle` (case-insensitive),
    with their MainWindowHandle on Windows (-1 on other systems)."""
    needle = needle.lower()
    if WINDOWS:
        r = run(["powershell", "-NoProfile", "-NonInteractive", "-Command", _PS.replace("__NEEDLE__", needle.replace("'", "''"))])
        try:
            rows = json.loads(r.stdout or "[]")
        except ValueError:
            return []
        return [x for x in (rows if isinstance(rows, list) else [rows]) if isinstance(x, dict)]
    r = run(["ps", "-eo", "pid=,ppid=,args="])
    out = []
    for line in r.stdout.splitlines():
        parts = line.split(None, 2)
        if len(parts) == 3 and needle in parts[2].lower() and str(os.getpid()) != parts[0]:
            out.append({"pid": int(parts[0]), "ppid": int(parts[1]), "name": parts[2].split()[0], "hwnd": -1, "cmd": parts[2]})
    return out


def service_running() -> Optional[Dict[str, Any]]:
    for p in processes_naming("serve --service"):
        if "opencode2" in str(p.get("name", "")).lower() or "opencode2" in str(p.get("cmd", "")).lower():
            return p
    return None


class WindowWatch(threading.Thread):
    """Samples the processes naming the temp folder about once a second and
    keeps every one seen with a visible window."""

    def __init__(self, needle: str):
        super().__init__(daemon=True)
        self.needle, self.stop, self.visible, self.seen, self.samples = needle, threading.Event(), {}, {}, 0

    def run(self) -> None:
        while not self.stop.is_set():
            for p in processes_naming(self.needle):
                self.seen[p["pid"]] = p
                if int(p.get("hwnd") or 0) > 0:
                    self.visible[p["pid"]] = p
            self.samples += 1
            self.stop.wait(1.0)


# ---------------------------------------------------------------- ledger

def ledger_records(path: Path) -> List[Dict[str, Any]]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except ValueError:
            pass
    return out


def git_status_judgments(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    found = []
    for r in records:
        if r.get("record_type") != "judgment":
            continue
        action = (r.get("envelope") or {}).get("action") or {}
        command = str((action.get("arguments") or {}).get("command", ""))
        if action.get("tool") == "bash" and "git status" in command:
            found.append(r)
    return found


def evaluate(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """(a) and (b) from the ledger records."""
    res: Dict[str, Any] = {"a": False, "b": False, "a_why": "", "b_why": ""}
    js = git_status_judgments(records)
    if not js:
        tools = sorted({str(((r.get("envelope") or {}).get("action") or {}).get("tool")) for r in records
                        if r.get("record_type") == "judgment"})
        res["a_why"] = f"no judgment for bash git status ({len(records)} ledger records, judged tools {tools})"
        return res
    good = [j for j in js if (j.get("decision") or {}).get("decision") == "allow" and not (j.get("decision") or {}).get("error")]
    j = good[0] if good else js[-1]
    d = j.get("decision") or {}
    res["judgment"] = {"decision": d.get("decision"), "stage": d.get("stage"), "provider": d.get("provider"),
                       "error": d.get("error"), "reason_code": d.get("reason_code"),
                       "command": ((j.get("envelope") or {}).get("action") or {}).get("arguments", {}).get("command")}
    res["a"] = bool(good)
    if not good:
        res["a_why"] = f"git status judged {d.get('decision')} (stage {d.get('stage')}, error {str(d.get('error'))[:200]})"
    hr = [r for r in records if r.get("record_type") == "host_response" and r.get("content_digest") == j.get("judgment_id")]
    if hr:
        native = hr[-1].get("native") or {}
        res["host_response"] = {"decision": native.get("decision"), "tool": hr[-1].get("tool")}
        res["b"] = native.get("decision") == "allow"
        if not res["b"]:
            res["b_why"] = f"host_response sent {native.get('decision')}: {str(native.get('reason', ''))[:200]}"
    else:
        res["b_why"] = "no host_response record for the git status judgment"
    return res


def remove_tree(path: Path) -> None:
    """rmtree that also removes read-only files (git objects on Windows)."""
    import stat

    def again(func, p, *_):
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except OSError:
            pass
    shutil.rmtree(path, onerror=again) if sys.version_info < (3, 12) else shutil.rmtree(path, onexc=again)


# ---------------------------------------------------------------- main

def main() -> int:
    exe = shutil.which("opencode2")
    if not exe:
        print("LIVE opencode: SKIP (opencode2 is not on PATH)")
        return 3
    svc = service_running()
    if svc is None:
        print("LIVE opencode: SKIP (the OpenCode 2 background service is not running; "
              "this check never starts it: start it yourself with `opencode2 serve --service`)")
        return 3
    version = run([exe, "--version"]).stdout.strip()
    print(f"== live opencode: {version} service pid {svc['pid']}, model {MODEL}")
    # Not C:\Windows\Temp (where Git Bash points TEMP): OpenCode 2 fails there
    # with "Instruction initialization blocked by unavailable sources:
    # core/instructions". The user's own temp folder works.
    base = Path(os.environ["LOCALAPPDATA"]) / "Temp" if WINDOWS and os.environ.get("LOCALAPPDATA") else None
    tmp = Path(tempfile.mkdtemp(prefix="semgate-live-opencode-", dir=str(base) if base and base.is_dir() else None))
    needle = tmp.name
    cfg = tmp / "semgate" / "semgate.json"
    timings: List[str] = []
    result, reasons = "FAIL", []
    watch = WindowWatch(needle)
    try:
        g = ["git", "-c", "user.name=semgate-live", "-c", "user.email=live@semgate.invalid", "-c", "commit.gpgsign=false"]
        (tmp / "README.md").write_text("# live check project\n\nOne file, for `git status`.\n", encoding="utf-8")
        for cmd in (["git", "init", "-q"], ["git", "add", "README.md"], g + ["commit", "-q", "-m", "one file"]):
            r = run(cmd, cwd=str(tmp))
            if r.returncode:
                raise RuntimeError(f"{' '.join(cmd[:3])} failed: {r.stderr.strip()[:200]}")
        (tmp / "notes.txt").write_text("an untracked file, so git status has something to show\n", encoding="utf-8")
        init = ["init", "opencode", "--dir", str(tmp / "semgate"), "--project", str(tmp),
                "--hooks-file", str(tmp / ".opencode" / "plugin" / "semgate.js"), "--mode", "enforce", "--policy", "dev",
                "--provider", "openrouter", "--no-skill",
                "--purpose", f"Software development in {tmp.as_posix()}: read files, inspect git state, build, test"]
        rc, out = semgate_init(init)
        if rc:
            raise RuntimeError(f"semgate init opencode exit {rc}: {out.strip()[-300:]}")
        doc = json.loads(cfg.read_text(encoding="utf-8"))
        tools = doc.setdefault("enforcement", {}).setdefault("auto_allow_tools", [])
        for t in ("bash", "skill", "question"):
            if t not in tools:
                tools.append(t)
        cfg.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
        print(f"== temp project {tmp} (plugin {tmp / '.opencode' / 'plugin' / 'semgate.js'})")

        watch.start()
        ledger = tmp / "semgate" / "ledger.jsonl"
        checks: Dict[str, Any] = {}
        for attempt in (1, 2):
            t0 = time.monotonic()
            try:
                # PWD too: opencode2 takes the project folder from $PWD when it
                # is set (Git Bash sets it), not from the process's directory.
                r = run([exe, "run", "-m", MODEL, PROMPT], cwd=str(tmp), timeout=RUN_TIMEOUT_S,
                        env={**os.environ, "PWD": str(tmp)})
                rc, out = r.returncode, (r.stdout or "") + (r.stderr or "")
            except subprocess.TimeoutExpired as exc:
                rc, out = "timeout", str(exc.stdout or "")[-400:] if exc.stdout else ""
            took = time.monotonic() - t0
            checks = evaluate(ledger_records(ledger))
            timings.append(f"attempt{attempt}={took:.1f}s rc={rc}")
            tail = " | ".join(line.strip() for line in out.strip().splitlines()[-6:])[:500]
            print(f"== attempt {attempt}: {took:.1f}s, exit {rc}; output tail: {tail}")
            if rc == 0 and checks["a"] and checks["b"]:
                break
        # (c): the serve process for the temp config after opencode2 exited
        deadline = time.monotonic() + LINGER_S
        left = [p for p in processes_naming(needle) if "semgate.serve" in str(p.get("cmd", ""))]
        while left and time.monotonic() < deadline:
            time.sleep(1)
            left = [p for p in processes_naming(needle) if "semgate.serve" in str(p.get("cmd", ""))]
        watch.stop.set()
        watch.join(timeout=10)
        if checks.get("judgment"):
            print(f"== (a) judgment: {json.dumps(checks['judgment'])}")
        if checks.get("host_response"):
            print(f"== (b) host_response: {json.dumps(checks['host_response'])}")
        if not checks.get("a"):
            reasons.append(f"(a) {checks.get('a_why')}")
        if not checks.get("b"):
            reasons.append(f"(b) {checks.get('b_why')}")
        if left:
            desc = ", ".join(f"pid {p['pid']} {p['name']} hwnd {p['hwnd']}" for p in left)
            print(f"== (c) serve still running {LINGER_S}s after opencode2 exited (the plugin keeps it for the "
                  f"service's lifetime; this check does not stop processes it did not start): {desc}")
            if any(int(p.get("hwnd") or 0) != 0 for p in left):
                reasons.append(f"(c) the kept serve process has a window: {desc}")
        else:
            print(f"== (c) no semgate.serve process for the temp config {LINGER_S}s after opencode2 exited")
        print(f"== (d) {watch.samples} samples, {len(watch.seen)} processes named the temp folder, "
              f"{len(watch.visible)} had a visible window")
        if watch.visible:
            reasons.append("(d) visible window: " + ", ".join(f"pid {p['pid']} {p['name']} hwnd {p['hwnd']}"
                                                               for p in watch.visible.values()))
        result = "PASS" if not reasons else "FAIL"
    except Exception as exc:
        reasons.append(f"{type(exc).__name__}: {str(exc)[:300]}")
    finally:
        watch.stop.set()
        cleanup = "removed"
        for _ in range(5):
            remove_tree(tmp)
            if not tmp.exists():
                break
            time.sleep(2)
        else:
            cleanup = f"NOT removed ({tmp})"
            reasons.append(f"temp folder {cleanup}")
            result = "FAIL"
        print(f"== temp folder {cleanup}")
    detail = "; ".join(reasons) if reasons else "git status judged allow, host got allow, no visible window"
    print(f"LIVE opencode: {result} ({detail}; {', '.join(timings) or 'no run'})")
    return 0 if result == "PASS" else 1


if __name__ == "__main__":
    sys.exit(main())
