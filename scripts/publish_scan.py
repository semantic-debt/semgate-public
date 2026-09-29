"""Checks a public snapshot made by scripts/make-public-snapshot.sh.

Prints one PASS / FAIL / SKIP row per check and exits 1 when any check fails.
It never prints a secret value: secret-like strings are shown as
prefix(4) + length + sha256[:16]; the real keys from the .env files stay in
this process and only "found" / "not found" is printed.

Per-repo settings come from `.publish/scan.json` in the source commit (read
with `git show`, so the file itself does not need to be in the snapshot):

    {
      "license": {"spdx": "Apache-2.0", "require": ["LICENSE", "NOTICE"]},
      "reviewed_secrets": [{"sha16": "...", "why": "..."}],
      "owner_paths": {"allow_files": [{"glob": "...", "why": "..."}]},
      "emails": {"allow_addresses": [], "allow_domains": [], "allow_files": [{"glob": "...", "why": "..."}]},
      "ai_attribution": {"allow_files": [{"glob": "...", "why": "..."}]},
      "vendor_markers": [{"id": "...", "vendor": "...", "pattern": "regex", "status": "unreported",
                          "note": "...", "paths": ["glob", ...]}],
      "agpl_reviewed": [{"sha16": "...", "why": "..."}],
      "large_files": {"max_bytes": 10000000, "allow_files": [{"glob": "...", "why": "..."}]},
      "forbidden_allow": [{"glob": "...", "why": "..."}]
    }

A vendor marker fails the scan while its status is not "reported" or
"accepted": set the status (and a link in "note") after the vendor report is
filed, or remove the text from the repo.

Provider token formats that GitHub push protection rejects (PUSH_PROTECTION)
fail the scan even when the value is a reviewed fake: there is no allow list.
Split the literal after the prefix ("xoxb-" + "..."); the runtime value stays
the same.
"""
from __future__ import annotations

import argparse
import bisect
import glob as globmod
import hashlib
import json
import math
import os
import random
import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

PLACEHOLDER_USERS = {"me", "dev", "runner", "runneradmin", "Public", "Default", "All Users", "user", "USER",
                     "USERNAME", "name", "you", "alice", "bob", "example", "Jane", "jane", "jdoe"}
USER_PATH = re.compile(r"[A-Za-z]:(?:\\\\|\\|/)+Users(?:\\\\|\\|/)+(?!<)([^\\/\s\"'`<>%$]+)"
                       r"|(?<![\w.<])/(?:home|Users)/(?!<)([A-Za-z][\w.-]*)/"
                       r"|(?<![\w.<])/[a-z]/Users/(?!<)([A-Za-z][\w.-]*)/")
EMAIL = re.compile(r"(?<![\w.%+\\-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.([A-Za-z]{2,})\b")
# "\n@pytest.fixture", "0.10.0@setup.py": code, not addresses
NOT_TLD = {"py", "toml", "txt", "md", "json", "yaml", "yml", "cfg", "ini", "js", "ts", "route", "tool", "resource",
           "session", "fixture", "parametrize", "xfail", "qnode", "customobservable", "mark", "property", "setter"}
HOSTNAME = re.compile(r"\b(?:DESKTOP|LAPTOP)-[A-Z0-9]{6,}\b|\b[a-z0-9-]+\.[a-z0-9-]+\.ts\.net\b")
SESSION = re.compile(r"claude\.ai/(?:code/)?(?:session|chat|share)[/_][A-Za-z0-9_-]{8,}|\bsession_0[0-9A-Za-z]{20,}")
# built from parts so this file does not match its own pattern
AI_ATTR = re.compile("|".join([
    "Co-" + "Authored-By:", "Generated " + r"with \[?Claude", "Claude-" + "Session:", r"claude\.ai/code/" + "session",
    "noreply" + r"@anthropic\.com", "\U0001F916" + " Generated"]), re.I)
EXTRA_SECRETS = [
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("Slack webhook", re.compile(r"hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+")),
    ("Bearer token", re.compile(r"[Bb]earer\s+([A-Za-z0-9._~+/\-]{24,}=*)")),
    ("keyname=highentropy", re.compile(
        r"(?i)(?:api[_-]?key|token|secret|passw(?:or)?d|auth|hmac|access[_-]?key|private[_-]?key|client[_-]?secret)"
        r"[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9_\-+/=.]{20,})")),
    ("TypeSafe-like ts_ key", re.compile(r"\bts[_-](?:live|test|sk|key)?[_-]?[A-Za-z0-9]{24,}")),
    ("Stripe-like key", re.compile(r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}")),
]
# Formats GitHub push protection blocks in any pushed file, fake or real: they
# carry no checksum, so GitHub cannot tell a fake from a key. 2026-09-29 the
# first public push was rejected (GH013) for a reviewed fake Slack token.
# GitHub classic tokens (gh[pousr]_) are not listed: their CRC32 checksum lets
# fakes pass.
PUSH_PROTECTION = [
    ("Slack token", re.compile(r"xox[abposre]-[0-9A-Za-z-]{10,}")),
    ("Slack webhook", re.compile(r"hooks\.slack\.com/services/T[0-9A-Z]+/B[0-9A-Z]+/[0-9A-Za-z]+")),
    ("Stripe live key", re.compile(r"[rs]k_live_[0-9A-Za-z]{10,}")),
    ("Google API key", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("SendGrid key", re.compile(r"SG\.[\w-]{22}\.[\w-]{43}")),
    ("Anthropic key", re.compile(r"sk-ant-(?:api|admin)\d\d-[\w-]{20,}")),
    ("OpenAI key", re.compile(r"sk-(?:proj-|svcacct-)?[\w-]{20,}T3BlbkFJ[\w-]{20,}")),
    ("Hugging Face token", re.compile(r"hf_[A-Za-z]{34}")),
    ("PyPI token", re.compile(r"pypi-AgEIcHlwaS5vcmc[\w-]{50,}")),
    ("Shopify token", re.compile(r"shp(?:at|ca|pa|ss)_[0-9a-fA-F]{32}")),
    ("Databricks token", re.compile(r"dapi[0-9a-f]{32}")),
    ("private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s+[A-Za-z0-9+/=\s]{100,}")),
    ("Azure storage key", re.compile(r"AccountKey=[A-Za-z0-9+/]{86}==")),
]
FORBIDDEN = re.compile(r"(^|/)(\.env|\.env\..+|id_rsa|id_ed25519|.+\.pem|.+\.key|.+\.p12|.+\.pfx|CLAUDE\.md|AGENTS\.md|"
                       r"\.claude|\.gemini|\.agents|\.antigravity|\.codex|evals/private|private-eval|artifacts|"
                       r"docs/upstream)(/|$)")
BINARY_MAGIC = (b"MZ", b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xca\xfe\xba\xbe")
WORDS = ("fake", "test", "example", "notreal", "dummy", "xxxx", "abcd", "1234", "sample", "demo", "0000", "aaaa",
         "secret", "hunter", "passw", "s3cr", "local", "redact", "canary", "mock", "zzz", "exfil", "planted")


def sha16(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", "surrogatepass")).hexdigest()[:16]


def glob_rx(pattern: str) -> re.Pattern:
    """git-style glob: `dir/` = everything under dir, `**` any depth, `*` no slash."""
    if pattern.endswith("/"):
        pattern += "**"
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out, i = out + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            out, i = out + ".*", i + 2
        elif pattern[i] == "*":
            out, i = out + "[^/]*", i + 1
        elif pattern[i] == "?":
            out, i = out + "[^/]", i + 1
        else:
            out, i = out + re.escape(pattern[i]), i + 1
    return re.compile(out + r"\Z")


def matches(path: str, globs) -> bool:
    return any(glob_rx(g).match(path) for g in globs)


def allow_globs(entries) -> list:
    return [e["glob"] if isinstance(e, dict) else e for e in entries or []]


def git(repo, *args) -> bytes:
    return subprocess.run(["git", "-C", str(repo), *args], capture_output=True, check=True).stdout


def git_show(repo, commit, path):
    r = subprocess.run(["git", "-C", str(repo), "show", f"{commit}:{path}"], capture_output=True)
    return r.stdout.decode("utf-8") if r.returncode == 0 else None


def read_excludes(text):
    return [ln.strip() for ln in (text or "").splitlines() if ln.strip() and not ln.strip().startswith("#")]


def push_protection_hits(text):
    """(line, kind, length) of each PUSH_PROTECTION match; never the value."""
    hits = [(text.count("\n", 0, m.start()) + 1, kind, len(m.group(0)))
            for kind, rx in PUSH_PROTECTION for m in rx.finditer(text)]
    return sorted(hits)


def entropy(s):
    if not s:
        return 0.0
    counts = defaultdict(int)
    for ch in s:
        counts[ch] += 1
    return -sum(c / len(s) * math.log2(c / len(s)) for c in counts.values())


class Scan:
    def __init__(self, a):
        self.a = a
        self.snap = Path(a.snapshot).resolve()
        cfg_text = git_show(a.source_repo, a.source_commit, ".publish/scan.json")
        self.cfg = json.loads(cfg_text) if cfg_text else {}
        self.excludes = read_excludes(git_show(a.source_repo, a.source_commit, ".publish/exclude.txt"))
        self.excludes += list(a.exclude or [])
        self.files = {}      # rel path -> bytes
        for p in sorted(self.snap.rglob("*")):
            rel = p.relative_to(self.snap).as_posix()
            if rel == ".git" or rel.startswith(".git/") or not p.is_file():
                continue
            self.files[rel] = p.read_bytes()
        self.text = {rel: data.decode("utf-8", "replace") for rel, data in self.files.items()
                     if not data.startswith(BINARY_MAGIC)}
        self.rows = []       # (check, status, detail lines)
        self._hay = None

    # -- helpers
    def row(self, check, ok, summary, details=(), skip=False):
        status = "SKIP" if skip else ("PASS" if ok else "FAIL")
        self.rows.append({"check": check, "status": status, "summary": summary, "details": list(details)})

    def haystack(self):
        if self._hay is None:
            names = sorted(self.text)
            offsets, pos = [], 0
            for n in names:
                offsets.append(pos)
                pos += len(self.text[n]) + 1
            self._hay = (names, offsets, "\x00".join(self.text[n] for n in names))
        return self._hay

    def where(self, needle, limit=5):
        names, offsets, big = self.haystack()
        hits, start = [], 0
        while len(hits) < limit:
            j = big.find(needle, start)
            if j < 0:
                break
            k = bisect.bisect_right(offsets, j) - 1
            hits.append(names[k])
            start = offsets[k + 1] if k + 1 < len(offsets) else len(big)
        return hits

    # -- checks
    def check_git(self):
        d = []
        ok = True
        commits = git(self.snap, "rev-list", "--all").decode().split()
        if len(commits) != 1:
            ok = False
            d.append(f"commits: {len(commits)} (expected 1)")
        remotes = git(self.snap, "remote").decode().split()
        if remotes:
            ok = False
            d.append(f"remotes present: {remotes}")
        ident = git(self.snap, "log", "-1", "--format=%an <%ae>|%cn <%ce>").decode().strip()
        for who in ident.split("|"):
            if who != self.a.author:
                ok = False
                d.append(f"identity {who!r} != {self.a.author!r}")
        msg = git(self.snap, "log", "-1", "--format=%B").decode()
        if AI_ATTR.search(msg):
            ok = False
            d.append("AI attribution line in the commit message")
        branches = git(self.snap, "for-each-ref", "--format=%(refname)").decode().split()
        d.append(f"refs: {branches}; identity: {ident.split('|')[0]}")
        self.row("git: one commit, owner identity, no remote", ok, f"{len(commits)} commit(s), {len(remotes)} remote(s)", d)

    def check_tree(self):
        """Snapshot tree == source commit tree minus the exclude list (path, mode and blob id)."""
        src = {}
        for ent in git(self.a.source_repo, "ls-tree", "-r", "-z", self.a.source_commit).split(b"\0"):
            if ent:
                meta, path = ent.split(b"\t", 1)
                mode, _t, sha = meta.decode().split()
                src[path.decode()] = (mode, sha)
        want = {p: v for p, v in src.items() if not matches(p, self.excludes)}
        got = {}
        for ent in git(self.snap, "ls-tree", "-r", "-z", "HEAD").split(b"\0"):
            if ent:
                meta, path = ent.split(b"\t", 1)
                mode, _t, sha = meta.decode().split()
                got[path.decode()] = (mode, sha)
        missing = sorted(set(want) - set(got))
        extra = sorted(set(got) - set(want))
        diff = sorted(p for p in set(want) & set(got) if want[p] != got[p])
        excluded = sorted(set(src) - set(want))
        leaked = [p for p in got if matches(p, self.excludes)]
        d = [f"source {self.a.source_commit[:12]}: {len(src)} files; excluded {len(excluded)}; snapshot {len(got)}"]
        d += [f"excluded: {p}" for p in excluded[:40]]
        if len(excluded) > 40:
            d.append(f"... {len(excluded) - 40} more excluded")
        d += [f"missing: {p}" for p in missing[:20]] + [f"extra: {p}" for p in extra[:20]]
        d += [f"mode/content differs: {p} {want[p]} vs {got[p]}" for p in diff[:20]]
        d += [f"excluded path present: {p}" for p in leaked[:20]]
        ok = not (missing or extra or diff or leaked)
        self.row("tree = source commit minus exclude list", ok,
                 f"{len(got)} files, {len(excluded)} excluded, {len(missing)} missing, {len(extra)} extra, {len(diff)} changed", d)

    def check_forbidden(self):
        allow = allow_globs(self.cfg.get("forbidden_allow"))
        hits = [p for p in self.files if FORBIDDEN.search(p) and not matches(p, allow)]
        self.row("no key files, agent config, private or excluded folders", not hits, f"{len(hits)} forbidden path(s)", hits[:30])

    def check_real_keys(self):
        env_files = [f for f in self.a.env_file if f and os.path.isfile(f)]
        if not env_files:
            self.row("real keys from .env (hash-only)", True, "no .env file given or found", skip=True)
            return
        keys = {}
        for f in env_files:
            with open(f, encoding="utf-8") as h:
                for ln in h:
                    ln = ln.strip()
                    if ln and not ln.startswith("#") and "=" in ln:
                        k, v = ln.split("=", 1)
                        v = v.strip().strip("'\"")
                        if len(v) >= 8:
                            keys[f"{os.path.basename(os.path.dirname(f)) or '.'}/.env:{k.strip()}"] = v
        found = []
        msg = git(self.snap, "log", "--all", "--format=%B").decode("utf-8", "replace")
        blobs = list(self.files.items()) + [("<commit message>", msg.encode())]
        for name, v in keys.items():
            full, pre = v.encode(), v[:12].encode()
            where_full = [p for p, data in blobs if full in data]
            where_pre = [p for p, data in blobs if pre in data] if len(v) > 12 else []
            if where_full or where_pre:
                found.append(f"{name}: full value in {where_full[:5]}, first 12 chars in {where_pre[:5]}")
        del keys
        self.row("real keys from .env (hash-only)", not found,
                 f"{len(env_files)} .env file(s) checked in-process; values never printed; "
                 f"{'FOUND' if found else 'not found'}", found)

    def check_secrets(self):
        root = self.a.secretfinder_root
        sys.path.insert(0, root)
        try:
            from semgate import secretfinder as sf
        except Exception as e:  # noqa: BLE001
            self.row("secret-like values (all reviewed as fakes)", True, f"secretfinder not importable: {e}", skip=True)
            return
        finally:
            sys.path.pop(0)
        reviewed = {e["sha16"] for e in self.cfg.get("reviewed_secrets", [])}
        seen = {}
        for rel, text in self.text.items():
            vals = []
            for off in range(0, max(len(text), 1), sf.MAX_SCAN - 4096):
                for f in sf.find(text[off: off + sf.MAX_SCAN]):
                    vals.append((f.type, f.value))
                if off + sf.MAX_SCAN >= len(text):
                    break
            for kind, rx in EXTRA_SECRETS:
                for m in rx.finditer(text):
                    v = m.group(1) if m.groups() else m.group(0)
                    if kind in ("keyname=highentropy", "Bearer token") and entropy(v) < 3.8:
                        continue
                    vals.append(("extra: " + kind, v))
            for kind, v in vals:
                k = sha16(v)
                e = seen.setdefault(k, {"kind": kind, "prefix4": v[:4], "len": len(v),
                                        "words": [w for w in WORDS if w in v.lower()], "files": []})
                if rel not in e["files"] and len(e["files"]) < 3:
                    e["files"].append(rel)
        new = {k: e for k, e in seen.items() if k not in reviewed}
        d = [f"{k} {e['kind']} {e['prefix4']!r} len={e['len']} words={e['words']} in {e['files']}" for k, e in sorted(new.items())]
        self.row("secret-like values (all reviewed as fakes)", not new,
                 f"{len(seen)} distinct, {len(seen) - len(new)} reviewed, {len(new)} not reviewed", d)
        self.secret_inventory = seen

    def check_push_protection(self):
        """Token formats GitHub push protection rejects. No allow list: reviewed_secrets
        does not apply, because GitHub blocks a fake in these formats as well."""
        d = [f"{rel}:{line} {kind} len={n}" for rel, text in self.text.items()
             for line, kind, n in push_protection_hits(text)]
        self.row("provider token formats (GitHub push protection)", not d,
                 f"{len(d)} hit(s); split each literal after the prefix" if d else "0 hits", d[:40])

    def check_owner_paths(self):
        """The owner's user name in any user path fails, in every file. Other real-looking
        user names fail too, except in files allowed with a reason (third-party datasets)."""
        allow = allow_globs(self.cfg.get("owner_paths", {}).get("allow_files"))
        owners = {u.lower() for u in self.a.owner_user if u}
        mine, others = defaultdict(set), defaultdict(set)
        for rel, text in self.text.items():
            for m in USER_PATH.finditer(text):
                user = next(g for g in m.groups() if g)
                if user.lower() in owners:
                    mine[user].add(rel)
                elif not (user in PLACEHOLDER_USERS or len(user) <= 2 or user.startswith(("<", "{", "$", "%"))
                          or matches(rel, allow)):
                    others[user].add(rel)
        d = [f"OWNER user name in {len(fs)} file(s): {sorted(fs)[:10]}" for fs in mine.values()]
        d += [f"user {u!r} in {sorted(fs)[:6]}" for u, fs in sorted(others.items())]
        self.row("owner / user paths (C:\\Users\\<name>, /home/<name>)", not (mine or others),
                 f"owner name in {sum(len(v) for v in mine.values())} file(s); "
                 f"{len(others)} other name(s) outside allowed files", d)

    def check_personal(self):
        cfg = self.cfg.get("emails", {})
        allow_addr = {a.lower() for a in cfg.get("allow_addresses", [])} | {self.a.author.split("<")[-1].rstrip(">").lower()}
        allow_dom = [d.lower() for d in cfg.get("allow_domains", [])] + [
            "example.com", "example.org", "example.net", "example", "invalid", "test", "localhost", "local", "internal",
            "users.noreply.github.com", "noreply.github.com"]
        allow_files = allow_globs(cfg.get("allow_files"))
        bad = defaultdict(set)
        other = []
        for rel, text in self.text.items():
            if not matches(rel, allow_files):
                for m in EMAIL.finditer(text):
                    if m.group(1).lower() in NOT_TLD:
                        continue
                    e = m.group(0).lower()
                    dom = e.split("@", 1)[1]
                    if e in allow_addr or any(dom == x or dom.endswith("." + x) for x in allow_dom):
                        continue
                    bad[e].add(rel)
            for rx, label in ((HOSTNAME, "hostname"), (SESSION, "session link")):
                for m in rx.finditer(text):
                    other.append(f"{label} {m.group(0)[:60]!r} in {rel}")
        d = [f"email {e!r} in {sorted(fs)[:4]}" for e, fs in sorted(bad.items())] + other[:20]
        self.row("personal data (emails, hostnames, session links)", not (bad or other),
                 f"{len(bad)} email(s) not allowed, {len(other)} hostname/session hit(s)", d)

    def check_ai_attribution(self):
        allow = allow_globs(self.cfg.get("ai_attribution", {}).get("allow_files"))
        hits = []
        for rel, text in self.text.items():
            if matches(rel, allow):
                continue
            for n, line in enumerate(text.splitlines(), 1):
                if AI_ATTR.search(line):
                    hits.append(f"{rel}:{n}: {line.strip()[:120]}")
        self.row("AI attribution lines (files; commit message is in the git check)", not hits, f"{len(hits)} hit(s)", hits[:20])

    def check_vendor_markers(self):
        markers = self.cfg.get("vendor_markers", [])
        if not markers:
            self.row("vendor findings not reported upstream", True, "no markers configured", skip=True)
            return
        d, fail = [], False
        for mk in markers:
            rx = re.compile(mk["pattern"], re.I)
            paths = mk.get("paths") or ["**"]
            hits = []
            for rel, text in self.text.items():
                if not matches(rel, paths):
                    continue
                for n, line in enumerate(text.splitlines(), 1):
                    if rx.search(line):
                        hits.append(f"{rel}:{n}")
            if not hits:
                continue
            blocking = mk.get("status") not in ("reported", "accepted")
            fail |= blocking
            d.append(f"[{'BLOCKS' if blocking else mk.get('status')}] {mk['id']} ({mk.get('vendor', '?')}, "
                     f"{mk.get('status')}): {len(hits)} line(s): {', '.join(hits[:8])}{' ...' if len(hits) > 8 else ''}")
        self.row("vendor findings not reported upstream", not fail,
                 f"{sum(1 for x in d if x.startswith('[BLOCKS'))} marker(s) with unreported status found", d)

    def check_license(self):
        lic = self.cfg.get("license", {})
        spdx = lic.get("spdx")
        d, ok = [], True
        for req in lic.get("require", ["LICENSE"]):
            if req not in self.files:
                ok = False
                d.append(f"missing {req}")
        text = self.text.get("LICENSE", "")
        if spdx == "Apache-2.0" and not re.search(r"Apache License\s+Version 2\.0", text):
            ok = False
            d.append("LICENSE is not the Apache-2.0 text")
        if spdx is None:
            ok = False
            d.append("no license.spdx in .publish/scan.json")
        py = self.text.get("pyproject.toml")
        if py is not None and spdx:
            m = re.search(r'^license\s*=\s*"([^"]+)"', py, re.M)
            if not m or m.group(1) != spdx:
                ok = False
                d.append(f"pyproject license {m.group(1) if m else None!r} != {spdx!r}")
        pkg = self.text.get("package.json")
        if pkg is not None and spdx:
            try:
                if json.loads(pkg).get("license") != spdx:
                    ok = False
                    d.append("package.json license differs")
            except ValueError:
                pass
        d.append(f"license {spdx}; files: {[f for f in ('LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md') if f in self.files]}")
        self.row("license files", ok, f"{spdx or 'unknown'}", d)

    def check_agpl(self):
        data = self.a.agpl_data
        if not data or not os.path.isdir(data):
            self.row("AGPL corpora text (L1B3RT4S, AgentTrust)", True, "no local dataset folder", skip=True)
            return

        def good(s):
            s = s.strip()
            return len(s) >= 40 and len(set(re.findall(r"[A-Za-z]{3,}", s))) >= 5

        def strings(o, out):
            if isinstance(o, str):
                if good(o):
                    out.append(o.strip()[:200])
            elif isinstance(o, dict):
                for v in o.values():
                    strings(v, out)
            elif isinstance(o, list):
                for v in o:
                    strings(v, out)

        corpora = {"L1B3RT4S": [], "AgentTrust": []}
        for f in globmod.glob(os.path.join(data, "l1b3rt4s", "*")):
            if os.path.basename(f) not in ("LICENSE", "README.md") and os.path.isfile(f):
                for ln in open(f, encoding="utf-8", errors="replace"):
                    if good(ln):
                        corpora["L1B3RT4S"].append(ln.strip()[:200])
        for f in globmod.glob(os.path.join(data, "agenttrust*", "*.jsonl")):
            for ln in open(f, encoding="utf-8", errors="replace"):
                try:
                    d = json.loads(ln)
                except ValueError:
                    continue
                strings(d.get("envelope", d), corpora["AgentTrust"])
        reviewed = {e["sha16"] for e in self.cfg.get("agpl_reviewed", [])}
        rnd = random.Random(1)
        d, bad = [], 0
        for name, ss in corpora.items():
            ss = list(dict.fromkeys(ss))
            sample = ss if len(ss) <= self.a.agpl_sample else rnd.sample(ss, self.a.agpl_sample)
            found = [(s, self.where(s, 3)) for s in sample]
            found = [(s, w) for s, w in found if w]
            new = [(s, w) for s, w in found if sha16(s) not in reviewed]
            bad += len(new)
            d.append(f"{name}: {len(ss)} strings, checked {len(sample)}, found {len(found)}, not reviewed {len(new)}")
            d += [f"  {sha16(s)} len={len(s)} in {w}" for s, w in new[:15]]
        self.row("AGPL corpora text (L1B3RT4S, AgentTrust)", bad == 0, f"{bad} unreviewed match(es)", d)

    def check_heldout(self):
        pdir = self.a.private_dir
        if not pdir or not os.path.isdir(pdir):
            self.row("held-out cases (evals/private) not in snapshot", True, "no local evals/private folder", skip=True)
            return
        index = set()
        for data in self.files.values():
            for ln in data.split(b"\n"):
                ln = ln.strip()
                if len(ln) > 20:
                    index.add(hashlib.sha1(ln).digest())
        n_lines = n_line_hits = n_ids = n_id_hits = 0
        d = []
        for f in sorted(x for x in globmod.glob(os.path.join(pdir, "**", "*.jsonl"), recursive=True) if os.path.isfile(x)):
            file_line_hits = file_id_hits = 0
            for ln in open(f, "rb").read().split(b"\n"):
                ln = ln.strip()
                if not ln:
                    continue
                n_lines += 1
                if hashlib.sha1(ln).digest() in index:
                    file_line_hits += 1
                try:
                    cid = json.loads(ln).get("case_id")
                except ValueError:
                    cid = None
                if cid:
                    n_ids += 1
                    if self.where(json.dumps(cid), 1):
                        file_id_hits += 1
            n_line_hits += file_line_hits
            n_id_hits += file_id_hits
            if file_line_hits or file_id_hits:
                d.append(f"{os.path.basename(f)}: {file_line_hits} case line(s), {file_id_hits} case id(s) in snapshot")
        # whole private files by content
        blob_ids = {hashlib.sha1(b"blob %d\0" % len(v) + v).hexdigest() for v in self.files.values()}
        for f in sorted(x for x in globmod.glob(os.path.join(pdir, "**", "*"), recursive=True) if os.path.isfile(x)):
            data = open(f, "rb").read()
            if len(data) > 200 and hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest() in blob_ids:
                d.append(f"whole private file in snapshot: {os.path.basename(f)}")
        ok = not d
        self.row("held-out cases (evals/private) not in snapshot", ok,
                 f"{n_lines} private case lines: {n_line_hits} found; {n_ids} case ids: {n_id_hits} found", d)

    def check_large(self):
        cfg = self.cfg.get("large_files", {})
        mx = cfg.get("max_bytes", 10_000_000)
        allow = allow_globs(cfg.get("allow_files"))
        hits = [f"{p} {len(v)} bytes{' (executable binary)' if v.startswith(BINARY_MAGIC) else ''}"
                for p, v in self.files.items()
                if (len(v) > mx or v.startswith(BINARY_MAGIC)) and not matches(p, allow)]
        biggest = max(self.files.items(), key=lambda kv: len(kv[1]))[0] if self.files else "-"
        self.row("no large or executable binary files", not hits,
                 f"largest {biggest} ({len(self.files.get(biggest, b''))} bytes)", hits)

    def run(self):
        self.check_git()
        self.check_tree()
        self.check_forbidden()
        self.check_real_keys()
        self.check_secrets()
        self.check_push_protection()
        self.check_owner_paths()
        self.check_personal()
        self.check_ai_attribution()
        self.check_vendor_markers()
        self.check_license()
        self.check_agpl()
        self.check_heldout()
        self.check_large()
        return self.rows


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--source-repo", required=True)
    ap.add_argument("--source-commit", required=True)
    ap.add_argument("--author", required=True)
    ap.add_argument("--exclude", action="append", help="extra exclude glob (same syntax as .publish/exclude.txt)")
    ap.add_argument("--env-file", action="append", default=[])
    ap.add_argument("--private-dir")
    ap.add_argument("--agpl-data")
    ap.add_argument("--agpl-sample", type=int, default=5000)
    ap.add_argument("--owner-user", action="append",
                    default=[os.environ.get("USERNAME") or os.environ.get("USER") or ""],
                    help="user name that must not appear in any path (default: the current user)")
    ap.add_argument("--secretfinder-root", default=str(Path(__file__).resolve().parents[1]))
    ap.add_argument("--report", help="write the rows as JSON here (keep it outside the snapshot)")
    a = ap.parse_args(argv)
    rows = Scan(a).run()
    w = max(len(r["check"]) for r in rows)
    print(f"\n{'CHECK'.ljust(w)}  RESULT  SUMMARY")
    for r in rows:
        print(f"{r['check'].ljust(w)}  {r['status'].ljust(6)}  {r['summary']}")
    for r in rows:
        if r["details"] and (r["status"] == "FAIL" or a.report is None):
            print(f"\n[{r['status']}] {r['check']}")
            for line in r["details"][:60]:
                print("   ", line)
    if a.report:
        with open(a.report, "w", encoding="utf-8") as h:
            json.dump(rows, h, indent=1)
    failed = [r for r in rows if r["status"] == "FAIL"]
    print(f"\n{'FAIL' if failed else 'PASS'}: {len(rows) - len(failed)}/{len(rows)} checks passed or skipped")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
