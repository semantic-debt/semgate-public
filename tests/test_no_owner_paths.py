"""Shipped code, eval generators and committed manifests carry no path of one
user's machine (C:/Users/<name>/..., /home/<name>/..., /Users/<name>/...).
A placeholder such as C:/Users/<user> is fine."""
import importlib.util
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# drive + Users + a real name (not "<...>"), or /home/<name>/ and /Users/<name>/ outside a placeholder
USER_PATH = re.compile(r"[A-Za-z]:(?:\\|\|/)+Users(?:\\|\|/)+(?!<)[^\/\s\"'`<>]+"
                       r"|(?<![\w.<])/(?:home|Users)/(?!<)[A-Za-z][\w.-]*/")
ALLOWED_EXAMPLES = {"/home/runner/", "/home/dev/", "/home/me/"}   # CI and made-up example homes


def _files():
    yield from sorted((ROOT / "semgate").rglob("*.py"))
    yield from sorted((ROOT / "evals").glob("*.py"))
    yield from sorted((ROOT / "evals").glob("*-manifest.json"))


def test_no_user_specific_paths():
    hits = []
    for path in _files():
        text = path.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            for m in USER_PATH.finditer(line):
                if m.group(0) not in ALLOWED_EXAMPLES:
                    hits.append(f"{path.relative_to(ROOT).as_posix()}:{n}: {m.group(0)}")
    assert hits == []


def test_pattern_finds_owner_paths():
    for text in (r'MAIN = Path(r"C:\Users\alice\Desktop\semgate")', '"C:/Users/alice/Desktop/semgate"',
                 '"path": "C:\\Users\\alice\\Desktop"', "/home/alice/proj/x"):
        assert USER_PATH.search(text), text
    for text in ("C:/Users/<user>", r"C:\Users\<name>\x", "/home/<user>/.env"):
        assert not USER_PATH.search(text), text


def _heldout():
    sys.path.insert(0, str(ROOT / "evals"))
    try:
        import heldout
        return heldout
    finally:
        sys.path.pop(0)


def test_eval_data_root_env_wins(tmp_path, monkeypatch):
    heldout = _heldout()
    monkeypatch.setenv(heldout.DATA_ROOT_ENV, str(tmp_path))
    assert heldout.data_root() == tmp_path.resolve()


def test_eval_data_root_default_is_a_checkout_of_this_repo(monkeypatch):
    heldout = _heldout()
    monkeypatch.delenv(heldout.DATA_ROOT_ENV, raising=False)
    root = heldout.data_root()
    assert (root / "evals").is_dir() and (root / "semgate").is_dir()


def test_rel_to_gives_forward_slash_relative_paths(tmp_path):
    heldout = _heldout()
    assert heldout.rel_to(tmp_path / "evals" / "private" / "x.jsonl", tmp_path) == "evals/private/x.jsonl"


@pytest.mark.parametrize("script,var", [("17-gen-test-damage.py", "ROWS_DIR"), ("18-gen-slow-drift.py", "PRIVATE_PATH")])
def test_generators_take_a_data_root(tmp_path, monkeypatch, script, var):
    monkeypatch.setenv(_heldout().DATA_ROOT_ENV, str(tmp_path))
    name = "gen_" + script.split("-", 1)[0]
    spec = importlib.util.spec_from_file_location(name, ROOT / "evals" / script)
    mod = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, name, mod)
    sys.path.insert(0, str(ROOT / "evals"))
    try:
        spec.loader.exec_module(mod)
    finally:
        sys.path.pop(0)
    assert mod.MAIN == tmp_path.resolve()
    assert getattr(mod, var).is_relative_to(tmp_path.resolve())
    other = tmp_path / "other"
    mod._set_data_root(str(other))
    assert mod.MAIN == other.resolve()
    assert getattr(mod, var).is_relative_to(other.resolve())


# Committed logs, eval reports and tests that once carried the owner's paths
# (C:\Users\<name>\..., /home/<name>/...). Example users (me, dev, runner) are
# fine; a real name is not. The TLC logs say <repo> for the checkout folder,
# the reports <tmp> for the temp folder.
EXAMPLE_USERS = {"me", "dev", "runner"}
_USER_NAME = re.compile(r"Users[\\/]+([^\\/\s\"'`<>]+)|/(?:home|Users)/([A-Za-z][\w.-]*)/")


def _logs_reports_tests():
    yield from sorted((ROOT / "formal" / "results" / "tlc").iterdir())
    yield from sorted((ROOT / "evals" / "reports").glob("linkcode-s6-*.json"))
    yield ROOT / "tests" / "test_telemetry.py"
    yield ROOT / "tests" / "test_hard_rules.py"


def test_no_real_user_paths_in_logs_reports_and_these_tests():
    hits = []
    files = list(_logs_reports_tests())
    assert len(files) > 100                                   # the TLC logs are there
    for path in files:
        text = path.read_text(encoding="utf-8", errors="replace")
        for n, line in enumerate(text.splitlines(), 1):
            for m in USER_PATH.finditer(line):
                name = _USER_NAME.search(m.group(0))
                user = (name.group(1) or name.group(2)) if name else m.group(0)
                if user not in EXAMPLE_USERS:
                    hits.append(f"{path.relative_to(ROOT).as_posix()}:{n}: {m.group(0)[:80]}")
    assert hits == []


def test_example_users_pass_and_real_names_do_not():
    def real(text):
        out = []
        for m in USER_PATH.finditer(text):
            name = _USER_NAME.search(m.group(0))
            user = (name.group(1) or name.group(2)) if name else m.group(0)
            if user not in EXAMPLE_USERS:
                out.append(user)
        return out
    assert real(r"cat C:\Users\me\.ssh\config /home/me/.env C:/Users/me/notes.txt") == []
    assert real(r"Parsing file C:\Users\alice\Desktop\semgate\formal\x.tla") == ["alice"]
    assert real("/home/bob/proj/x") == ["bob"]
