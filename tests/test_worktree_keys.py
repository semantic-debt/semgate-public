"""Key lookup from a git worktree (semgate/providers/keys.py): a worktree
has no .env of its own, so the main checkout's .env is read after the
checkout's own .env. Fake git layout and fake key values only; no real .env
is read and no git runs."""
from pathlib import Path

from semgate.init_antigravity import _check_interpreter
from semgate.providers import keys

NAME = "OPENROUTER_API_KEY"


def make_worktree(root: Path, relative_gitdir: bool = False) -> dict:
    """<root>/main/.git/worktrees/wt (gitdir) and <root>/main/.claude/worktrees/wt (checkout)."""
    main = root / "main"
    gitdir = main / ".git" / "worktrees" / "wt"
    gitdir.mkdir(parents=True)
    (gitdir / "commondir").write_text("../..\n", encoding="utf-8")
    wt = main / ".claude" / "worktrees" / "wt"
    wt.mkdir(parents=True)
    target = "../../../.git/worktrees/wt" if relative_gitdir else gitdir.as_posix()
    (wt / ".git").write_text(f"gitdir: {target}\n", encoding="utf-8")
    return {"main": main, "wt": wt}


def test_main_checkout_env_of_a_worktree(tmp_path):
    t = make_worktree(tmp_path)
    assert keys.main_checkout_env(t["wt"]) == (t["main"] / ".env").resolve()


def test_relative_gitdir(tmp_path):
    t = make_worktree(tmp_path, relative_gitdir=True)
    assert keys.main_checkout_env(t["wt"]) == (t["main"] / ".env").resolve()


def test_not_a_worktree(tmp_path):
    normal = tmp_path / "normal"
    (normal / ".git").mkdir(parents=True)              # a normal checkout: .git is a folder
    assert keys.main_checkout_env(normal) is None
    assert keys.main_checkout_env(tmp_path / "nothing") is None
    sub = tmp_path / "sub"                             # a submodule: gitdir without commondir
    (tmp_path / "modgit").mkdir()
    sub.mkdir()
    (sub / ".git").write_text(f"gitdir: {(tmp_path / 'modgit').as_posix()}\n", encoding="utf-8")
    assert keys.main_checkout_env(sub) is None


def test_worktree_finds_the_key_in_the_main_checkout(tmp_path, monkeypatch):
    t = make_worktree(tmp_path)
    (t["main"] / ".env").write_text(f"{NAME}=fake-main-value\n", encoding="utf-8")
    monkeypatch.setattr(keys, "CHECKOUT_ENV", t["wt"] / ".env")
    home = tmp_path / "home"
    assert [label for label, _ in keys.env_files(home)] == [keys.HOME_LABEL, keys.CHECKOUT_LABEL, keys.MAIN_CHECKOUT_LABEL]
    assert keys.find_key(NAME, environ={}, home=home) == ("fake-main-value", keys.MAIN_CHECKOUT_LABEL)
    assert keys.key_status("openrouter", environ={}, home=home) == {"found": True, "location": keys.MAIN_CHECKOUT_LABEL}


def test_the_worktree_env_comes_first(tmp_path, monkeypatch):
    t = make_worktree(tmp_path)
    (t["main"] / ".env").write_text(f"{NAME}=fake-main-value\n", encoding="utf-8")
    (t["wt"] / ".env").write_text(f"{NAME}=fake-worktree-value\n", encoding="utf-8")
    monkeypatch.setattr(keys, "CHECKOUT_ENV", t["wt"] / ".env")
    assert keys.find_key(NAME, environ={}, home=tmp_path / "home") == ("fake-worktree-value", keys.CHECKOUT_LABEL)


def test_home_env_comes_before_both(tmp_path, monkeypatch):
    t = make_worktree(tmp_path)
    (t["main"] / ".env").write_text(f"{NAME}=fake-main-value\n", encoding="utf-8")
    home = tmp_path / "home"
    (home / ".semgate").mkdir(parents=True)
    (home / ".semgate" / ".env").write_text(f"{NAME}=fake-home-value\n", encoding="utf-8")
    monkeypatch.setattr(keys, "CHECKOUT_ENV", t["wt"] / ".env")
    assert keys.find_key(NAME, environ={}, home=home)[0] == "fake-home-value"


def test_skip_drops_the_real_checkout_and_its_main_checkout(monkeypatch):
    # conftest sets SEMGATE_SKIP_CHECKOUT_ENV=1; CHECKOUT_ENV is the real default.
    assert keys.CHECKOUT_ENV == keys._DEFAULT_CHECKOUT_ENV
    labels = [label for label, _ in keys.env_files()]
    assert labels == [keys.HOME_LABEL]
    # doctor passes the real checkout path explicitly: the skip applies there too.
    assert [label for label, _ in keys.env_files(checkout=keys._DEFAULT_CHECKOUT_ENV)] == [keys.HOME_LABEL]


def test_init_reports_no_missing_key_from_a_worktree(tmp_path, monkeypatch):
    t = make_worktree(tmp_path)
    monkeypatch.setattr(keys, "CHECKOUT_ENV", t["wt"] / ".env")
    assert any(p.startswith(f"{NAME} not found") for p in _check_interpreter("openrouter"))
    (t["main"] / ".env").write_text(f"{NAME}=fake-main-value\n", encoding="utf-8")
    assert _check_interpreter("openrouter") == []
