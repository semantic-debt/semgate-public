"""Grant path-scoping over command text, including Windows/UNC paths.

extract_paths previously recognized only POSIX-style tokens, so on Windows a
command reading C:\\... or \\\\server\\... slipped past allowed_path_prefixes.
These use forward slashes for in-scope assertions so they pass on both Windows
(normpath -> backslashes) and Linux CI (normpath keeps them); out-of-scope
assertions hold on either OS because a non-matching path is always a violation.
"""
import os
import pytest
from semgate.rules import extract_paths, check_grant_scope
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant

ROOT = "C:/proj"


def _env(command, prefixes=(ROOT,)):
    return Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction("bash", {"command": command}),
        grant=UserGrant(grant_id="g", principal="p", purpose="x",
                        expires_at="2099-01-01T00:00:00Z",
                        allowed_path_prefixes=tuple(prefixes)),
        environment=Environment(project_root=ROOT, cwd=ROOT, harness="t", session_id="s"),
    )


def _violations(command, prefixes=(ROOT,)):
    return check_grant_scope(_env(command, prefixes))


def test_windows_backslash_path_outside_scope_is_flagged():
    assert _violations(r"Get-Content C:\Windows\System32\drivers\etc\hosts")


def test_windows_forward_slash_outside_scope_is_flagged():
    assert _violations("Get-Content C:/Users/x/secret.txt")


def test_windows_forward_slash_inside_scope_is_ok():
    assert _violations("Get-Content C:/proj/readme.md") == []


def test_quoted_windows_path_is_detected():
    assert _violations('type "C:/Users/x/.env"')


def test_unc_path_is_flagged():
    assert _violations(r"dir \\server\share\secret")


def test_posix_path_outside_scope_still_flagged():   # regression
    assert _violations("cat /etc/passwd")


def test_posix_path_inside_scope_ok():
    assert _violations("cat /proj/readme.md", prefixes=("/proj",)) == []


def test_extract_paths_finds_windows_drive_and_unc():
    paths = extract_paths(_env(r"Get-Content C:\a\b ; dir \\srv\share"))
    assert any(p.endswith(("a\\b", "a/b")) for p in paths)
    assert any("srv" in p for p in paths)


def test_symlink_cannot_smuggle_path_past_scope(tmp_path):
    # A symlink inside the workspace that points outside must NOT count as in-scope:
    # canonicalization resolves it to the real (outside) target. Without realpath
    # (plain normpath), ws/link/secret.txt startswith ws/ and would pass — the gap.
    workspace = tmp_path / "ws"; workspace.mkdir()
    outside = tmp_path / "outside"; outside.mkdir()
    (outside / "secret.txt").write_text("x", encoding="utf-8")
    link = workspace / "link"
    try:
        os.symlink(str(outside), str(link), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation not permitted on this platform")
    target = link / "secret.txt"
    assert check_grant_scope(_env(f'cat "{target}"', prefixes=(str(workspace),)))  # flagged out of scope
    # a real file genuinely inside the workspace stays in scope
    (workspace / "ok.txt").write_text("x", encoding="utf-8")
    assert check_grant_scope(_env(f'cat "{workspace / "ok.txt"}"', prefixes=(str(workspace),))) == []
