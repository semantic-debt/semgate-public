"""grant.json names the host `semgate init <host>` wrote it for. Before, every
host got "agy-<date>" and "written by `semgate init antigravity`". Grants
written before still load (nothing reads grant_id or provenance to decide)."""
import json

import pytest

from semgate.adapters.antigravity import grant_from_config
from semgate.cli import main
from semgate.init_antigravity import _grant

HOOK_FILE = {"antigravity": "hooks.json", "claude": "settings.json", "codex": "hooks.json", "copilot": "semgate.json",
             "droid": "hooks.json", "opencode": "semgate.js", "pi": "semgate.ts"}
PREFIX = {"antigravity": "agy", "claude": "claude", "codex": "codex", "copilot": "copilot", "droid": "droid",
          "opencode": "opencode", "pi": "pi"}


@pytest.mark.parametrize("host", sorted(HOOK_FILE))
def test_grant_names_the_real_host(tmp_path, host, monkeypatch):
    monkeypatch.setenv("PI_CODING_AGENT_DIR", str(tmp_path / "pi-agent"))
    monkeypatch.setenv("CODEX_HOME", str(tmp_path / "codex"))
    argv = ["init", host, "--purpose", "Dev work", "--provider", "none", "--no-skill",
            "--dir", str(tmp_path / "sg"), "--hooks-file", str(tmp_path / "host" / HOOK_FILE[host])]
    assert main(argv) == 0
    grant = json.loads((tmp_path / "sg" / "grant.json").read_text(encoding="utf-8"))
    prefix, date = grant["grant_id"].split("-", 1)
    assert prefix == PREFIX[host] and len(date) == 8 and date.isdigit()
    assert grant["provenance"] == f"written by `semgate init {host}`; edit by hand, never from the agent"


def test_default_host_is_antigravity_for_other_callers():
    g = _grant("p", 1, "")
    assert g["grant_id"].startswith("agy-") and "`semgate init antigravity`" in g["provenance"]


def test_an_old_grant_with_the_antigravity_text_still_loads():
    old = {"grant_id": "agy-20260920", "principal": "me", "purpose": "Dev work",
           "issued_at": "2026-09-20T00:00:00Z", "expires_at": "2099-01-01T00:00:00Z",
           "allowed_domains": [], "forbidden_patterns": [],
           "provenance": "written by `semgate init antigravity`; edit by hand, never from the agent"}
    g = grant_from_config(old)
    assert g.grant_id == "agy-20260920" and g.provenance.startswith("written by `semgate init antigravity`")
