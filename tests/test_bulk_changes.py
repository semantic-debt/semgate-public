"""Bulk permission changes and bulk in-place edits reach a human (destructive_irreversible).
A single named file (normal dev work) is not bulk and is not gated by these patterns."""
import pytest

from semgate.envelope import SCHEMA_VERSION, Envelope, Environment, ProposedAction, UserGrant
from semgate import rules

GRANT = UserGrant(grant_id="g", principal="p", purpose="Software development in this project", expires_at="2099-01-01T00:00:00Z")


def env(command):
    return Envelope(schema=SCHEMA_VERSION, action=ProposedAction("bash", {"command": command}), grant=GRANT,
                    environment=Environment(project_root="/w/p", cwd="/w/p"))


def classes(command):
    return {h.gate_class for h in rules.detect_gates(env(command))}


@pytest.mark.parametrize("command", [
    # the three NL2SH cases that were auto-allowed
    'find /testbed -name "*.php" -exec chmod 755 {} \\; -exec /bin/echo {} \\; | wc -l',   # nl2sh:112 / nl2sh:127
    'grep -rl "Hello" /testbed | xargs sed -i \'s/Hello/Hi/g\'',                           # nl2sh:298
    "chmod -R 755 /testbed",
    "chmod -R u+w src",
    "chmod --recursive 644 docs",
    "chgrp -R staff /srv/app",
    "chmod 755 *.php",
    "chmod 644 src/*.py",
    "find . -type f -exec chmod 644 {} +",
    "find . -name '*.sh' -execdir chmod +x {} \\;",
    "ls *.sh | xargs chmod +x",
    "find . -name '*.py' | xargs sed -i 's/foo/bar/'",
    "find . -name '*.py' -exec sed -i 's/foo/bar/' {} +",
    "sed -i 's/foo/bar/' src/*.py",
    "cd /w/p && chmod -R 777 .",
])
def test_bulk_changes_reach_a_human(command):
    assert "destructive_irreversible" in classes(command), command


@pytest.mark.parametrize("command", [
    "chmod +x build.sh",
    "chmod 644 README.md",
    "chmod u+x scripts/run_tests.sh",
    "sed -i 's/foo/bar/' src/app.py",
    "sed -i 's/a*b/x/' src/app.py",          # '*' inside the quoted sed script is not a glob
    "sed -n '1,20p' setup.py",
    "grep -rn 'chmod' src",
    "echo 'chmod -R 755 /' > notes.txt",     # quoted text is not a command
    "ls -la *.py",
    "python -m pytest tests/ -q",
])
def test_normal_dev_commands_are_not_bulk(command):
    assert "destructive_irreversible" not in classes(command), command


def test_bulk_sed_is_relaxable_but_bulk_chmod_is_not():
    # sed -i over files git tracks can be restored by git (relaxed only after
    # gitstate verifies every target); lost permission bits cannot.
    assert rules.recoverable_destructive_only(env("sed -i 's/foo/bar/' src/*.py"))
    assert not rules.recoverable_destructive_only(env("chmod -R 755 src"))
    assert not rules.recoverable_destructive_only(env("find . -type f -exec chmod 644 {} +"))
