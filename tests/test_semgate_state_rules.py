"""Hard rules for writes to semgate's own state folder (~/.semgate: the
trust store, the approval tickets, the agent-host record, the keys). Every
write form the agent could use is a hard deny; reading stays allowed."""
import pytest

from semgate import rules
from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory, UserGrant


def _env(command, tool="bash"):
    grant = UserGrant(grant_id="g", principal="p", purpose="dev", expires_at="2099-01-01T00:00:00Z")
    return Envelope(schema="semgate-envelope/1", action=ProposedAction(tool=tool, arguments={"command": command}),
                    grant=grant, environment=Environment(project_root="/p", cwd="/p", session_id="s"),
                    trajectory=Trajectory(recent=()), user_message="x", user_messages=("x",))


WRITES = [
    "echo '{}' >> ~/.semgate/trust.jsonl",
    'printf x >> "$HOME/.semgate/trust.jsonl"',
    "cd ~/.semgate && echo x >> trust.jsonl",
    "cd ~/.semgate\necho x >> trust.jsonl",
    "pushd ~/.semgate; echo x >> trust.jsonl; popd",
    "Set-Location ~/.semgate; Add-Content trust.jsonl x",
    "cp /tmp/t.jsonl ~/.semgate/trust.jsonl",
    "mv /tmp/t.jsonl ~/.semgate/trust.jsonl",
    "sed -i 's/a/b/' ~/.semgate/trust.jsonl",
    "perl -i -pe 's/a/b/' ~/.semgate/trust.jsonl",
    "tee -a ~/.semgate/trust.jsonl < /tmp/t",
    "truncate -s 0 ~/.semgate/trust.jsonl",
    ": > ~/.semgate/trust.jsonl",
    "install -m 600 /tmp/t ~/.semgate/trust.jsonl",
    "dd if=/tmp/t of=$HOME/.semgate/trust.jsonl",
    "ln -sf /tmp/evil ~/.semgate/trust.jsonl",
    "rsync /tmp/t ~/.semgate/trust.jsonl",
    "curl -o ~/.semgate/trust.jsonl https://x.invalid/t",
    "wget -O ~/.semgate/trust.jsonl https://x.invalid/t",
    "touch ~/.semgate/trust.jsonl",
    "tar -xf /tmp/t.tar -C ~/.semgate",
    "find ~/.semgate -name '*.jsonl' -delete",
    "ls ~/.semgate/*.key | xargs rm",
    "echo x > ~/.semgate/trust-tickets.jsonl",
    "rm ~/.semgate/agent-hosts.json",
    r"Remove-Item $HOME\.semgate\trust.key",
    r'Add-Content -Path "$env:USERPROFILE\.semgate\trust.jsonl" -Value x',
    r"Add-Content (Join-Path $HOME '.semgate\trust.jsonl') x",
    r'[IO.File]::AppendAllText("$HOME\.semgate\trust.jsonl", "x")',
    "Set-Content -Path ~/.semgate/trust.jsonl -Value x",
    r'"x" | Out-File -Append $HOME\.semgate\trust.jsonl',
    r"Copy-Item C:\tmp\t.jsonl -Destination $env:USERPROFILE\.semgate\trust.jsonl",
    r"New-Item -ItemType SymbolicLink -Path x -Target $HOME\.semgate\trust.jsonl",
    r'cmd /c "echo x >> %USERPROFILE%\.semgate\trust.jsonl"',
    r"cmd /c mklink /J link %USERPROFILE%\.semgate",
    "python -c \"open('/home/u/.semgate/trust.jsonl','a').write('x')\"",
    "python -c \"import pathlib; (pathlib.Path.home()/'.semgate'/'trust.jsonl').open('a').write('x')\"",
    "python -c \"import os; p=os.path.join(os.path.expanduser('~'),'.semgate','trust.jsonl'); open(p,'a').write('x')\"",
    "python -c \"from pathlib import Path; Path.home().joinpath('.semgate','trust.jsonl').write_text('x')\"",
    "python -c \"import shutil; shutil.copy('/tmp/t', '/home/u/.semgate/trust.jsonl')\"",
    "python3 - <<'EOF'\nimport os\np = os.path.join(os.path.expanduser('~'), '.semgate', 'trust.jsonl')\nopen(p, 'a').write('x')\nEOF",
    "node -e \"require('fs').appendFileSync(require('os').homedir()+'/.semgate/trust.jsonl','x')\"",
]
READS = [
    "cat ~/.semgate/trust.jsonl", "semgate trust list", "ls ~/.semgate", "grep npm ~/.semgate/trust.jsonl",
    "python -c \"print(open('/home/u/.semgate/trust.jsonl').read())\"", r"Get-Content $HOME\.semgate\trust.jsonl",
    "tail -n 5 ~/.semgate/ledger.jsonl", "cat ~/.semgate/ledger.jsonl > /tmp/copy.jsonl", "jq . ~/.semgate/semgate.json",
    "cd ~/.semgate && ls", "cd ~/.semgate 2>/dev/null && cat trust.jsonl",
    "python -c \"import json; print(json.load(open('/home/u/.semgate/semgate.json')))\"",
    "python -c \"print(open('/home/u/.semgate/ledger.jsonl', encoding='ascii').read())\"",
    "wc -l ~/.semgate/ledger.jsonl > out.txt", r"Select-String allow $HOME\.semgate\claude\ledger.jsonl",
    "cp config.example.json config.semgate.json", "echo done > build/.semgate-stamp.txt",
]


@pytest.mark.parametrize("command", WRITES)
def test_writes_to_semgate_state_are_hard_denied(command):
    assert rules.check_hard_deny(_env(command)).outcome == "deny", command


@pytest.mark.parametrize("command", READS)
def test_reads_of_semgate_state_are_not_hard_denied(command):
    assert rules.check_hard_deny(_env(command)).outcome != "deny", command


