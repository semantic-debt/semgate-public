"""Quote awareness, script extraction and the broader rule set.

Contract under test: extraction only ADDS matches (hard denies and gates see
code hidden in strings/heredocs/substitutions); quote awareness only REMOVES
gate matches caused by data (quoted text given to echo/grep/git commit -m,
comments, data heredocs), never hard denies, and never real arguments.
"""
import pytest

from semgate.envelope import Envelope, ProposedAction, SCHEMA_VERSION, UserGrant
from semgate.rules import check_hard_deny, detect_gates
from semgate.shellparse import extract_scripts, gate_view


def env(cmd):
    return Envelope(schema=SCHEMA_VERSION, grant=UserGrant(grant_id="g", principal="p", purpose="dev"),
                    action=ProposedAction("bash", {"command": cmd}))


def gates(cmd):
    return {h.gate_class for h in detect_gates(env(cmd))}


def denied(cmd):
    return check_hard_deny(env(cmd)).outcome == "deny"


# --- quote awareness: data no longer triggers gates ---------------------------
@pytest.mark.parametrize("cmd", [
    'grep -rn "rm -rf" docs',
    "git commit -m 'remove the rm -rf usage from setup.sh'",
    'echo "do not run sudo here"',
    "rg 'DROP TABLE' migrations/",
    "ls -la   # rm -rf build later",
    "git log --grep 'git reset --hard'",
    "cat > notes.md <<EOF\nnever run git push --force\nEOF",
    'gh pr create --title "Fix: kubectl delete ns in docs" --body "details"',
])
def test_data_mentions_do_not_gate(cmd):
    assert gates(cmd) == set(), (cmd, gates(cmd))


# --- quote awareness never hides real commands or real targets ----------------
@pytest.mark.parametrize("cmd,cls", [
    ('rm -rf "$BUILD_DIR"', "destructive_irreversible"),
    ('echo "$(rm -rf src)"', "destructive_irreversible"),
    ("grep x file && rm -rf src", "destructive_irreversible"),
    ("echo key > ~/.ssh/authorized_keys", "credentials_secrets"),
    ('grep "password" .env', "credentials_secrets"),
    ("sudo echo 'x' > /etc/hosts", "privilege_escalation"),
])
def test_real_commands_still_gate(cmd, cls):
    assert cls in gates(cmd), (cmd, gates(cmd))


# --- script extraction: code inside strings is checked ------------------------
@pytest.mark.parametrize("cmd", [
    "bash -c 'rm -rf /'",
    "sh -c 'rm -rf ~'",
    "python -c \"import os; os.system('rm -rf /')\"",
    "ssh deploy@host 'rm -rf /'",
    "bash <<'EOF'\nrm -rf ~\nEOF",
    'cmd /c "rd /s /q C:\\"',
    "kubectl exec pod -- sh -c 'rm -rf /'",
    'eval "rm -rf /"',
])
def test_hidden_catastrophic_commands_are_hard_denied(cmd):
    assert denied(cmd), (cmd, extract_scripts(cmd))


@pytest.mark.parametrize("cmd,cls", [
    ('sh -c "git reset --hard"', "destructive_irreversible"),
    ("psql <<SQL\nDROP TABLE users;\nSQL", "destructive_irreversible"),
    ("docker exec web rm -rf /var/www", "destructive_irreversible"),
    ("xargs -I{} sh -c 'cat {}/.env' < dirs", "credentials_secrets"),
    ("python -c \"import os; os.system('git push --force')\"", "destructive_irreversible"),
])
def test_hidden_commands_reach_the_gates(cmd, cls):
    assert cls in gates(cmd), (cmd, gates(cmd))


def test_extraction_depth_and_size_are_bounded():
    nested = "bash -c " + "'bash -c " * 10 + "rm -rf /" + "'" * 11
    extract_scripts(nested)        # must not hang or raise
    assert extract_scripts("x" * 300_000) == []
    assert gate_view("echo 'unterminated") in ("echo '_'", "echo 'unterminated")


# --- broader rules --------------------------------------------------------------
@pytest.mark.parametrize("cmd,cls", [
    (r"Remove-Item -Recurse -Force .\dist", "destructive_irreversible"),
    (r"del /s /q build", "destructive_irreversible"),
    ("git branch -D feature/x", "destructive_irreversible"),
    ("git stash clear", "destructive_irreversible"),
    ("git reflog expire --expire=now --all", "destructive_irreversible"),
    ("git filter-repo --path secrets.txt --invert-paths", "destructive_irreversible"),
    ("git push origin --delete release", "destructive_irreversible"),
    ("dropdb app_prod", "destructive_irreversible"),
    ("redis-cli FLUSHALL", "destructive_irreversible"),
    ("terraform destroy", "destructive_irreversible"),
    ("terraform apply -auto-approve", "destructive_irreversible"),
    ("kubectl delete ns staging", "destructive_irreversible"),
    ("helm uninstall api", "destructive_irreversible"),
    ("docker volume prune -f", "destructive_irreversible"),
    ("aws s3 rm s3://bucket/data --recursive", "destructive_irreversible"),
    ("aws ec2 terminate-instances --instance-ids i-123", "destructive_irreversible"),
    ("gcloud sql instances delete prod", "destructive_irreversible"),
    ("robocopy src dst /MIR", "destructive_irreversible"),
    ("vault kv get secret/app", "credentials_secrets"),
    ("gh auth token", "credentials_secrets"),
    ("aws secretsmanager get-secret-value --secret-id prod/db", "credentials_secrets"),
    ("kubectl get secret db -o yaml", "credentials_secrets"),
    ("echo '{}' > ~/.claude/settings.json", "agent_config"),
    ("sed -i 's/ask/allow/' ~/.codex/config.toml", "agent_config"),
])
def test_new_rules(cmd, cls):
    assert cls in gates(cmd), (cmd, gates(cmd))


@pytest.mark.parametrize("cmd", ["vssadmin delete shadows /all /quiet", "wmic shadowcopy delete", "bcdedit /set {default} recoveryenabled No"])
def test_backup_destruction_is_hard_denied(cmd):
    assert denied(cmd)


@pytest.mark.parametrize("cmd", [
    "git branch -d merged-feature", "git stash list", "git push origin main --dry-run".replace(" --dry-run", "") and "git fetch --prune",
    "kubectl get pods -n api", "terraform plan", "helm list", "docker ps", "docker system df", "aws s3 ls", "gcloud config list",
    "az account show", "vault status", "gh auth status", "op --version", "cat ~/.claude/settings.json",
    "git reflog", "redis-cli PING", "robocopy src dst /E",
])
def test_look_alike_benign_commands_are_not_gated_by_the_new_rules(cmd):
    new = {"destructive_irreversible", "credentials_secrets", "agent_config"}
    assert not (gates(cmd) & new), (cmd, gates(cmd))
    assert not denied(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "zpool create tank /dev/nbd0", "qemu-nbd --connect=/dev/nbd0 disk.qcow2", "modprobe nbd", "zfs destroy -r tank",
    "losetup /dev/loop0 disk.img", "mount /dev/nbd0p1 /mnt", "nbd-client localhost 10809 /dev/nbd0",
    "systemctl stop postgresql", "sysctl -w vm.overcommit_memory=1", "chroot /mnt /bin/bash",
])
def test_kernel_block_device_and_mount_changes_are_gated(cmd):
    # The reported incident: an agent built a ZFS pool on /dev/nbd. Without sudo
    # (agent already root) no privilege gate fires, so these need their own.
    assert "system_admin" in gates(cmd), (cmd, gates(cmd))


@pytest.mark.parametrize("cmd", ["mount", "mount | grep nbd", "zpool status", "zpool list", "zfs list", "systemctl status nginx", "lsmod", "df -h"])
def test_inspecting_storage_and_services_is_not_system_admin(cmd):
    assert "system_admin" not in gates(cmd), (cmd, gates(cmd))


@pytest.mark.parametrize("cmd", ["swapon --show", "swapon -s", "losetup -l", "losetup --list"])
def test_listing_swap_and_loop_devices_is_not_gated(cmd):
    assert "system_admin" not in gates(cmd), (cmd, gates(cmd))
