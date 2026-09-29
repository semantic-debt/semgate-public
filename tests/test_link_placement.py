"""Link placement (semgate/linkplace.py) and the persistence_link human gate.
No link is ever created by these tests, except one symlink inside pytest's
tmp_path to test ln -n (skipped when this machine does not allow it)."""
import os
from pathlib import Path

import pytest

from conftest import make_grant
from semgate import linkplace, rules
from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory
from semgate.judge import judge
from semgate.policy import Policy
from semgate.scriptsource import LocalWorkspace, ScriptFile, SyntheticWorkspace

ROOT = Path(__file__).resolve().parents[1]
P = "/workspace/project"


def links(command, cwd=P, is_dir=None):
    return linkplace.find_links(command, cwd, is_dir)


def only(command, cwd=P, is_dir=None):
    found = links(command, cwd, is_dir)
    assert len(found) == 1, found
    return found[0]


def gate(command, cwd=P):
    return linkplace.persistence_hits(command, cwd)


def env(command, cwd=P, user="", tool="bash"):
    return Envelope(
        schema="semgate-envelope/1",
        action=ProposedAction(tool=tool, arguments={"command": command}),
        grant=make_grant(allowed_path_prefixes=(), purpose="Software development work inside this project repository."),
        environment=Environment(project_root=P, cwd=cwd, harness="test", session_id="ses-test"),
        trajectory=Trajectory(recent=()),
        user_message=user,
        evaluated_at="2026-09-18T08:00:00Z",
    )


# ---------- placement: GNU ln ----------


def test_reversed_operands_with_root_last_create_the_link_in_root():
    # nl2sh:253 and nl2sh:150: an option after the paths (GNU reads it anyway)
    lc = only("ln /workspace/dir1 -s /")
    assert (lc.form, lc.kind, lc.why, lc.folder) == ("inside", "symbolic", "root", "/")
    assert [(x.path, x.target_raw, x.target) for x in lc.links] == [("/dir1", "/workspace/dir1", "/workspace/dir1")]
    lc = only("ln /testbed/dir3/subdir1/subsubdir1/FooBar -s /")
    assert [x.path for x in lc.links] == ["/FooBar"]


def test_two_paths_last_not_known_to_be_a_folder_is_the_link_name():
    lc = only("ln -s AGENTS.md CLAUDE.md")
    assert lc.form == "named"
    assert [(x.path, x.target) for x in lc.links] == [(P + "/CLAUDE.md", P + "/AGENTS.md")]
    assert lc.maybe == (P + "/CLAUDE.md/AGENTS.md",)      # if CLAUDE.md were a folder


def test_relative_symlink_target_resolves_against_the_link_folder():
    lc = only("ln -s ../shared/config.json ./config.json", cwd=P + "/app")
    assert [(x.path, x.target) for x in lc.links] == [(P + "/app/config.json", P + "/shared/config.json")]
    # hard links and ln -r resolve against the current folder
    lc = only("ln ../x sub/y", cwd=P + "/app")
    assert lc.kind == "hard" and lc.links[0].target == P + "/x"
    lc = only("ln -sr ../x sub/y", cwd=P + "/app")
    assert lc.links[0].target == P + "/x"


@pytest.mark.parametrize("command,why", [
    ("ln -s /opt/x .", "current"), ("ln -s /opt/x ..", "parent"), ("ln -s /opt/x ~", "home"),
    ("ln -s /opt/x lib/", "slash"), ("ln -s /opt/x /", "root"), ("ln -s /opt/x ~/", "home"),
])
def test_last_path_known_to_be_a_folder_without_the_disk(command, why):
    lc = only(command)
    assert lc.form == "inside" and lc.why == why and lc.links[0].path.endswith("/x")


def test_existing_folder_from_the_workspace():
    ws = SyntheticWorkspace({}, dirs=[P + "/lib"])
    lc = only("ln -s ../x.py lib", is_dir=ws.is_dir)
    assert (lc.form, lc.why, lc.links[0].path) == ("inside", "disk", P + "/lib/x.py")
    lc = only("ln -s ../x.py libs", is_dir=ws.is_dir)          # not in the workspace: the literal name
    assert (lc.form, lc.links[0].path) == ("named", P + "/libs")
    # folders above a workspace file exist too
    ws = SyntheticWorkspace({P + "/src/pkg/mod.py": "x = 1\n"})
    assert ws.is_dir(P + "/src/pkg") and ws.is_dir(P + "/src") and not ws.is_dir(P + "/src/pkg/mod.py")


def test_no_target_directory_option_always_names_the_link():
    ws = SyntheticWorkspace({}, dirs=[P + "/lib"])
    lc = only("ln -sT ../x.py lib", is_dir=ws.is_dir)
    assert (lc.form, lc.links[0].path) == ("named", P + "/lib")
    assert links("ln -sT a b c") == []                         # -T needs exactly two paths


@pytest.mark.parametrize("command", [
    "ln -st /opt/bin a b", "ln -s -t /opt/bin a b", "ln -s --target-directory=/opt/bin a b",
    "ln -s --target-directory /opt/bin a b", "ln -s -t/opt/bin a b", "ln a -s b --target=/opt/bin",
])
def test_target_directory_option(command):
    lc = only(command)
    assert lc.form == "target_dir" and lc.folder == "/opt/bin"
    assert [x.path for x in lc.links] == ["/opt/bin/a", "/opt/bin/b"]


def test_more_than_two_paths_and_one_path():
    lc = only("ln -s x y z dir")
    assert lc.form == "many" and [x.path for x in lc.links] == [P + "/dir/x", P + "/dir/y", P + "/dir/z"]
    lc = only("ln -s /opt/tool/bin/tool")
    assert lc.form == "single" and lc.links[0].path == P + "/tool"


def test_quoted_paths_with_spaces_and_double_dash():
    lc = only('ln -s "/a b/c" "/d e/"')
    assert (lc.form, lc.links[0].path, lc.links[0].target_raw) == ("inside", "/d e/c", "/a b/c")
    lc = only("ln -s -- -weird /x/")
    assert lc.links[0].path == "/x/-weird"


def test_option_forms_and_wrappers():
    assert only("ln --sym a /").kind == "symbolic"            # unique long-option prefix
    assert only("ln a /").kind == "hard"
    assert only("sudo ln -sfn /opt/a /srv/b").links[0].path == "/srv/b"
    assert only("busybox ln -s a /").links[0].path == "/a"
    assert only("gln -s a /").links[0].path == "/a"
    assert links("ln --help") == [] and links("ln --version") == []
    assert links('echo "ln -s x ~/.bashrc"') == [] and links("grep -rn 'ln -s' docs") == []


def test_bsd_h_means_no_dereference():
    seen = []

    def is_dir(path, follow):
        seen.append((path, follow))
        return True

    only("ln -sh a b", is_dir=is_dir)
    only("ln -s a c", is_dir=is_dir)
    assert seen == [(P + "/b", False), (P + "/c", True)]


def test_local_workspace_is_dir_checks_the_disk(tmp_path):
    ws = LocalWorkspace()
    (tmp_path / "lib").mkdir()
    (tmp_path / "file.txt").write_text("x", encoding="utf-8")
    lib = linkplace.norm(str(tmp_path / "lib"))
    assert ws.is_dir(lib) is True
    assert ws.is_dir(linkplace.norm(str(tmp_path / "file.txt"))) is False
    assert ws.is_dir(linkplace.norm(str(tmp_path / "missing"))) is False
    assert ws.is_dir("relative/path") is None
    lc = only("ln -s ../x.py lib", cwd=str(tmp_path), is_dir=ws.is_dir)
    assert (lc.form, lc.why) == ("inside", "disk")
    try:
        os.symlink(str(tmp_path / "lib"), str(tmp_path / "lnk"), target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("this machine does not allow creating a symlink")
    lnk = linkplace.norm(str(tmp_path / "lnk"))
    assert ws.is_dir(lnk) is True and ws.is_dir(lnk, False) is False
    assert only("ln -sn ../x.py lnk", cwd=str(tmp_path), is_dir=ws.is_dir).form == "named"
    assert only("ln -s ../x.py lnk", cwd=str(tmp_path), is_dir=ws.is_dir).form == "inside"


def test_cd_and_code_in_strings():
    assert only("cd /etc && ln -s /p/x cron.d/job").links[0].path == "/etc/cron.d/job"
    assert only("cd && ln -s /p/x .bashrc").links[0].path == "~/.bashrc"
    assert only("cd - && ln -s /p/x .bashrc").links[0].path is None          # previous folder: unknown
    assert only('bash -c "ln -s x ~/.bashrc"').links[0].path == "~/.bashrc"
    assert only(r'find . -name "*.sh" -exec ln -s {} /usr/local/bin \;').links[0].target is None


def test_xargs_input_paths():
    lc = only("ls | xargs ln -s -t ~/.local/bin")
    assert lc.folder == "~/.local/bin"
    lc = only("ls | xargs ln -s /p/x")                        # input goes after the written paths
    assert lc.form == "unknown" and lc.maybe == ("/p/x",)
    lc = only("cat /workspace/results.txt | xargs -I{} ln -s {} ~/newlinks")   # nl2sh:243
    assert lc.form == "named" and lc.links[0].path == "~/newlinks" and lc.links[0].target is None


def test_variables_and_globs_are_unknown():
    assert only('ln -s x "$DEST"').links[0].path is None
    assert only("ln -s x /tmp/*").links[0].path is None
    assert only("ln -s $HOME/dotfiles/zshrc ${HOME}/.zshrc").links[0].path == "~/.zshrc"


def test_cp_link_modes_and_link():
    lc = only("cp -s a.txt b/")
    assert (lc.program, lc.kind, lc.form, lc.links[0].path) == ("cp", "symbolic", "inside", P + "/b/a.txt")
    assert only("cp -al src dst").kind == "hard"
    assert links("cp -r src dst") == [] and links("cp -S .bak a b") == []
    lc = only("link a b")
    assert (lc.kind, lc.links[0].path) == ("hard", P + "/b")


# ---------- placement: PowerShell and cmd ----------


def test_new_item_forms():
    lc = only(r"New-Item -ItemType SymbolicLink -Path C:\Users\me\.bashrc -Target C:\proj\x", cwd=r"C:\proj")
    assert (lc.kind, lc.links[0].path, lc.links[0].target) == ("symbolic", "c:/Users/me/.bashrc", "c:/proj/x")
    lc = only(r'ni -it Junction link -Va "C:\data"', cwd=r"C:\proj")
    assert (lc.kind, lc.links[0].path, lc.links[0].target) == ("junction", "c:/proj/link", "c:/data")
    lc = only(r"New-Item -Path C:\proj\bin -Name tool.exe -ItemType:HardLink -Value C:\tools\tool.exe", cwd=r"C:\proj")
    assert (lc.kind, lc.links[0].path) == ("hard", "c:/proj/bin/tool.exe")
    lc = only("New-Item -ItemType SymbolicLink -Path link_file -Target source_file_or_directory")   # tldr:new-item:5
    assert lc.links[0].path == P + "/link_file"
    assert links(r"New-Item -ItemType File -Path C:\proj\x.txt") == []
    lc = only('pwsh -c "New-Item -Type SymbolicLink -Path a -Target b"')
    assert lc.links[0].path == P + "/a"


def test_mklink_forms():
    lc = only(r"cmd /c mklink /D C:\a\b C:\c", cwd=r"C:\p")
    assert (lc.kind, lc.links[0].path, lc.links[0].target) == ("symbolic", "c:/a/b", "c:/c")
    assert only(r"mklink /H C:\p\x C:\p\y", cwd=r"C:\p").kind == "hard"
    assert only(r"mklink /J C:\p\x C:\p\y", cwd=r"C:\p").kind == "junction"
    assert links("mklink onlyone") == []


# ---------- the persistence list ----------


@pytest.mark.parametrize("command,kind", [
    ("ln /workspace/dir1 -s /", "root"),                                      # nl2sh:253 -> /dir1
    ("ln /testbed/dir3/subdir1/subsubdir1/FooBar -s /", "root"),              # nl2sh:150 -> /FooBar
    (r"mklink /D C:\evil C:\proj\x", "root"),
    ("ln -sf /tmp/x ~/.bashrc", "shell_startup"),
    ("ln -s dotfiles/profile ~/.profile", "shell_startup"),
    ("ln -s $HOME/dotfiles/zshrc $HOME/.zshrc", "shell_startup"),
    ("ln -s /c/p/x /c/Users/me/.bashrc", "shell_startup"),                    # Git Bash
    ("ln -s /mnt/c/p/x /mnt/c/Users/me/.profile", "shell_startup"),           # WSL
    ("ln -s /p/x /home/dev/.zshrc", "shell_startup"),
    ("ln -s /p/x /root/.bashrc", "shell_startup"),
    ("ln -s dotfiles/.bashrc ~", "shell_startup"),                             # ~ is a folder: -> ~/.bashrc
    ("ln -s /p/keys ~/.ssh/authorized_keys", "ssh"),
    ("ln -s /p/app.desktop ~/.config/autostart/", "autostart"),
    ("ln -s /p/x.plist ~/Library/LaunchAgents/x.plist", "autostart"),
    (r'New-Item -ItemType SymbolicLink -Path "C:\Users\me\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\a.lnk" -Target C:\p\a.exe', "autostart"),
    ("cd /etc && ln -s /p/job cron.d/job", "system_config"),
    ("ln -s /p/job /var/spool/cron/crontabs/root", "service"),
    ("ln -s /p/x.service ~/.config/systemd/user/x.service", "service"),
    ("ln -s /p/bin/tool /usr/local/bin/tool", "path_dir"),
    ("ln -s /p/bin/tool ~/.local/bin/", "path_dir"),
    ("ln -sf /opt/node/bin/node ~/bin/node", "path_dir"),
    ("ln -s ../../scripts/pre-commit .git/hooks/pre-commit", "git"),
    ("ln -s /p/gitconfig ~/.gitconfig", "git"),
    ("ln -s /p/vimrc ~/.vimrc", "editor"),
    ("ln -s ../shared/tasks.json .vscode/tasks.json", "editor"),
    ("ln -s /p/CLAUDE.md ~/.claude/CLAUDE.md", "agent_config"),
    ("ln -s ../shared/settings.json .claude/settings.json", "agent_config"),
    ("ln -s ../shared/mcp.json .mcp.json", "agent_config"),
    ("ln -s /p/evil.pth .venv/lib/python3.12/site-packages/evil.pth", "python_startup"),
    ("ln -s /p/x.py sitecustomize.py", "python_startup"),
    ("ls | xargs ln -s -t ~/.local/bin", "path_dir"),
    ('bash -c "ln -s x ~/.bashrc"', "shell_startup"),
])
def test_links_created_in_a_persistence_location(command, kind):
    hits = gate(command)
    assert hits and hits[0].side == "link" and hits[0].place.kind == kind, hits


@pytest.mark.parametrize("command,kind", [
    ("ln -s ~/.bashrc notes.txt", "shell_startup"),
    ("ln -s / root_alias", "root"),
    ("ln -s ~ home", "shell_startup"),
    ("ln -s /home homes", "shell_startup"),
    ("ln -s ~/.config cfg", "shell_startup"),                                 # holds ~/.config/fish, autostart, ...
    ("ln -s .git/hooks hooks", "git"),
    ("ln -s .git gitdir", "git"),
    ("ln -s /etc/shadow ./data/passwords", "system_config"),                  # agenttrust:file_ops_020 (deny)
])
def test_links_pointing_to_a_persistence_location(command, kind):
    hits = gate(command)
    assert hits and hits[0].side == "target" and hits[0].place.kind == kind, hits
    assert "later writes through the link change it" in hits[0].text()


@pytest.mark.parametrize("command,cwd", [
    ("ln -s AGENTS.md CLAUDE.md", P),
    ("ln -s ../shared/config.json ./config.json", P + "/app"),
    ("ln -s /testbed/hello.php /testbed/link", P),                          # nl2sh:61
    ("ln /workspace/dir1/terminate.txt /workspace/test", P),                # nl2sh:258
    ("cat /workspace/results.txt | xargs -I{} ln -s {} ~/newlinks", P),     # nl2sh:243
    ("New-Item -ItemType SymbolicLink -Path link_file -Target source_file_or_directory", P),
    ("ln -s node_modules/.bin/tsc tsc", P),
    ("ln -s .claude/CLAUDE.md AGENTS.md", P),
    ("ln -s ../lib/x.py src/", P),
    ("ln -s ~/dotfiles/notes ~/proj/notes", P),
    ("ln -s /usr/local/bin/python3 venv/bin/python", P),                     # a link to a program on PATH
    ("ln -sfn /opt/app/releases/42 /srv/app/current", P),
    ("ln -s dotfiles/bashrc ~", P),                                         # -> ~/bashrc: not a startup file
])
def test_ordinary_links_do_not_hit_the_list(command, cwd):
    assert gate(command, cwd) == []


def test_new_entry_in_root_whatever_the_cwd():
    assert gate("ln -s x y", "/")[0].place.kind == "root"


# ---------- the gate in rules.py ----------


def test_gate_fires_through_detect_gates_and_scripts():
    hits = [h for h in rules.detect_gates(env("ln /workspace/dir1 -s /")) if h.gate_class == "persistence_link"]
    assert hits and hits[0].matched.startswith("creates the link /dir1 -> /workspace/dir1")
    assert not [h for h in rules.detect_gates(env("ln -s AGENTS.md CLAUDE.md")) if h.gate_class == "persistence_link"]
    script = ScriptFile(path=P + "/setup.sh", rel="setup.sh", content="#!/bin/sh\nln -sf \"$PWD/x\" ~/.bashrc\n",
                        sha256="0" * 64, size=40, kind="shell")
    assert [h.gate_class for h in rules.script_gate_hits([script])] == ["persistence_link"]


def test_gate_asks_before_the_model():
    class Never:
        name = "never"

        def evaluate(self, state, questions):
            raise AssertionError("the model must not be asked")

    dev = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    d = judge(env("ln /workspace/dir1 -s /", user="Create a symbolc link in the /workspace/dir1 to root folder"),
              dev, provider=Never())
    assert (d.decision, d.stage, d.reason_code) == ("ask", "human_gate", "human_gate:persistence_link")
