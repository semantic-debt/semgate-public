"""S6_link_placement: the code signal that tells the model where a link
command really creates its link (semgate/codesignals.py, linkplace.py)."""
import json
from pathlib import Path

import pytest

from conftest import make_grant
from semgate import codesignals, router
from semgate.envelope import Envelope, Environment, ProposedAction, Trajectory
from semgate.judge import judge
from semgate.policy import Policy
from semgate.providers.base import PredicateAnswer
from semgate.scriptsource import SyntheticWorkspace

ROOT = Path(__file__).resolve().parents[1]
P = "/workspace/project"


def env(command, cwd=P, user=""):
    return Envelope(
        schema="semgate-envelope/1",
        action=ProposedAction(tool="bash", arguments={"command": command}),
        grant=make_grant(allowed_path_prefixes=(), purpose="Software development work inside this project repository."),
        environment=Environment(project_root=P, cwd=cwd, harness="test", session_id="ses-test"),
        trajectory=Trajectory(recent=()),
        user_message=user,
        evaluated_at="2026-09-18T08:00:00Z",
    )


def _s6(command, cwd=P, workspace=None):
    return codesignals.compute(env(command, cwd), enabled=[codesignals.S6_ID], workspace=workspace)


def test_s6_text_for_the_reversed_case():
    sig = _s6("ln /workspace/dir1 -s /")
    assert len(sig) == 1 and sig[0].id == "S6_link_placement"
    assert sig[0].text == (
        "checked by code: this command creates the symbolic link /dir1, pointing to /workspace/dir1. / is an existing "
        "folder (the root folder), and when the last path given to ln is an existing folder, ln creates the link inside "
        "that folder, named after the other path; /workspace/dir1 is the link's target, not a new link; /dir1 is outside "
        "the project folder /workspace/project")
    assert sig[0].record()["links"] == ["/dir1"]


def test_s6_other_forms():
    assert _s6("ln -s x y z dir")[0].text.startswith(
        "checked by code: this command creates the symbolic links /workspace/project/dir/x (pointing to x), ")
    assert "given one path, so it creates the link in the current folder /workspace/project" in _s6("ln -s /opt/tool")[0].text
    assert "the folder given with -t" in _s6("ln -st lib a")[0].text
    assert "outside the project folder" not in _s6("ln -s ../lib/x.py src/")[0].text
    ws = SyntheticWorkspace({}, dirs=[P + "/lib"])
    assert "(checked on disk)" in _s6("ln -s ../x.py lib", workspace=ws)[0].text


@pytest.mark.parametrize("command", [
    "ln -s AGENTS.md CLAUDE.md", "ln -s ../shared/config.json ./config.json", "ln -s /testbed/hello.php /testbed/link",
    "cat /workspace/results.txt | xargs -I{} ln -s {} ~/newlinks", "ls | xargs ln -s /p/x", "ls -la", "git status",
    "New-Item -ItemType SymbolicLink -Path link_file -Target source_file_or_directory",
])
def test_s6_silent_when_the_link_path_is_written_out(command):
    assert _s6(command) == []


def test_s6_off_unless_listed_and_reaches_the_state_when_listed(tmp_path):
    raw = json.loads((ROOT / "policies" / "router_policy_dev.json").read_text(encoding="utf-8"))
    raw["router"]["code_signals"].remove("S6_link_placement")
    dev = Policy(raw, source="dev before S6")                    # dev before it adopted S6
    dev_s6 = Policy.load(str(ROOT / "policies" / "router_policy_dev.json"))
    assert codesignals.S6_ID not in router.enabled_code_signals(dev)
    assert codesignals.S6_ID in router.enabled_code_signals(dev_s6)
    assert codesignals.S6_ID not in codesignals.DEFAULT_IDS

    class Capture:
        name = "capture"

        def __init__(self):
            self.states = []

        def evaluate(self, state, questions):
            self.states.append(dict(state))
            out = {}
            for q, spec in questions.items():
                if spec.get("type") == "choice":
                    out[q] = PredicateAnswer(q, value="review", confidence=0.9, raw={"probabilities": {"review": 0.9}})
                elif spec.get("type") == "score":
                    out[q] = PredicateAnswer(q, value=1.0, confidence=0.9, raw={"probabilities": {}})
                else:
                    out[q] = PredicateAnswer(q, probability=0.9, confidence=0.8)
            return out

    e = env("ln -s ../lib/x.py src/", user="link lib/x.py into src")
    a, b = Capture(), Capture()
    judge(e, dev, provider=a)
    d = judge(e, dev_s6, provider=b)
    assert "code_signals" not in a.states[0]
    assert "creates the symbolic link /workspace/project/src/x.py" in b.states[0]["code_signals"]
    assert [f["id"] for f in d.evidence["code_signals"]["fired"]] == ["S6_link_placement"]


def test_dev_adopted_dev_s6():
    """dev_s6 was dev plus the signal; dev adopted it (2026-09-24), so dev =
    dev_s6 except name and provenance."""
    a = json.loads((ROOT / "policies" / "router_policy_dev.json").read_text(encoding="utf-8"))
    b = json.loads((ROOT / "policies" / "router_policy_dev_s6.json").read_text(encoding="utf-8"))
    a["router"].pop("test_run_facts", None)          # adopted 2026-09-25, from dev_testrun
    a["router"].pop("test_run_build_facts", None)    # adopted 2026-09-26, from dev_buildfacts
    a["router"]["thresholds"].pop("test_damage_withholds_edit_allow", None)    # adopted 2026-09-26, from dev_s4allow
    a["router"]["approval_questions"].pop("user_declined_blocked_action", None)    # adopted 2026-09-29, from dev_chatdecline
    assert a["router"]["code_signals"][-1] == "S6_link_placement"
    for key in ("trust_requests", "trust_questions", "pin_requests", "pin_questions"):   # adopted later, from dev_trust
        a["router"].pop(key)
    for key in ("trust_request_min", "pin_request_min"):
        a["router"]["thresholds"].pop(key)
    for raw in (a, b):
        raw.pop("name"); raw.pop("provenance")
    assert a == b
