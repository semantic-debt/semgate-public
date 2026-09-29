"""Every GitHub Action a workflow uses is pinned by commit SHA.

A tag (actions/checkout@v4) can be moved to other code by whoever controls
the action's repository; a commit SHA cannot. The comment after the SHA
names the release and its date, so an update can check the 72-hour rule."""
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WORKFLOWS = sorted((ROOT / ".github" / "workflows").glob("*.y*ml"))
USES = re.compile(r"^\s*(?:-\s+)?uses:\s*(\S+)(.*)$")
PINNED = re.compile(r"^[\w.-]+/[\w./-]+@[0-9a-f]{40}$")
COMMENT = re.compile(r"^\s+# v\d+\.\d+\.\d+ \(released \d{4}-\d\d-\d\d\)$")


def test_there_are_workflows():
    assert {p.name for p in WORKFLOWS} >= {"ci.yml", "release.yml"}


def test_every_action_is_pinned_by_commit_sha_with_its_release():
    bad = []
    for path in WORKFLOWS:
        for n, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            m = USES.match(line)
            if not m or m.group(1).startswith("./"):
                continue
            if not PINNED.match(m.group(1)) or not COMMENT.match(m.group(2)):
                bad.append(f"{path.name}:{n}: {line.strip()}")
    assert not bad, "\n".join(bad)


def test_the_removed_key_workflows_stay_removed():
    """workflow_dispatch jobs that gave TYPESAFE_API_KEY to a run with
    contents: write (removed 2026-09-25)."""
    names = {p.name for p in WORKFLOWS}
    for gone in ("2-jev-dataset-eval.yml", "3-jev-two-pass-eval.yml", "4-model-token-preflight.yml",
                 "jev-corrected-probe.yml", "private-jev.yml"):
        assert gone not in names
    for path in WORKFLOWS:
        text = path.read_text(encoding="utf-8")
        assert not ("TYPESAFE_API_KEY" in text and re.search(r"contents:\s*write", text)), path.name
