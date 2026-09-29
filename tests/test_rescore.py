"""evals/rescore.py on a synthetic report. No real report files, no model calls."""
from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EVALS = ROOT / "evals"
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(EVALS))

from semgate.eval.metrics import score  # noqa: E402


def _load():
    spec = importlib.util.spec_from_file_location("rescore", EVALS / "rescore.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rescore = _load()


def _rec(case_id, source, source_id, label, decision, category):
    return {"case_id": case_id, "source": source, "source_id": source_id, "label": label,
            "decision": decision, "category": category, "stage": "semantic", "predicate_votes": []}


RECORDS = [
    _rec("nl2sh:4", "nl2sh", "4", "ask", "allow", "nl2sh:difficulty1"),        # false allow before, correct after
    _rec("nl2sh:22", "nl2sh", "22", "ask", "ask", "nl2sh:difficulty1"),        # correct before, wrong after
    _rec("nl2sh:298", "nl2sh", "298", "allow", "allow", "nl2sh:difficulty3"),  # correct before, false allow after
    _rec("karanxa:aaa111", "karanxa", "aaa111", "allow", "allow", "karanxa:trust_hierarchy"),  # -> ask: false allow
    _rec("karanxa:bbb222", "karanxa", "bbb222", "deny", "allow", "karanxa:secrets_exfil"),     # private, -> ask
    _rec("redcode:1_1", "redcode", "1_1", "deny", "deny", "redcode:index1"),
]


def _write(path: Path, data) -> str:
    path.write_text(json.dumps(data), encoding="utf-8")
    return str(path)


def _setup(tmp_path: Path):
    report = {"schema": "semgate-eval-report/1", "provider": "synthetic", "policy_version": "test",
              "metrics": score(RECORDS), "cases": RECORDS}
    report_path = _write(tmp_path / "report.json", report)
    nl2sh = _write(tmp_path / "nl2sh.json", {
        "_meta": {"standard": "test"},
        "nl2sh:4": {"old": "ask", "new": "allow", "reason": "requested"},
        "nl2sh:22": {"old": "ask", "new": "allow", "reason": "read-only"},
        "nl2sh:298": {"old": "allow", "new": "ask", "reason": "sed -i"},
        "nl2sh:999": {"old": "ask", "new": "allow", "reason": "not in this report"},
    })
    karanxa = _write(tmp_path / "karanxa.json", {
        "_meta": {"source": "karanxa"},
        "aaa111": {"label": "ask", "reason": "unconfirmed purchase"},
        "bbb222": {"label": "ask", "reason": "private case"},
    })
    private_dir = tmp_path / "private"
    private_dir.mkdir()
    (private_dir / "karanxa.jsonl").write_text(json.dumps({"case_id": "karanxa:bbb222", "source": "karanxa"}) + "\n", encoding="utf-8")
    return report_path, nl2sh, karanxa, str(private_dir)


def test_rescore_recomputes_metrics_with_overridden_labels(tmp_path, capsys):
    report_path, nl2sh, karanxa, private_dir = _setup(tmp_path)
    assert rescore.main(["--report", report_path, "--overrides", nl2sh, "--overrides", karanxa,
                         "--private-dir", private_dir, "--json"]) == 0
    out = json.loads(capsys.readouterr().out)

    assert out["before"] == score(RECORDS)
    assert out["stored_metrics_mismatch"] == []
    after = out["after"]
    # decisions unchanged: allow x4 (nl2sh:4, nl2sh:298, aaa111, bbb222)
    assert after["auto_allow_count"] == 4
    # after labels: nl2sh:4 allow (ok), nl2sh:298 ask (false), aaa111 ask (false), bbb222 ask (false)
    assert after["false_allow_count"] == 3
    assert after["harmful_false_allow_count"] == 3
    assert after["confusion_matrix"]["allow"] == {"allow": 1, "ask": 1, "deny": 0}
    assert after["confusion_matrix"]["ask"] == {"allow": 3, "ask": 0, "deny": 0}
    assert after["confusion_matrix"]["deny"] == {"allow": 0, "ask": 0, "deny": 1}
    assert after["tri_state_accuracy"] == 2 / 6
    assert out["before"]["false_allow_count"] == 2  # nl2sh:4 (ask) and bbb222 (deny)

    summary = out["overrides"]
    assert summary["labels_changed"] == 5
    assert summary["label_transitions"] == {"allow->ask": 2, "ask->allow": 2, "deny->ask": 1}
    assert summary["files"][nl2sh]["not_in_report"] == 1
    assert summary["old_label_mismatch"] == 0
    assert out["changed_private_count"] == 1


def test_rescore_never_lists_private_cases(tmp_path, capsys):
    report_path, nl2sh, karanxa, private_dir = _setup(tmp_path)
    rescore.main(["--report", report_path, "--overrides", nl2sh, "--overrides", karanxa,
                  "--private-dir", private_dir, "--list-changed"])
    text = capsys.readouterr().out
    assert "karanxa:aaa111" in text and "nl2sh:298" in text
    assert "bbb222" not in text
    assert "1 private case(s) not listed" in text
    assert "confusion matrix after" in text

    rescore.main(["--report", report_path, "--overrides", karanxa, "--private-dir", private_dir, "--list-changed", "--json"])
    payload = capsys.readouterr().out
    assert "bbb222" not in payload


def test_report_inside_private_dir_is_all_private(tmp_path, capsys):
    report_path, nl2sh, karanxa, private_dir = _setup(tmp_path)
    inside = Path(private_dir) / "karanxa-jev.json"
    inside.write_text(Path(report_path).read_text(encoding="utf-8"), encoding="utf-8")
    rescore.main(["--report", str(inside), "--overrides", nl2sh, "--overrides", karanxa,
                  "--private-dir", private_dir, "--list-changed"])
    text = capsys.readouterr().out
    assert "changed public cases (0; 5 private case(s) not listed)" in text
    for case_id in ("nl2sh:4", "nl2sh:22", "nl2sh:298", "aaa111", "bbb222"):
        assert case_id not in text


def test_old_label_mismatch_and_conflicts_are_counted(tmp_path, capsys):
    report_path, nl2sh, karanxa, private_dir = _setup(tmp_path)
    first = _write(tmp_path / "a.json", {"nl2sh:22": {"old": "allow", "new": "allow"}})
    second = _write(tmp_path / "b.json", {"nl2sh:22": {"new": "deny"}})
    rescore.main(["--report", report_path, "--overrides", first, "--overrides", second,
                  "--private-dir", private_dir, "--json"])
    out = json.loads(capsys.readouterr().out)
    assert out["overrides"]["old_label_mismatch"] == 1
    assert out["overrides"]["conflicts_between_files"] == 1
    assert out["overrides"]["label_transitions"] == {"ask->deny": 1}


def test_committed_override_files_are_valid():
    for name in ("nl2sh-overrides.json", "karanxa-overrides.json", "karanxa-tristate-overrides.json"):
        path = EVALS / "labels" / name
        if path.exists():
            entries = rescore.load_overrides([str(path)])
            assert entries, name
