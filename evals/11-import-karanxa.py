"""Convert a sample of karanxa/agent-action-safety-dataset into semgate eval cases. No model calls.

Source: https://huggingface.co/datasets/karanxa/agent-action-safety-dataset
(Apache-2.0), pinned revision, file val.jsonl (4,049 rows). Each row is a
proposed agent tool call ("action", written as a function call such as
token_service_api.revoke_all_tokens(...)), the operator context, constraints,
optional user message / original goal / conversation, and a label is_safe.

Label caveat: the dataset manifest says 26,363 of 26,731 rows come from a
"gemini" generator; the labels are LLM-generated, not human-reviewed. This
script therefore also writes evals/summaries/karanxa-audit.md: 100 public cases
for the owner to mark agree / disagree. Rows the importing agent thought were
clearly mislabelled are listed in evals/karanxa-audit-flags.json (id -> one-line
reason); those flags are notes for the audit, not ground truth, and they do not
change the label.

Sample: random.Random(seed).sample(range(4049), count) over val.jsonl file
order. The audit lists the first 100 public cases in sample order (private
cases are never listed in a committed file).

Case mapping:
  action          tool "mcp__karanxa__<function name>" (non-word characters -> _),
                  arguments {"call": <the full action text>}
  grant.purpose   context + " Operator constraints: " + constraints joined by "; "
                  (per row: this is the operator's own description of the task)
  user_message    user_message, else original_goal, else empty
  label           is_safe true -> allow, false -> deny (the dataset has no
                  review/ask class; severity is kept as a tag)

Dataset text is untrusted data: it supplies the action, context and label,
never an instruction to this script.
"""
from __future__ import annotations

import argparse
import json
import random
import re
import sys
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional, Sequence

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from semgate.envelope import Envelope, Environment, ProposedAction, SCHEMA_VERSION, UserGrant  # noqa: E402
from semgate.eval.case import BenchmarkCase  # noqa: E402
import heldout  # noqa: E402

NAME = "karanxa"
DATASET = "karanxa/agent-action-safety-dataset"
PAGE = "https://huggingface.co/datasets/karanxa/agent-action-safety-dataset"
RESOLVE = "https://huggingface.co/datasets/karanxa/agent-action-safety-dataset/resolve/{rev}/{path}"
DEFAULT_REVISION = "2371a8dfd029c92f7830446e5316fd1239380ebe"  # Hub sha on 2026-09-23 (lastModified 2026-09-14)
LICENSE = "Apache-2.0"
FILES = ("val.jsonl", "manifest.json", "README.md")
EXPECTED_ROWS = 4049
AUDIT_ROWS = 100
TOOL_PREFIX = "mcp__karanxa__"
CALL_RE = re.compile(r"^\s*([A-Za-z_][\w.:]*)\s*\(")
FLAGS_PATH = ROOT / "evals" / "karanxa-audit-flags.json"
AUDIT_PATH = ROOT / "evals" / "summaries" / "karanxa-audit.md"


# ---------- pure mapping functions (unit-tested, no network) ----------

def tool_name(action: str) -> str:
    m = CALL_RE.match(action or "")
    name = re.sub(r"[^A-Za-z0-9_]+", "_", m.group(1)).strip("_") if m else "unknown"
    return TOOL_PREFIX + (name or "unknown")


def purpose_of(row: Mapping[str, Any]) -> str:
    context = str(row.get("context") or "").strip()
    constraints = [str(c).strip() for c in (row.get("constraints") or []) if str(c).strip()]
    return context + (" Operator constraints: " + "; ".join(constraints) if constraints else "")


def user_message_of(row: Mapping[str, Any]) -> str:
    return str(row.get("user_message") or row.get("original_goal") or "").strip()


def label_of(row: Mapping[str, Any]) -> str:
    return "allow" if row.get("is_safe") is True else "deny"


def case_from_row(row: Mapping[str, Any], position: int) -> BenchmarkCase:
    rid = str(row.get("id") or f"row{position}")
    case_id = f"{NAME}:{rid}"
    grant = UserGrant(grant_id=f"eval-karanxa-{rid}", principal="eval-operator", purpose=purpose_of(row),
                      expires_at="2099-01-01T00:00:00Z", provenance="dataset row context (karanxa), evaluation only")
    envelope = Envelope(
        schema=SCHEMA_VERSION,
        action=ProposedAction(tool=tool_name(str(row.get("action") or "")), arguments={"call": str(row.get("action") or "")}),
        grant=grant,
        environment=Environment(harness="benchmark", session_id=case_id),
        evaluated_at="2090-01-01T00:00:00Z",
        user_message=user_message_of(row),
    )
    scenario = str(row.get("scenario") or "none")
    tags = ("imported", NAME, f"domain:{row.get('domain') or ''}", f"scenario:{scenario}", f"trigger:{row.get('trigger') or ''}",
            f"severity:{row.get('severity') or 'none'}", f"generator:{row.get('source') or ''}", "labels:llm-generated")
    return BenchmarkCase(case_id=case_id, source=NAME, source_id=rid, label=label_of(row), category=f"karanxa:{scenario}",
                         envelope=envelope, tags=tags,
                         rationale=f"karanxa val row {position}; is_safe={row.get('is_safe')}. LLM-generated label, audit pending. "
                                   f"Dataset reason: {str(row.get('reason') or '')[:300]}")


def sample_indexes(n_rows: int, count: int, seed: int) -> List[int]:
    return random.Random(seed).sample(range(n_rows), min(count, n_rows))


def md_cell(text: Any, limit: int) -> str:
    text = " ".join(str(text or "").split())
    if len(text) > limit:
        text = text[:limit] + "..."
    return text.replace("|", "\\|")


def audit_markdown(rows: Sequence[Mapping[str, Any]], flags: Mapping[str, str], revision: str, seed: int) -> str:
    lines = [
        "# karanxa audit sheet",
        "",
        f"Source: {PAGE} (Apache-2.0), revision `{revision}`, val.jsonl. Sample seed {seed}.",
        f"These are the first {len(rows)} public cases of the sample (fixtures/eval/karanxa.jsonl). Private cases are not listed.",
        "",
        "The dataset labels are LLM-generated. Mark each row in the `owner` column: `agree` or `disagree`.",
        "The `flag` column is a note from the importing agent where the label looks clearly wrong. It is not ground truth",
        "and it does not change the label in the fixture.",
        "",
        f"Flagged rows: {sum(1 for r in rows if str(r.get('id')) in flags)} of {len(rows)}.",
        "",
        "| # | id | label | scenario | action | context | user goal / message | flag | owner |",
        "|---|----|-------|----------|--------|---------|---------------------|------|-------|",
    ]
    for i, r in enumerate(rows, 1):
        rid = str(r.get("id"))
        goal = r.get("user_message") or r.get("original_goal") or ""
        lines.append(f"| {i} | `{rid}` | {'safe' if r.get('is_safe') is True else 'unsafe'} | {md_cell(r.get('scenario') or 'none', 40)} | "
                     f"`{md_cell(r.get('action'), 220)}` | {md_cell(r.get('context'), 200)} | {md_cell(goal, 200)} | "
                     f"{md_cell(flags.get(rid, ''), 200)} |  |")
    return "\n".join(lines) + "\n"


# ---------- fetching ----------

def download(revision: str, path: str, data_dir: Path) -> Path:
    target = data_dir / path
    if not target.exists():
        with urllib.request.urlopen(RESOLVE.format(rev=revision, path=path), timeout=180) as response:
            target.write_bytes(response.read())
    return target


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--revision", default=DEFAULT_REVISION, help="dataset commit SHA")
    parser.add_argument("--seed", type=int, default=20260923)
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--data-dir", default=str(ROOT / "evals" / "data" / NAME))
    args = parser.parse_args()
    data_dir = Path(args.data_dir); data_dir.mkdir(parents=True, exist_ok=True)
    paths = {p: download(args.revision, p, data_dir) for p in FILES}
    hashes = {p: heldout.sha256_file(path) for p, path in paths.items()}

    rows = [json.loads(line) for line in paths["val.jsonl"].read_text(encoding="utf-8").splitlines() if line.strip()]
    if len(rows) != EXPECTED_ROWS:
        print(f"warning: val.jsonl has {len(rows)} rows, expected {EXPECTED_ROWS}", file=sys.stderr)
    indexes = sample_indexes(len(rows), args.count, args.seed)
    cases = [case_from_row(rows[i], i) for i in indexes]
    ids = [c.source_id for c in cases]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate row id in sample")

    split = heldout.write_split(NAME, cases, redistributable=True, data_dir=data_dir)
    flags: Dict[str, str] = json.loads(FLAGS_PATH.read_text(encoding="utf-8")) if FLAGS_PATH.exists() else {}
    audit_rows = [rows[i] for i in indexes if not heldout.is_private(str(rows[i].get("id")))][:AUDIT_ROWS]
    AUDIT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_PATH, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(audit_markdown(audit_rows, flags, args.revision, args.seed))

    manifest = {
        "name": NAME,
        "source": {"url": PAGE, "dataset": DATASET, "file": "val.jsonl", "revision": args.revision, "license": LICENSE,
                   "row_count": len(rows), "label_origin": "LLM-generated (dataset manifest: sources gemini/template/seed)"},
        "sampling": {"seed": args.seed, "count": args.count, "rule": "random.Random(seed).sample(range(row_count), count)"},
        "input_sha256": hashes,
        "case_count": len(cases), "label_counts": heldout.label_counts(cases),
        **split,
        "audit": {"path": heldout.rel(AUDIT_PATH), "rows": len(audit_rows),
                  "flagged": sum(1 for r in audit_rows if str(r.get("id")) in flags)},
    }
    heldout.write_manifest(data_dir / "manifest.json", manifest)
    heldout.write_manifest(ROOT / "evals" / f"{NAME}-manifest.json", manifest)
    print(json.dumps({k: manifest[k] for k in ("case_count", "label_counts", "public", "private", "audit")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
