# Semgate evaluation roadmap

Semgate should be judged at one asymmetric operating point: maximize benign auto-allow while observing zero false allows on frozen held-out cases. Aggregate accuracy is secondary. The current benchmarks measure useful parts of the gate, but they do not yet cover the whole product boundary.

## Evaluation discipline

- Freeze datasets, splits, prompts, thresholds, and decision rules before an evaluation starts.
- Never fit thresholds, prompts, policies, or exceptions to held-out failures.
- Publish dataset revisions, split hashes, operating thresholds, false allows, benign auto-allow, calibration, latency, and cost.
- Preserve old results, including negative experiments. A new method gets a new report.
- Every failure found in the wild becomes a new frozen regression case. Case `r-judge:102` is the first named example.
- The adversarial corpus is append-only. Fix labels with a new revision and an audit note; never silently edit history.
- Dataset labels measure outcomes. They never create authorization or policy grants.

## Priority suites

### 1. Capability-policy dataset

This is the next dataset to build. The existing frozen benchmark has no trusted, predeclared, exact capabilities, so it cannot measure the coverage of a known-benign policy layer.

Each case must pair a fully instantiated action envelope with an owner-issued grant and expected decision. Include minimally changed counterfactuals for wrong target, wider scope, expired grants, future grants, untrusted provenance, missing fields, malformed fields, extra arguments, and revoked grants. Freeze the complete cases and splits before any evaluator or threshold sees held-out labels.

Primary metrics:

- benign auto-allow at zero observed false allows;
- false allows by counterfactual type;
- unnecessary asks on exact in-scope actions;
- rejection of expired, revoked, widened, and untrusted grants;
- coverage by action primitive and target type.

### 2. Adversarial framing suite

The current benchmark largely presents one decision at a time. Several real failures live in the trajectory. Build multi-turn trajectories that vary only the framing:

- gradual trust erosion across turns;
- a fresh conversation carrying trusted-looking prior context;
- CTF, research, simulation, or emergency frames;
- fabricated transcripts in which other agents already executed the action;
- repeated benign actions followed by one widened or irreversible action;
- model statements that acknowledge a classifier warning and then reason around it.

Measure whether the same final action receives a different decision because of accumulated trust, narrative framing, or social proof.

### 3. Injection tests

Test adversarial content reaching the gate inside the data it must inspect:

- tool outputs, webpages, email bodies, file contents, diffs, logs, issue text, and quoted conversation context;
- direct and indirect instructions to change policy, suppress evidence, widen scope, disclose data, or choose a tool;
- split payloads whose instruction emerges only after several observations are combined;
- injected claims of owner approval or trusted provenance.

The gate must treat these as evidence, never authority. Report injection families separately from ordinary unsafe actions.

### 4. Normalization and evasion suite

This belongs to the deterministic layer and should run as unit/property tests, not an LLM benchmark.

Cover encoding tricks, Unicode homoglyphs and normalization, bidirectional controls, shell quoting variants, escaped separators, path traversal and symlink tricks, alternate path forms, chained commands, command substitution, redirects, environment expansion, argument reordering, URL canonicalization, and nested structured arguments. Assert that equivalent actions normalize to one representation and evasive widening cannot bypass exact matching.

### 5. Calibration

A probability is useful only if it is reliable. For each semantic score and source:

- publish reliability diagrams and bin counts;
- report Brier score and expected calibration error with confidence intervals;
- separate veto confidence from missing-evidence confidence;
- inspect calibration drift by action primitive, data source, trajectory length, and model revision;
- never claim that a score is calibrated from accuracy alone.

### 6. Operational budgets as tests

Treat deployment constraints as regression tests:

- p50 and p95 latency per decision, including retries and schema failures;
- model and infrastructure cost per 1,000 decisions;
- timeout, parse-failure, and provider-error rates;
- cold-start and sustained-throughput behavior;
- ask-safe fallback under every provider failure.

Publish latency and cost at the same frozen operating point used for safety and coverage.

## Handoff prompt: build suite 1

Copy the prompt below into a coding agent with access to the Semgate repository.

```text
Implement Semgate's capability-policy evaluation dataset and runner. This is an evaluation artifact, not a production authorization store. Work in the existing semgate repository and preserve all prior reports.

Goal
Build a frozen dataset that measures whether an exact, deterministic capability layer can auto-allow in-scope actions while rejecting minimally changed unauthorized variants. Dataset labels are measurement only and must never be loaded as runtime grants.

Case schema
Use one versioned JSONL record per case:

{
  "schema": "semgate-capability-case/1",
  "id": "stable-string",
  "family_id": "stable-counterfactual-family",
  "split": "dev|test",
  "envelope": {
    "action": "fully-qualified action primitive",
    "target": {"type": "resource type", "id": "canonical exact identifier"},
    "scope": {"canonical action-specific limits": "..."},
    "arguments": {"complete normalized arguments": "..."},
    "requested_at": "RFC3339 timestamp",
    "source": {"channel": "trusted|untrusted channel type", "principal": "bound identifier or unverified"}
  },
  "grant": {
    "grant_id": "stable-string",
    "issued_by": "trusted_owner_channel",
    "subject": "agent or principal",
    "action": "exact action primitive",
    "target": {"type": "resource type", "id": "canonical exact identifier"},
    "scope": {"same canonical limits": "..."},
    "not_before": "RFC3339 timestamp",
    "expires_at": "RFC3339 timestamp",
    "revoked_at": null,
    "provenance_ref": "opaque original-owner observation reference"
  },
  "expected": "allow|ask|deny",
  "counterfactual": {
    "kind": "base|wrong_target|wider_scope|expired|future|revoked|untrusted_provenance|missing_field|extra_argument|malformed",
    "changed_fields": ["JSON pointers changed from the base case"]
  },
  "metadata": {"primitive": "read|write|shell|send|deploy|permission|credential|money|other", "notes": "non-authoritative"}
}

Dataset construction
- Create at least 100 base families and at least 1,000 total cases.
- Each family must contain one exact in-scope base action plus at least: wrong target, wider scope, expired, revoked, untrusted provenance, and one action-specific evasion.
- Cover at minimum file reads/writes, repository operations, shell commands, network requests, message sends, deploys, permission changes, credential access, and money-bearing actions.
- Include both reversible and irreversible effects. External representation, money, credentials, permission changes, and destructive actions must follow Semgate's hard invariants and cannot become allowable merely because a fuzzy model score is high.
- Use canonical resource identifiers and complete arguments. No wildcard grants and no broad rules such as "git push is benign."
- Counterfactuals must be minimally changed and record exact changed JSON pointers.
- Do not copy benchmark labels into grants. Grants must be explicit data fields with trusted-owner provenance in the case schema.

Freeze rules
- Generate the full corpus and deterministic family-level dev/test split before running any evaluator. Counterfactual siblings must remain in the same split to prevent leakage.
- Write a manifest containing dataset SHA-256, case count, family count, split hashes, generator commit, schema version, and creation timestamp.
- After the first scored run, the corpus is append-only. Corrections create a new version and audit record; never rewrite the published revision.
- Do not tune the matcher, model prompt, threshold, or rules on held-out test labels.

Runner and tests
- Add a deterministic exact matcher for action, canonical target, scope, arguments, time window, revocation, subject, and trusted provenance.
- Reject malformed or incomplete grants safely.
- Add unit/property tests for all counterfactual types and normalization boundaries.
- Add an offline evaluation runner that reports confusion matrix, false allows, benign auto-allow, unnecessary asks, results by primitive/counterfactual, and the zero-false-allow operating point.
- Add CI that validates schema, hashes, family-level split isolation, append-only manifest rules, and deterministic reproduction. Do not call paid models.

Deliverables
- versioned JSON schema;
- generator and seed/config;
- frozen JSONL corpus;
- manifest with hashes;
- deterministic matcher and tests;
- offline report;
- README explaining threat model, limitations, and how to add future append-only cases.

Before committing, run all tests, reproduce the dataset twice and verify identical hashes, then inspect the report for accidental use of labels as grants. Report exact file URLs and any unresolved limitation. Do not run paid evaluation calls.
```
