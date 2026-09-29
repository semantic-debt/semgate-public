# Semgate shadow observer for Gemini CLI v0.60.0

This is a POSIX-only shadow-data prototype verified against Gemini CLI **v0.60.0** on Linux. It logs candidates but never returns a Gemini permission decision. Gemini remains authoritative. Native Windows/PowerShell is not supported in this release.

## Install

Requires Python 3.10+ on a POSIX system. From the extracted archive root:

```bash
cd gemini-cli-shadow
python3 install.py
```

The installer understands Gemini's JSON-with-comments settings, preserves existing telemetry values and unrelated hooks, makes a private backup, stages a versioned hook, and changes settings only after staging succeeds. On POSIX it uses shell quoting and private file modes. On native Windows (`py install.py`) the installed command passes the log path as `--log "<path>"` with Windows argument quoting, because Windows shells have no `VAR=value command` form; files under your user profile are private through the profile's access rules, since Windows has no POSIX mode bits.

It installs `BeforeTool` and `Notification:ToolPermission` hooks. ToolPermission notifications are **confirmation-flow attempts**. Gemini v0.60.0 emits them before `AwaitingApproval`, and a modified proposal can emit another attempt. They do not prove the UI was seen or answered and they are not unique-call identities.

## Static rule

The sole static rule identifies a low-risk *shape*: a `read_file` request with v0.60.0's real argument names, an existing regular file whose resolved path is inside the workspace, an explicit range of 1-500 lines, a listed source/text suffix, and no recognized sensitive filename. Suffix and line bounds do not prove non-sensitive contents. The logged candidate is separate from user authorization. An explicit `trusted_constraints.read_files=false` is honored before the static candidate.

## Optional Jev shadow evaluation

Off by default. Install the SDK explicitly and pin it for this experiment:

```bash
python3 -m pip install 'typesafe-sdk==0.7.0'
export SEMGATE_SHADOW_JEV=1
export SEMGATE_JEV_MODEL=jev-1.13.0
export SEMGATE_TRUSTED_CONTEXT_FILE=/private/path/session-context.json
```

Only version-shaped model names such as `jev-1.13.0` are accepted; `jev-latest`, previews, and whitespace are rejected. A session entry must contain a non-empty string `trusted_intent` and non-empty object `trusted_constraints`, for example:

```json
{"SESSION_ID":{"trusted_intent":"Review this project","trusted_constraints":{"read_only":true,"read_files":true}}}
```

The package does not create, authenticate, expire, or refresh that context. Production use needs owner/source, session/workspace, revision, and expiry validation. The full outbound state is redacted, but redaction is not DLP and may remove decision-relevant facts. TypeSafe debug logs can contain request bodies.

The client uses a 4-second per-HTTP-operation timeout and zero retries. This is **not** a four-second end-to-end deadline. SDK startup, multiple operations, processing, and writes consume the hook's outer 7-second Gemini budget. The proposal is durably logged before optional evaluation, and the evaluation is a separate event. Production evaluation should move off the interactive hook path.

## Report

```bash
python3 correlate_shadow.py \
  --shadow ~/.gemini/semgate-shadow-v4.jsonl \
  --telemetry ~/.gemini/telemetry.log \
  --out ./shadow-report.json
```

The installed hook command, the standalone hook default, and this report command all use `~/.gemini/semgate-shadow-v4.jsonl`. Direct invocation of `semgate_shadow_hook.py` honors a `SEMGATE_SHADOW_LOG` override. Installed hooks instead set the log path explicitly in their command (a leading assignment on POSIX, `--log` on Windows), so an inherited `SEMGATE_SHADOW_LOG` does not redirect an installed hook: change that assignment in both installed hook entries (BeforeTool and Notification) to use a custom location. Reinstalling restores the default assignments, so reapply custom-path edits afterward. Report against the file your configuration actually writes. In the default workflow the legacy `semgate-shadow.jsonl` is preserved as history and never appended to; a deliberately configured custom path is your own choice and may use any filename. If your telemetry `outfile` is customized, use that path for `--telemetry`.

Gemini's local exporter writes concatenated pretty JSON. The parser reads the full file and decodes successive values; malformed input fails with a **character** offset. It ignores unsupported structured records. The report uses candidate associations only. It does not select name+args matches or claim per-call outcomes, even when session IDs agree. Exact prompt reduction remains `not_computable_without_stable_cross_surface_identity_and_coverage`.

`measurement_status` describes whether proposals and telemetry were present, never that the collection is complete. A lack of permission notifications can mean no confirmations occurred or collection was incomplete. `logPrompts` defaults to false only when absent; existing values are preserved.

## Privacy

Shadow logs, report files, settings backups, and staged settings use private POSIX modes. Notification logs keep bounded metadata and hashes, omitting diffs/original/new content and free-form messages. Tool inputs, trusted context, and optional external Jev state are redacted, but secrets can still evade pattern-based filtering. Gemini's telemetry file creation is controlled by Gemini; this installer only tightens an existing file. Choose retention deliberately and keep SDK wire/debug logging off around private state.

## Upgrade from v2/v3

v4 writes to `~/.gemini/semgate-shadow-v4.jsonl`; it never appends to the old `semgate-shadow.jsonl`. Preserve the old file as history. The v4 reporter counts any legacy records supplied to it but excludes them from calculations and never re-exports legacy notification bodies. Do not concatenate schemas for measurement. An explicit offline migration adapter would be needed to normalize old embedded evaluations; none is claimed here.

The report reconciles v4 proposal/evaluation identities by a validated `(session_id, event_id)` key: paired IDs, missing evaluations, orphan evaluations, duplicate IDs, records without IDs, and records whose IDs are present but unusable (null, non-string, empty, or whitespace-only `event_id`, or a missing/blank `session_id`). Invalid records are counted separately from missing, orphan, and duplicate records, and never form pairs. Any mismatch changes status to `incomplete_shadow_event_pairs`. Candidate telemetry indexes refer to the filtered telemetry-with-args sequence and are diagnostic only.

`shadow_evaluation_status_counts` reports captured evaluations by status (for example `ok`, `skipped_fast_path`, `disabled`, `blocked_by_explicit_constraint`, `unscorable_missing_trusted_context`, `unscorable_unpinned_model`, or `error`). It describes evaluator health separately from capture health: a captured, well-formed pair can still carry a disabled, unscorable, or failed evaluation. Capture completeness and evaluator health are different things; neither is an approval-safety metric.

## Credentials and preflight

Set `TYPESAFE_API_KEY` in the effective Gemini hook environment when Jev mode is enabled. Run `python3 preflight.py` in that same environment; it reports only booleans, never a key value. Whitespace-only values are treated as absent, matching the SDK, which ignores empty or whitespace-only environment values. Preflight also reports readiness fields (`typesafe_sdk_available`, `effective_session_id_configured`, `trusted_context_json_valid`, `trusted_context_session_usable`); its exit code still gates only on presence, pinned model, and readability, so exit 0 is not proof of authentication, SDK reachability, or a usable trusted context. Do not use the exit code alone as the go/no-go signal for a Jev experiment (`python3 preflight.py && ./start_experiment` is wrong): inspect the readiness fields, confirm the installed SDK version matches the pin in `requirements.txt`, and verify an actual non-fast-path evaluation has returned status `ok` in the shadow log before trusting a trial. `typesafe_sdk_available` checks module discoverability only, not a successful import, the pinned version, or network reachability. Gemini v0.60.0 returns the process environment unchanged when environment redaction is disabled and strict GitHub mode is absent. When redaction is enabled, or in strict GitHub mode, key-like variables including `TYPESAFE_API_KEY` may be stripped. Do not disable secret protections broadly to work around this.

## Uninstall and rollback

Restore the private `settings.json.backup-<uuid>` you want, or remove only hook entries whose `name` is `semgate-shadow` from `BeforeTool` and `Notification`, then restart Gemini CLI. Installed hooks are versioned and unreferenced older copies are intentionally retained for rollback. Delete an unreferenced version only after checking the active command in settings. Logs and reports are not deleted automatically.
