# Gemini v2 foundation: no-fork, one-shot review

**Experimental, disabled by default. Not production enforcement.**
This is the first implementation slice after the v2 review. It does not change `main`, the legacy Antigravity integration or the old Gemini hook. Do not run the old and new Gemini hooks together and assume their decisions compose safely.

## What ships in this slice

- `semgate/action_identity.py`: `semgate-action/2` correlation identity. It preserves case, quoted whitespace, list order and all arguments, with explicit host/session/cwd/shell, grant and policy/provider binding.
- `semgate/gemini_gate.py`: strict `BeforeTool` shell gateway using the existing Python judge. No TypeScript fork.
- Unit/contract tests, real-engine tests and a native Windows/Linux Python CI matrix.

A **digest is not an approval capability**. It does not authenticate the operator, freeze referenced files, capture every ambient environment change, or bind a future UI response to a pending host call. No stored identity grants permission in this slice. Legacy feedback/history keys are neither read nor migrated. Their existing behavior elsewhere in Semgate is unchanged and still needs a separate migration.

## Decision mapping

| Semgate result | Gateway output |
|---|---|
| Hard-rule denial | `deny`; no approval option requested |
| Expired/invalid grant, missing evidence, provider error or malformed output | `deny` |
| Semantic deny/ask or human gate | `ask` only when the explicit confirmation probe is enabled; otherwise `deny` |
| Semantic or deterministic allow | Still `ask` in the probe; never native `allow` |
| Legacy learned/feedback stage or unsupported tool/arguments | Reject; no pass-through |

The gateway never executes a proposed action, writes a standing native permission, records a feedback approval, or caches a model result. It does not infer approval from an AfterTool event. The host owns its pending call and the proceed-once interaction.

The conservative default is intentional: until `host DENY + hook ASK`, failure semantics and argument rewriting are tested, enabling this in a real project would be premature. Host confirmation may offer broader options; choose **proceed once only**, and inspect that no standing rule was created. This gateway cannot constrain the host UI's other buttons.

## Install into a trusted environment

Use a complete checkout of the implementation branch and an operator-controlled Python environment outside the disposable agent workspace:

```powershell
py -3.12 -m venv C:\SemgateTrusted\venv
C:\SemgateTrusted\venv\Scripts\python.exe -m pip install -e "C:\SemgateTrusted\semgate[dev]"
C:\SemgateTrusted\venv\Scripts\python.exe -m pytest C:\SemgateTrusted\semgate\tests\test_gemini_foundation.py C:\SemgateTrusted\semgate\tests\test_gemini_foundation_integration.py -q
```

Replace the paths with actual directories. Installing outside the workspace is hygiene, **not OS access separation**: an unsandboxed agent with the same user privileges may still modify those files. Do not claim operator-only writes until a broker or equivalent OS-enforced boundary is designed and tested.

Create `config.json`, `grant.json` and the policy outside the disposable workspace. All configured paths must be absolute and exist. JSON may contain a UTF-8 BOM (PowerShell tooling); command strings are never stripped or case-folded.

Example config (edit the paths and shell to match the installed host):

```json
{
  "schema": "semgate-gemini-config/1",
  "project_root": "C:/SemgateProbe",
  "grant_file": "C:/SemgateTrusted/grant.json",
  "policy_file": "C:/SemgateTrusted/semgate/policies/default_policy.json",
  "shell": "powershell",
  "harness_version": "v0.60.0",
  "provider": "none",
  "deadline_seconds": 5,
  "confirmation_probe": false
}
```

Create the grant in your own terminal, with an explicit one-hour lifetime:

```powershell
$root = (Resolve-Path C:\SemgateProbe).Path
@{
  grant_id = [guid]::NewGuid().ToString()
  principal = $env:USERNAME
  purpose = 'Run harmless one-shot confirmation probes in this disposable workspace'
  allowed_tools = @('bash')
  allowed_path_prefixes = @($root)
  expires_at = [DateTimeOffset]::UtcNow.AddHours(1).ToString('o')
  provenance = 'operator-authored probe grant'
} | ConvertTo-Json | Set-Content -Encoding utf8 C:\SemgateTrusted\grant.json
```

`bash` is Semgate's existing canonical shell-tool name; it does **not** launch bash or establish the actual Windows shell. The configured shell/version are operator declarations which the host probe must verify. Grants missing expiry, expired grants, and grants more than 24 hours into the future are rejected.

## First native-host probe

1. Record `gemini --version` and the actual shell. Use a disposable workspace with no secrets, credentials or valuable files.
2. Keep the normal host permission system active. Do not add broad allow rules or use YOLO to manufacture live auto-allow.
3. Register the gateway as a BeforeTool hook with the actual absolute Python path, using the host's documented configuration. Example command for a no-spaces path:

   ```text
   C:\SemgateTrusted\venv\Scripts\python.exe -I -m semgate.gemini_gate --config C:\SemgateTrusted\config.json
   ```

   Use a match-all hook only in this disposable workspace: unsupported tools deliberately deny. Set the outer hook timeout above the internal worker budget (for example, 10000 ms versus a 5-second worker deadline). That margin is a probe configuration, not a measured latency guarantee.

4. Confirm that with `confirmation_probe: false` the gateway refuses execution. Then explicitly set it to `true` for the supervised test. No normal runtime configuration is modified by this code or installer.
5. Request a harmless command such as `Write-Output 'SEMGATE_PROBE_A'`. Confirm the reason appears, rejection prevents execution, and proceed-once executes only that pending action. A variation must prompt again. `provider: none` exercises the existing judge's abstention, not a fake clearance model.
6. Perform the precedence/failure matrix in `integrations/gemini-cli-fork/FINDINGS.md` before using the probe anywhere else. Keep the result NO-GO if any path runs without judgment or weakens a host denial.

The hook payload's own `grant`, `provider`, `feedback` or model-written approval claims are never used as authorization. This slice rejects `dir_path` overrides, background execution, additional permissions and unknown shell arguments rather than guessing their semantics. Shell-internal `cd`, environment changes, script file contents and filesystem races are not solved by the request hash; every action still receives human review.

## Optional live judging, still no auto-allow

The existing TypeSafe adapter may be selected in the trusted config with `provider: typesafe` and an explicit `model`. Install the existing optional SDK and provide `TYPESAFE_API_KEY` via the operator environment. No API key is needed for offline tests or the initial host probe, and no live request was made in preparing this slice. Pin the provider/model and characterize SDK retries before relying on latency numbers.

The parent uses its own `sys.executable`, fixed arguments, `-I`, JSON stdin and `shell=False`. The proposed command never enters the subprocess command line. Provider output is captured separately; invalid/oversized child output, child failure, worker timeout, cancellation and handled parser/config errors produce valid denial JSON and exit 2. Grant expiry is rechecked after the model call.

The worker deadline does **not** prove handling of a killed/unlaunchable parent, a host that disables hooks, a blocked filesystem, every descendant process, or the whole native host's cancellation semantics. These remain runtime/OS test obligations. Identity correlation is not execution-time revalidation after the human spends time at a prompt.

## Tests and remaining work

```powershell
py -m pytest tests/test_gemini_foundation.py tests/test_gemini_foundation_integration.py -q
py -m pytest tests/ --ignore=tests/tests -q
```

The `Gemini v2 foundation` workflow runs new contract/real-engine tests on Linux and Windows, Python 3.9 and 3.12, and the complete existing suite on Linux/Python 3.12. It has read-only repository permissions, no checkout credentials persisted and no model credentials supplied. Check actual workflow results; a matrix definition is not a test pass. Full legacy-suite compatibility on native Windows and Gemini UI end-to-end execution are separate open gates.

Next implementation slice: prove host precedence and failure behavior, then design a trusted pending-call approval receipt with one-shot consumption, expiry and execution-time revalidation. Only after that evaluate live auto-allow. Do not add a second `ask` implementation, a model cache, persistent approvals, a generic provider loader or the three-block display ahead of those gates.
