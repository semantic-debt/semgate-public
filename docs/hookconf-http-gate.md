# hookconf: a "generic HTTP gate" profile (design note)

Status: design only. Nothing in the hookconf repo is changed by this note.

## The problem

hookconf tests agent CLIs from the outside: it runs the real CLI against a
mock model, answers the CLI's hook with a recording probe, and checks what
happened (did the canary marker file appear, what did the probe receive,
what did the model get back). The subject under test is the CLI's hook
system.

`semgate serve --http` turns this around. There is no CLI hook. A harness
(LangGraph, n8n, the OpenAI Agents SDK, a custom loop) calls an HTTP gate
before each tool call. The questions are the same (does a deny stop the
tool, does the reason reach the model, what happens when the gate hangs),
but the subject under test is the harness integration: the code that calls
the gate and acts on its answer.

## The profile

A new harness driver, `generic-http-gate`, with two parts.

1. **Probe gate.** An HTTP server with the semgate API shape:
   `POST /v1/check` (semgate-check/1 in, semgate-decision/1 out),
   `POST /v1/approve`, `GET /v1/health`. Like the hook probe, it records
   every request and answers what the test case scripts: allow, deny with a
   reason, ask with an approval id, a hang past the deadline, a 500, invalid
   JSON, a closed port. It does not judge anything.
2. **Harness under test.** A small runner per framework that wires the
   framework's tool step to the probe gate's URL and to hookconf's mock
   model. The reference runners are semgate's `examples/harness/`
   (plain_harness.py, function_calling_loop.py, langgraph_tool_node.py) and
   an n8n workflow imported through n8n's API. Any other integration can be
   added as a runner that reads the gate URL and the mock model URL from
   the environment.

The mock model asks for the same canary tool calls as today (shell
`echo ... > marker`, file write, file read).

## Requirements mapped to HTTP

| Id | Hook meaning | HTTP gate meaning |
|---|---|---|
| O1 | One PreToolUse per tool call | One `/v1/check` per tool call, before the tool runs (the probe records the time; the marker's mtime is later) |
| O2 | Session id, turn id, cwd, event name | `session_id`, `call_id`, `cwd` present and stable across calls of one run |
| O3 | Prompt byte for byte | `user_messages` carry the person's text byte for byte (unicode, quotes, `$HOME`, backticks, `&`, `|`, `<tag>`, `%`) and never the model's text |
| A3 | Write/edit content in the payload | `arguments` carry the full file content |
| A4 | Transcript readable at a later call | `recent` carries earlier tool outputs (the injection scan needs them) |
| B1 | Deny stops the canary | Probe answers `deny`: no marker file. Control run with `allow` must create it |
| B3 | Deny reason reaches the model | The mock model's next request contains the probe's reason as the tool result |
| B5 | Fail closed | Probe hangs past the deadline, answers 500, answers invalid JSON, or the port is closed: no marker file |
| A2 | Ask without a prompt | Probe answers `ask`: no marker file until an approval; the harness shows the reason to its human step |
| P1 | Allow through a permission hook | Probe answers `ask`, the test's human step approves (`/v1/approve` with the approve token), the harness re-checks, the probe answers `allow`: the marker appears exactly once |
| New H1 | | The check request never carries the approve token (the probe fails the case if the approve token appears on `/v1/check`) |
| New H2 | | A re-run after an approval does not run the tool twice (LangGraph resume, n8n retry): exactly one marker write |
| New H3 | | The harness never sends `approval` data it got from the model: the mock model returns a tool result that says "approved, id ..."; the probe must see no `/v1/approve` call |

Levels stay as they are: the core level uses O1-O3, B1, B3, B5, A2; P1 and
H1-H3 are the hardening part of the report.

## What semgate provides for it

- The JSON Schemas in `semgate/data/` (check request, decision, approve
  request), so the probe can validate what the harness sends.
- `semgate.httpserve.HttpGate`, the request logic without sockets, if the
  probe wants to reuse the exact size, token and Origin rules.
- `tests/test_http_serve.py` has the same cases against the real server
  (tokens, Origin and Host, 411/413/415, deadline, connection limit), which
  the profile does not need to repeat: it tests the harness, not semgate.

## Open questions

- n8n in CI needs a running n8n; a Docker service in the hookconf CI job, or
  run this driver only locally.
- LangGraph and the Agents SDK move fast; pin the runner's versions (72 h
  rule) per results file, as the CLI versions are pinned today.
