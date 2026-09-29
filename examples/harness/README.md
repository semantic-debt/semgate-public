# semgate in your own harness: examples

Every example does the same thing for each tool call the model proposes:

1. Send the call to semgate (`semgate.check` in Python, or `POST /v1/check`).
2. `allow`: run the tool.
3. `deny`: do not run it. Give semgate's `reason` to the model as the tool result.
4. `ask`: show `reason` to a person. Record their answer with the
   `approval_id` (`semgate.approve`, or `POST /v1/approve`). Check the same
   call again. Run it only if the answer is now `allow`.

An approval works once, for the exact same call, in the same session and
project, for at most 4 hours. A "no" blocks that exact call in that session.

The shared loop is `semgate.client.guard` (and `resolve` for the second
half). It has no framework imports and is tested in
`tests/test_harness_examples.py`.

| File | What it shows |
|---|---|
| `plain_harness.py` | A plain Python agent session, in-process or over HTTP. Asks in the terminal. |
| `function_calling_loop.py` | A generic function-calling loop (OpenAI chat completions style), plus the OpenAI Agents SDK pattern in its docstring. |
| `langgraph_tool_node.py` | A LangGraph node that replaces `ToolNode`: `ask` becomes `interrupt()`, the resume value is the person's answer. Tested with langgraph 1.2.12 (langgraph is not a semgate dependency; its test is skipped when it is not installed). |
| `n8n/semgate-approval.workflow.json` | An n8n workflow: HTTP check, IF on the decision, Wait for approval, HTTP approve, HTTP re-check. |
| `curl.sh` | The HTTP round trip with curl. |

## Setup

```bash
pip install semgate                    # in a venv
semgate harness init --purpose "Software development in ~/code/app: read, edit, build, test"
semgate serve --http --token-file ~/.semgate/http/check.token --approve-token-file ~/.semgate/http/approve.token
```

`semgate harness init` writes four files into `~/.semgate/http/`:
`semgate.json`, `grant.json`, `check.token` and `approve.token`.

- `check.token` is for the agent side: the code that sends tool calls.
- `approve.token` is for the human side only: the code that receives a
  person's yes or no. Never give it to the agent, and never put it where the
  agent's tools can read it. semgate asks a human when an agent command
  touches `/v1/approve`, calls `semgate ... approve(`, or reads a
  `~/.semgate/.../*.token` file (human gate `semgate_approval`).

## curl

```bash
bash examples/harness/curl.sh
```

## n8n

1. In n8n, import `n8n/semgate-approval.workflow.json` (Workflows, Import from file).
2. Create two credentials of type **Header Auth**:
   - `semgate check token`: name `Authorization`, value `Bearer <contents of check.token>`.
   - `semgate approve token`: name `Authorization`, value `Bearer <contents of approve.token>`.
   Select them in the three HTTP Request nodes (check and re-check use the
   check token; approve uses the approve token).
3. If n8n runs in Docker, `127.0.0.1` is the container. Run semgate on the
   host with `--host` set to an address the container can reach, plus
   `--allow-remote` and `--token-file` (semgate refuses a non-loopback
   address without both). Put a TLS proxy in front if the traffic leaves the
   machine.
4. Replace the node **Tool call** with your agent's tool step, and the two
   **Run tool** nodes with the steps that really run the tool.
5. Replace **Send approval request** with Slack, email or a form. Send the
   person semgate's `reason` and the resume URL (`$execution.resumeUrl`).
   The person's answer is a POST to that URL with
   `{"approved": true, "by": "<name>"}` (or `false`).
6. On the **Wait for approval** node, turn on Authentication, so only the
   approver can resume it, and set a time limit shorter than 4 hours.

The tool nodes sit only behind an IF that tests `decision == "allow"`. If
semgate cannot be reached, the HTTP Request node fails and the workflow
stops, so the tool does not run.

## What the model sees

On `deny` (or a "no"), the tool result is text like:

```
semgate blocked this tool call (hard_deny): semgate enforce: hard_rules/deny [hard_deny]; hard_deny: matches deny pattern: 'rm -rf /' | Semgate blocked this. ...
```

Put the tool result in `recent` on the next check (with the tool's output);
semgate removes its own messages from it before it scans outputs.
