# Enforce sandbox

A throwaway Docker container that runs a small agent loop under Semgate in
**enforce** mode. Unlike Antigravity 1.2.7, which prompts even when a hook
returns `allow`, this loop obeys the gate directly:

- `allow` -> the command runs, in `/sandbox/workspace` inside the container
- `deny` -> the command never runs
- `ask` / `force_ask` -> held; runs only with `--interactive` and an operator yes

Because allowed commands really execute, run it **only in the container**, never
on the host.

Works the same with Docker or Podman; use whichever you have. The commands
below show `docker`; replace it with `podman` (same flags) on Podman hosts.

## Build

From the repo root (the build context must be the repo, not this folder):

```bash
docker build -f sandbox/Dockerfile -t semgate-sandbox .
# podman: podman build -f sandbox/Dockerfile -t semgate-sandbox .
```

## Run

Pass your Jev key at run time; it is never baked into the image. No host
directory is mounted, so the loop cannot touch your machine.

```bash
docker run --rm -e TYPESAFE_API_KEY="$TYPESAFE_API_KEY" semgate-sandbox
# podman: podman run --rm -e TYPESAFE_API_KEY="$TYPESAFE_API_KEY" semgate-sandbox
```

## Two enforce profiles

- `sandbox/semgate.enforce.json` (default): allow runs, deny is blocked,
  ask/force_ask is **held** for an operator. Use when a human is present.
- `sandbox/semgate.yolo.json`: adds `block_when_unsure`. Anything that is not a
  confident allow becomes a hard **deny**, so only clearly-benign commands run
  and everything uncertain or dangerous is blocked with no prompt. This is the
  profile for an auto-running ("YOLO") agent, where an `ask` would otherwise
  become a silent run. Select it with `--config /sandbox/semgate.yolo.json`.

On the example tasks the two profiles differ as expected: `enforce` runs 2,
holds 5, blocks 1; `yolo` runs the same 2 and blocks the other 6.

The image ships `tasks.example.jsonl`. To try your own commands, write a JSONL
file (one `{"command": "...", "user_message": "..."}` per line) and pass it:

```bash
docker run --rm -e TYPESAFE_API_KEY="$TYPESAFE_API_KEY" \
  -v "$PWD/my-tasks.jsonl:/sandbox/tasks.jsonl:ro" semgate-sandbox
```

## Check decisions without executing

`--dry-run` prints each gate decision and runs nothing. Safe anywhere:

```bash
docker run --rm -e TYPESAFE_API_KEY="$TYPESAFE_API_KEY" semgate-sandbox --dry-run
```

## What it uses

- Policy: `policies/router_policy_v3.json` (the router with the execution guard).
- Config: `sandbox/semgate.enforce.json` — `mode: enforce`, `auto_allow_tools: ["bash"]`
  so a router `allow` on a shell command actually runs, plus learned auto-allow.
- Grant: `sandbox/grant.json` — the operator purpose for the sandbox workspace.

## Limits

- Needs `TYPESAFE_API_KEY` for the Jev router; without it every decision falls
  back to `force_ask` (held).
- The container is the isolation boundary. Do not add a host bind mount of a real
  directory, and do not run `run_loop.py` outside a container without `--dry-run`.
- This does not run Antigravity. It proves the gate controls execution when the
  runner honours `allow`. Wiring the real agy subagent is a later step.
