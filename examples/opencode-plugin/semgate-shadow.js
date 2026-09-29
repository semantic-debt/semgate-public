// semgate shadow-mode plugin for OpenCode.
//
// OpenCode resolves every action against its `permission` config: static
// "allow" runs, static "deny" is blocked, everything else lands in the
// residual "ask" bucket and prompts the user. This plugin observes that
// bucket via the `permission.asked` event and asks semgate for a shadow
// judgment, which is appended to a local JSONL log.
//
// It NEVER calls permission.replied and never influences the host's
// decision. We judge. The host acts.
//
// Install: copy this file into .opencode/plugins/ inside a project that has
// semgate importable (pip install -e /path/to/semgate), and place a grant
// file at .opencode/semgate/grant.json (see README).

import { readFileSync, mkdirSync, appendFileSync } from "node:fs"
import { join } from "node:path"

export const SemgateShadow = async ({ directory }) => {
  const logDir = join(directory, ".opencode", "semgate")
  const logPath = join(logDir, "shadow-log.jsonl")
  const grantPath = join(logDir, "grant.json")

  return {
    event: async ({ event }) => {
      if (event.type !== "permission.asked") return
      let grant
      try {
        grant = JSON.parse(readFileSync(grantPath, "utf8"))
      } catch {
        return // no operator-supplied grant, no shadow judgment
      }
      const payload = JSON.stringify({
        event: event.properties ?? {},
        grant,
        cwd: directory,
      })
      try {
        const proc = Bun.spawn(
          ["python3", "-m", "semgate", "judge", "--adapter", "opencode", "--stdin", "--ledger", logPath.replace("shadow-log", "ledger")],
          { stdin: "pipe", stdout: "pipe", stderr: "pipe" },
        )
        proc.stdin.write(payload)
        proc.stdin.end()
        const decision = await new Response(proc.stdout).text()
        await proc.exited
        mkdirSync(logDir, { recursive: true })
        appendFileSync(logPath, JSON.stringify({
          ts: new Date().toISOString(),
          permission_event: event.properties ?? {},
          semgate: JSON.parse(decision),
        }) + "\n")
      } catch {
        // shadow mode never blocks the host on our own failure
      }
    },
  }
}
