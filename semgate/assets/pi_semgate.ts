// semgate extension for Pi 0.86.0. Installed as a tool-owned semgate.ts file.
// Every failed judgment, process error and timeout blocks the tool call.
// Hot reload: when semgate is updated, serve sends {"id": null, "reload": true};
// later calls go to a new serve, the old one answers what it has and exits
// when its input closes. `client` in every request says this extension can
// do that. Pi loads this file once: `semgate init pi --refresh` rewrites it,
// Pi must restart to load the new copy.
// The interpreter and the config are fixed here: no environment variable
// changes them (a variable of Pi's environment must not choose the program
// the extension runs or the config that judges). SEMGATE_TIMEOUT_MS still
// sets the timeout: a short value only refuses more.
import { spawn } from "node:child_process"
import { createInterface } from "node:readline"

const PYTHON = __SEMGATE_PYTHON__
const CONFIG = __SEMGATE_CONFIG__
const TIMEOUT_MS = Math.max(1000, Number(process.env.SEMGATE_TIMEOUT_MS || 20000))
const ASSET = __SEMGATE_ASSET__
const CLIENT = { stamp: ASSET, reload: 1 }

let current = null
let nextId = 1

function stop() {
  const state = current
  current = null
  if (!state) return
  for (const [, pending] of state.pending) {
    clearTimeout(pending.timer)
    pending.resolve({ decision: "ask", reason: "semgate serve stopped" })
  }
  state.pending.clear()
  try { state.proc.kill() } catch {}
}

function start() {
  const proc = spawn(PYTHON, ["-m", "semgate.serve", "--stdio", "--config", CONFIG],
    { stdio: ["pipe", "pipe", "inherit"], windowsHide: true })
  const state = { proc, pending: new Map() }
  current = state
  proc.stdin.on("error", () => {})   // a write after exit: the exit handler blocks the call
  createInterface({ input: proc.stdout }).on("line", line => {
    let answer
    try { answer = JSON.parse(line) } catch { return }
    if (answer && answer.reload === true && answer.id === null) {
      // serve's code changed: the next call starts a new serve
      if (current === state) current = null
      try { state.proc.stdin.end() } catch {}
      return
    }
    const pending = state.pending.get(answer.id)
    if (!pending) return
    state.pending.delete(answer.id)
    clearTimeout(pending.timer)
    pending.resolve(answer)
  })
  const fail = reason => {
    if (current === state) current = null
    for (const [, pending] of state.pending) {
      clearTimeout(pending.timer)
      pending.resolve({ decision: "ask", reason })
    }
    state.pending.clear()
  }
  proc.on("error", err => fail(`semgate could not start: ${err.message}`))
  proc.on("exit", code => fail(`semgate serve exited (code ${code})`))
  return state
}

function send(event, request) {
  const state = current || start()
  const id = nextId++
  return new Promise(resolve => {
    const timer = setTimeout(() => {
      state.pending.delete(id)
      resolve({ decision: "ask", reason: `semgate did not answer within ${TIMEOUT_MS} ms` })
      if (current === state) stop()
    }, TIMEOUT_MS)
    state.pending.set(id, { resolve, timer })
    try {
      state.proc.stdin.write(JSON.stringify({ id, host: "pi", event, timeout_ms: TIMEOUT_MS, client: CLIENT, request }) + "\n")
    } catch (err) {
      state.pending.delete(id)
      clearTimeout(timer)
      resolve({ decision: "ask", reason: `semgate request failed: ${err.message}` })
      if (current === state) stop()
    }
  })
}

function facts(event, ctx) {
  const sm = ctx.sessionManager
  const sessionID = sm.getSessionId()
  const entries = sm.getBranch()
  if (!sessionID || !Array.isArray(entries)) throw new Error("Pi session order is unavailable")
  return { sessionID, callID: event.toolCallId, tool: event.toolName,
    args: event.input, cwd: ctx.cwd, entries }
}

function outputText(content) {
  return (content || []).filter(x => x && x.type === "text").map(x => x.text).join("\n")
}

export default function (pi) {
  pi.on("tool_call", async (event, ctx) => {
    try {
      const answer = await send("before", facts(event, ctx))
      if (answer.decision === "allow") return
      return { block: true, reason: answer.reason || "semgate needs a human decision" }
    } catch (err) {
      return { block: true, reason: `semgate hook failure: ${err.message}` }
    }
  })

  pi.on("tool_result", async (event, ctx) => {
    try {
      const request = facts(event, ctx)
      request.output = outputText(event.content)
      request.error = event.isError ? "Pi tool error" : ""
      await send("after", request)
    } catch { /* post records cannot authorize a tool */ }
  })

  pi.on("session_shutdown", async () => { stop() })
}
