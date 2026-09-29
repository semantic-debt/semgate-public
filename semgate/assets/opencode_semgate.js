// semgate plugin for OpenCode (V1 >= 1.18.29 and V2), Apache-2.0.
//
// Every tool call (bash, edit, write, read, webfetch, ...) is judged by
// semgate before it runs. One long-running `python -m semgate.serve --stdio`
// process is started on first use and reused, so each call costs one JSON
// line, not a Python start-up.
//
// allow -> the call runs.  deny / ask -> the call is refused with the reason,
// which the model sees. OpenCode has no reliable native "ask" from a plugin
// (V1: permission.ask is never called; V2: effect "ask" is ignored, #47495),
// so an ask is refused with an explanation the agent can relay to the user.
// Timeouts and crashes answer "ask" (refused), never "allow".
//
// serve judges several calls at once and answers each by id. It answers
// "ask" itself shortly before TIMEOUT_MS (it gets timeout_ms with each call).
// After RESTART_AFTER timeouts in a row the plugin stops that serve process
// and starts a new one on the next call (a hung model call cannot block
// every later call). A late answer from an old process is ignored: each
// process has its own table of open calls.
//
// After a tool runs (V1 tool.execute.after), the plugin sends the output to
// serve and waits at most AFTER_WAIT_MS for the answer. When the output showed
// a secret (semgate.exposures), the answer carries a notice; the plugin
// appends it to the output the model reads. semgate stores only a masked
// preview and a sha256 of the secret, never the value.
//
// Hot reload: serve watches its own code. When semgate is updated, serve
// sends one line {"id": null, "reload": true}; the plugin then sends every
// later call to a new serve and closes the old one's input. The old process
// still answers every call it already has, so no call is lost or refused
// because of the update. The plugin says it can do this with `client` in
// every request ({ stamp: ASSET, reload: 1 }). This file itself is loaded by
// OpenCode once: `semgate init opencode --refresh` rewrites it, and OpenCode
// must restart to load the new copy (`semgate doctor` says when).
//
// Written by `semgate init opencode`, which fills in the two paths below and
// the stamp (first line and ASSET: the sha256 of the source asset). The
// interpreter and the config are fixed here: no environment variable changes
// them (a variable of OpenCode's environment must not choose the program the
// plugin runs or the config that judges). `semgate init opencode --refresh`
// rewrites them. SEMGATE_TIMEOUT_MS / SEMGATE_RESTART_AFTER /
// SEMGATE_AFTER_WAIT_MS still set the timing: a short value only refuses more.
//
// Proxy and CA variables: OpenCode removes HTTP_PROXY / HTTPS_PROXY / NO_PROXY
// from the environment of the processes it starts (it keeps only all_proxy).
// Without them, serve's call to the judge fails behind a proxy and every
// judged call asks. The plugin copies these variables (every spelling that is
// set, upper or lower case) from its own environment when it loads and passes
// them explicitly to serve: PROXY_ENV_NAMES below.

import { spawn } from "node:child_process"
import { createHash } from "node:crypto"
import { createInterface } from "node:readline"

const PYTHON = "__SEMGATE_PYTHON__"
const CONFIG = "__SEMGATE_CONFIG__"
const TIMEOUT_MS = Number(process.env.SEMGATE_TIMEOUT_MS || 20000)
const RESTART_AFTER = Math.max(1, Number(process.env.SEMGATE_RESTART_AFTER || 3))
const AFTER_WAIT_MS = Math.max(0, Number(process.env.SEMGATE_AFTER_WAIT_MS || 2000))
const MAX_MESSAGES = 30
const ASSET = "__SEMGATE_ASSET__"
const CLIENT = { stamp: ASSET, reload: 1 }

export const PROXY_ENV_NAMES = ["HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "ALL_PROXY",
                                "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE", "NODE_EXTRA_CA_CERTS"]

// The proxy and CA variables set in `env`, with the spelling they have there
// (HTTPS_PROXY and https_proxy are both kept when both are set).
export function proxyEnv(env) {
  const wanted = new Set(PROXY_ENV_NAMES)
  const out = {}
  for (const key of Object.keys(env || {})) {
    const value = env[key]
    if (wanted.has(key.toUpperCase()) && typeof value === "string" && value !== "") out[key] = value
  }
  return out
}

const PROXY_ENV = proxyEnv(process.env)   // captured once, when OpenCode loads the plugin

// The environment serve starts with: the current one plus the captured proxy
// and CA variables.
export function serveEnv(current = process.env, captured = PROXY_ENV) {
  return { ...current, ...captured }
}

let current = null            // { proc, pending: Map(id -> { resolve, timer }) }
let nextId = 1
let timeoutsInARow = 0

function start() {
  const proc = spawn(PYTHON, ["-m", "semgate.serve", "--stdio", "--config", CONFIG], { stdio: ["pipe", "pipe", "inherit"], env: serveEnv(), windowsHide: true })
  const state = { proc, pending: new Map() }
  current = state
  // A write after serve exited fails here; the exit handler answers "ask".
  proc.stdin.on("error", () => {})
  const rl = createInterface({ input: proc.stdout })
  rl.on("line", (line) => {
    let msg
    try { msg = JSON.parse(line) } catch { return }
    if (msg && msg.reload === true && msg.id === null) { retire(state); return }
    const waiter = state.pending.get(msg.id)
    if (waiter) {
      state.pending.delete(msg.id); clearTimeout(waiter.timer)
      waiter.resolve(msg)
      if (msg.timeout) noteTimeout()               // serve's own deadline answer ("ask")
      else if (msg.decision !== undefined) timeoutsInARow = 0
    }
  })
  const fail = (why) => {
    for (const [, waiter] of state.pending) { clearTimeout(waiter.timer); waiter.resolve({ decision: "ask", reason: why }) }
    state.pending.clear()
    if (current === state) current = null
  }
  proc.on("exit", (code) => fail(`semgate process exited (code ${code})`))
  proc.on("error", (err) => fail(`semgate could not start: ${err.message}`))
  return state
}

// serve's code changed: later calls go to a new serve; this one answers the
// calls it has and exits when its input closes.
function retire(state) {
  if (current === state) current = null
  try { state.proc.stdin.end() } catch { /* already closed */ }
}

function noteTimeout() {
  timeoutsInARow += 1
  if (timeoutsInARow >= RESTART_AFTER) {
    timeoutsInARow = 0
    restart(`semgate restarted after ${RESTART_AFTER} timeouts in a row`)
  }
}

function restart(why) {
  const state = current
  if (!state) return
  current = null                // the next call starts a new serve
  for (const [, waiter] of state.pending) { clearTimeout(waiter.timer); waiter.resolve({ decision: "ask", reason: why }) }
  state.pending.clear()
  try { state.proc.kill() } catch { /* already gone */ }
}

export function judge(request) {
  const state = current || start()
  const id = nextId++
  return new Promise((resolve) => {
    const timer = setTimeout(() => {
      state.pending.delete(id)
      resolve({ decision: "ask", reason: `semgate did not answer within ${TIMEOUT_MS} ms` })
      noteTimeout()
    }, TIMEOUT_MS)
    state.pending.set(id, { resolve, timer })
    try {
      state.proc.stdin.write(JSON.stringify({ id, host: "opencode", timeout_ms: TIMEOUT_MS, client: CLIENT, request }) + "\n")
    } catch (err) {
      state.pending.delete(id); clearTimeout(timer)
      resolve({ decision: "ask", reason: `semgate write failed: ${err.message}` })
    }
  })
}

// Post-tool event: records (files the agent created, scripts that changed
// after the decision, the tool output). Resolves with serve's answer, or null
// after AFTER_WAIT_MS. Never throws, never rejects.
export function recordAfter(request) {
  return new Promise((resolve) => {
    let state = null, id = 0, timer = null
    try {
      state = current || start()
      id = nextId++
      timer = setTimeout(() => { state.pending.delete(id); resolve(null) }, AFTER_WAIT_MS)
      state.pending.set(id, { resolve, timer })
      state.proc.stdin.write(JSON.stringify({ id, host: "opencode", event: "after", client: CLIENT, request }) + "\n")
    } catch {
      /* recording must never break the agent loop */
      if (state) { state.pending.delete(id); clearTimeout(timer) }
      resolve(null)
    }
  })
}

// The secret exposure notice from serve's answer, appended to the text the
// model reads (output.output). Nothing else in the output changes.
export function appendNotice(output, answer) {
  if (answer && typeof answer.notice === "string" && answer.notice && output && typeof output.output === "string") {
    output.output = output.output + "\n\n" + answer.notice
  }
}

export function enforce(verdict) {
  if (verdict && verdict.decision === "allow") return
  const reason = (verdict && verdict.reason) || "no reason"
  if (verdict && verdict.decision === "deny") throw new Error(`semgate blocked this: ${reason}`)
  throw new Error(
    `semgate needs a human decision before this runs: ${reason}. ` +
    `Tell the user plainly what this does and why. They can approve this exact command in their own terminal ` +
    `with: semgate feedback allow "<command>". Do not try to bypass the gate.`)
}

async function v1Messages(client, sessionID) {
  try {
    const res = await client.session.messages({ path: { id: sessionID } })
    const list = Array.isArray(res) ? res : (res && res.data) || []
    return list.slice(-MAX_MESSAGES)
  } catch { return [] }
}

// V2 ctx.session.context() resolves to the array of session messages after
// the latest compaction, in the server's order (the API unwraps {data}). A
// user message's attachments hold their bytes (base64, up to 20 MB each):
// only name and type are sent, so the request line stays small.
function slimV2(m) {
  if (!m || typeof m !== "object" || m.type !== "user" || !Array.isArray(m.files)) return m
  return { ...m, files: m.files.map((f) => ({ name: f && f.name, mime: f && f.mime })) }
}

async function v2Messages(ctx, sessionID) {
  try {
    const res = await ctx.session.context({ sessionID })
    const list = Array.isArray(res) ? res : (res && (Array.isArray(res.data) ? res.data : res.messages)) || []
    return list.slice(-MAX_MESSAGES).map(slimV2)
  } catch { return [] }
}

// Approval by chat reply on V2 (semgate/chatapproval.py). The session
// "prompt" hook runs inside OpenCode's Session.prompt, before the prompt is
// admitted: for text typed in the TUI / app, a command the user ran, and a
// subagent's prompt to its child session. The plugin keeps, per session, the
// message id, the time it saw the prompt (this clock = serve's clock) and a
// sha256 of the text. serve counts a history user message as a user turn only
// when its id is here, its text still has this hash and this time is after
// the block. Child sessions (parentID set: a subagent) never send `prompts`,
// so a block there is never approvable in chat.
const PROMPTS_KEPT = 50
const SESSIONS_KEPT = 200
const prompted = new Map()    // sessionID -> [{ id, t, sha }]
const sessionKind = new Map() // sessionID -> "root" | "child"

function remember(map, key, value) {
  map.delete(key); map.set(key, value)
  while (map.size > SESSIONS_KEPT) map.delete(map.keys().next().value)
}

// Never throws: OpenCode treats a failing session hook as a defect.
export function notePrompt(event, now = Date.now()) {
  try {
    const sessionID = event && event.sessionID
    const id = event && event.messageID
    const text = event && event.prompt && event.prompt.text
    if (typeof sessionID !== "string" || typeof id !== "string" || typeof text !== "string") return
    const list = prompted.get(sessionID) || []
    list.push({ id, t: now, sha: createHash("sha256").update(text, "utf8").digest("hex") })
    if (list.length > PROMPTS_KEPT) list.splice(0, list.length - PROMPTS_KEPT)
    remember(prompted, sessionID, list)
  } catch { /* recording must never break the prompt */ }
}

async function isRootSession(ctx, sessionID) {
  const known = sessionKind.get(sessionID)
  if (known) return known === "root"
  try {
    const res = await ctx.session.get({ sessionID })
    const info = res && res.id === sessionID ? res : res && res.data
    if (!info || info.id !== sessionID) return false
    remember(sessionKind, sessionID, info.parentID ? "child" : "root")
    return !info.parentID
  } catch { return false }
}

export default {
  id: "semgate",
  // OpenCode V2 calls setup(); V1 (>= 1.18.29) calls server().
  async setup(ctx) {
    let promptHook = false
    if (ctx.session && typeof ctx.session.hook === "function" && typeof ctx.session.get === "function") {
      try { await ctx.session.hook("prompt", (event) => { notePrompt(event) }); promptHook = true } catch { promptHook = false }
    }
    await ctx.tool.hook("execute.before", async (event) => {
      const request = {
        api: "v2", tool: event.tool, args: event.input, sessionID: event.sessionID, callID: event.id,
        cwd: process.cwd(), messages: await v2Messages(ctx, event.sessionID),
      }
      if (promptHook && await isRootSession(ctx, event.sessionID)) {
        request.prompts = (prompted.get(event.sessionID) || []).map((p) => ({ ...p }))
      }
      enforce(await judge(request))
    })
  },
  async server({ client, directory }) {
    return {
      "tool.execute.before": async (input, output) => {
        enforce(await judge({
          tool: input.tool, args: output.args, sessionID: input.sessionID, callID: input.callID,
          cwd: directory, messages: await v1Messages(client, input.sessionID),
        }))
      },
      // output.output is the text the model sees (hookconf M1). It is sent so
      // the next call's judge sees it even when session.messages() does not
      // hold it yet; capped at 256 KiB (semgate keeps 64 KiB).
      "tool.execute.after": async (input, output) => {
        const text = output && typeof output.output === "string" ? output.output.slice(0, 262144) : undefined
        const answer = await recordAfter({ sessionID: input.sessionID, callID: input.callID, tool: input.tool, args: input.args,
                                           ...(text === undefined ? {} : { output: text }) })
        appendNotice(output, answer)
      },
    }
  },
}
