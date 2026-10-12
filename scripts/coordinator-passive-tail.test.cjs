const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const workflow = fs.readFileSync(path.join(__dirname, "../.github/workflows/coordinator-deploy.yml"), "utf8");
const marker = "          node --input-type=module <<'JS'\n";
assert.equal(workflow.split(marker).length, 2);
const source = workflow.split(marker)[1].split("\n          JS\n")[0].split("\n")
  .map(line => { assert.ok(line.startsWith("          ")); return line.slice(10); }).join("\n");
const ID = "a".repeat(32);
const VERSION = "12345678-1234-1234-1234-123456789abc";
const TOKEN = "SYNTHETIC_AUTH_VALUE";
const URL_VALUE = "wss://tail.developers.workers.dev/opaque?capability=PRIVATE_URL";
const event = {
  eventTimestamp: 1791767100000, outcome: "exception", scriptVersion: { id: VERSION, tag: "PRIVATE_TAG" },
  event: { request: { url: "https://private.invalid/PRIVATE_REQUEST" } },
  logs: [{ message: ["PRIVATE_LOG"] }],
  exceptions: [{ name: "TypeError", message: "PRIVATE_MESSAGE durable object reset during operation",
    stack: "PRIVATE_STACK\n at handler (/PRIVATE_PATH/fleet.ts:123:45)" }]
};
async function run(options = {}) {
  const calls = [], sockets = [], timers = [], output = [];
  const env = { GITHUB_REPOSITORY: "openclaw/crabbox", GITHUB_EVENT_NAME: "workflow_dispatch",
    GITHUB_REF: "refs/heads/ops/capacity-settings-20261011",
    GITHUB_WORKFLOW_REF: "openclaw/crabbox/.github/workflows/coordinator-deploy.yml@refs/heads/ops/capacity-settings-20261011",
    GITHUB_SHA: "b".repeat(40), GITHUB_WORKFLOW_SHA: "b".repeat(40), GITHUB_RUN_ATTEMPT: "1",
    CLOUDFLARE_API_TOKEN: TOKEN, ...options.env };
  let socketClose = 0;
  const response = value => new Response(JSON.stringify(value), { status: 200 });
  class FakeWebSocket {
    constructor(...args) {
      sockets.push(args); this.listeners = new Map(); this.closed = false; this.sent = [];
      queueMicrotask(() => {
        if (options.socketError) { this.emit("error", { message: "PRIVATE_ERROR" }); return; }
        if (options.openTimeout) {
          timers.find(t => t.ms === 15000 && t.active).fn(); return;
        }
        this.emit("open", {});
        for (const data of options.frames || [JSON.stringify(event)]) {
          if (this.closed) break;
          this.emit("message", { data });
        }
        const timer = timers.find(t => t.ms === 60000 && t.active);
        if (timer) timer.fn();
      });
    }
    addEventListener(name, fn) { this.listeners.set(name, fn); }
    emit(name, value) { this.listeners.get(name)?.(value); }
    send(raw) { this.sent.push(raw); calls.push({ socket_send: raw }); }
    close() { socketClose++; this.closed = true; this.emit("close", {}); }
  }
  const sandbox = {
    Buffer, URL, ArrayBuffer, Date, Set, JSON, Number, Error, Promise, crypto: require("node:crypto").webcrypto,
    AbortSignal, WebSocket: FakeWebSocket,
    process: { env, stdout: { write: raw => output.push(raw) } },
    setTimeout: (fn, ms) => { const t = { fn, ms, active: true }; timers.push(t); return t; },
    clearTimeout: t => { if (t) t.active = false; },
    fetch: async (url, init) => {
      assert.equal(init.redirect, "error");
      assert.equal(init.headers.Authorization, "Bearer " + TOKEN);
      assert.equal(url, "https://api.cloudflare.com/client/v4/accounts/91b59577e757131d68d55a471fe32aca/workers/scripts/crabbox-coordinator/tails" +
        (init.method === "DELETE" ? "/" + ID : ""));
      calls.push({ method: init.method, body: init.body });
      if (init.method === "POST") {
        if (options.createError) throw new Error("PRIVATE_CREATE_ERROR");
        if (options.denied) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "PRIVATE_HTTP_ERROR" }, { code: 999999, message: "PRIVATE_OTHER" }] }), { status: 403 });
        if (options.apiOversize) return new Response("X".repeat(128 * 1024 + 1));
        return response({ success: true, errors: [], result: { id: ID, url: URL_VALUE,
          expires_at: "2099-01-01T00:00:00Z", ...options.result } });
      }
      assert.equal(init.method, "DELETE");
      if (options.deleteError) throw new Error("PRIVATE_DELETE_ERROR");
      if (options.deleteDenied) return new Response(JSON.stringify({ success: false, errors: [{ code: 10000, message: "PRIVATE_DELETE_ERROR" }] }), { status: 403 });
      return response({ success: true, errors: [] });
    }
  };
  await vm.runInNewContext(source, sandbox, { timeout: 2000, filename: "reviewed-inline-tail.js" });
  assert.equal(output.length, 1);
  assert.ok(Buffer.byteLength(output[0]) <= 64 * 1024);
  for (const forbidden of [TOKEN, URL_VALUE, "PRIVATE_MESSAGE", "PRIVATE_STACK", "PRIVATE_PATH",
    "PRIVATE_REQUEST", "PRIVATE_LOG", "PRIVATE_TAG", "PRIVATE_ERROR", "PRIVATE_CREATE_ERROR", "PRIVATE_DELETE_ERROR",
    "PRIVATE_HTTP_ERROR", "PRIVATE_OTHER", ID])
    assert.ok(!output[0].includes(forbidden), forbidden);
  return { result: JSON.parse(output[0]), calls, sockets, socketClose, code: sandbox.process.exitCode };
}
test("real inline entry creates once, projects safe fields, closes and deletes exact ID", async () => {
  const r = await run();
  assert.equal(r.code, 0); assert.equal(r.result.status, "observed");
  assert.equal(r.result.create_attempts, 1); assert.equal(r.result.delete_attempts, 1);
  assert.equal(r.result.cleanup_confirmed, true); assert.equal(r.socketClose, 1);
  assert.deepEqual(r.calls.map(x => x.method || "send"), ["POST", "send", "DELETE"]);
  assert.equal(r.calls[0].body, "{}"); assert.equal(r.calls[1].socket_send, '{"debug":false}');
  assert.deepEqual(r.sockets, [[URL_VALUE, "trace-v1"]]);
  assert.deepEqual(r.result.events[0], { timestamp: new Date(event.eventTimestamp).toISOString(),
    outcome: "exception", script_version: VERSION,
    exceptions: [{ name: "TypeError", category: "durable_object_reset",
      frames: [{ source: "fleet.ts", line: 123, column: 45 }] }] });
});
test("wrong workflow identity refuses before creation", async () => {
  const r = await run({ env: { GITHUB_RUN_ATTEMPT: "2" } });
  assert.equal(r.result.reason, "workflow_identity"); assert.equal(r.calls.length, 0);
});
test("failed or oversized creation stays ambiguous and is never replayed", async () => {
  for (const options of [{ denied: true }, { createError: true }, { apiOversize: true }]) {
    const r = await run(options);
    assert.equal(r.result.create_attempts, 1); assert.equal(r.result.created, false);
    assert.equal(r.result.delete_attempts, 0); assert.equal(r.calls.length, 1);
    assert.equal(r.sockets.length, 0); assert.equal(r.result.status, "requires_reconciliation");
    if (options.denied) {
      assert.equal(r.result.create_http_status, 403);
      assert.deepEqual(r.result.create_error_codes, [10000]); assert.equal(r.result.create_other_error_count, 1);
    }
  }
});
test("unsupported or expired Tail preserves validated ID for one cleanup", async () => {
  for (const result of [{ url: "wss://unexpected.invalid/PRIVATE_URL" },
    { url: "wss://user:password@tail.developers.workers.dev/path" },
    { expires_at: "2001-01-01T00:00:00Z" }]) {
    const r = await run({ result });
    assert.equal(r.sockets.length, 0); assert.equal(r.result.created, true);
    assert.equal(r.result.delete_attempts, 1); assert.equal(r.result.cleanup_confirmed, true);
    assert.equal(r.calls.length, 2);
    if (result.expires_at) assert.equal(r.result.expires_at, result.expires_at.replace("Z", ".000Z"));
  }
});
test("event and incoming byte limits close without processing another event", async () => {
  const count = await run({ frames: Array(201).fill(JSON.stringify(event)) });
  assert.equal(count.result.events_seen, 200); assert.equal(count.result.reason, "event_limit");
  const bytes = await run({ frames: ["X".repeat(2 * 1024 * 1024 + 1)] });
  assert.equal(bytes.result.events_seen, 0); assert.equal(bytes.result.reason, "incoming_limit");
  for (const r of [count, bytes]) {
    assert.equal(r.socketClose, 1); assert.equal(r.result.delete_attempts, 1);
  }
});
test("malformed and unknown events never export arbitrary fields", async () => {
  const r = await run({ frames: ["PRIVATE_MALFORMED", JSON.stringify({ ...event,
    outcome: "PRIVATE_OUTCOME", scriptVersion: { id: "PRIVATE_VERSION" },
    exceptions: [{ name: "PRIVATE_CLASS", message: "PRIVATE_UNKNOWN", stack: "PRIVATE_SOURCE:3:4" }] })] });
  assert.equal(r.result.invalid_events, 1);
  assert.deepEqual(r.result.events[0].exceptions, [{ name: "unknown", category: "unknown", frames: [] }]);
  assert.equal(r.result.events[0].outcome, "unknown"); assert.equal(r.result.events[0].script_version, null);
  assert.ok(!JSON.stringify(r.result).includes("PRIVATE_"));
});
test("socket refusal or timeout still closes and deletes once", async () => {
  for (const options of [{ socketError: true }, { openTimeout: true }]) {
    const r = await run(options);
    assert.equal(r.result.status, "requires_reconciliation");
    assert.equal(r.result.cleanup_confirmed, true); assert.equal(r.socketClose, 1);
    assert.equal(r.result.delete_attempts, 1);
  }
});
test("uncertain delete preserves recovery facts and never retries", async () => {
  const r = await run({ deleteError: true });
  assert.equal(r.result.status, "requires_reconciliation");
  assert.equal(r.result.tail_fingerprint, require("node:crypto").createHash("sha256").update(ID).digest("hex"));
  assert.ok(!JSON.stringify(r.result).includes(ID)); assert.equal(r.result.cleanup_confirmed, false);
  assert.equal(r.result.delete_attempts, 1); assert.equal(r.calls.filter(x => x.method === "DELETE").length, 1);
});

test("coordinator runtime and auth frames retain only fixed basenames and positions", async () => {
  const r = await run({ frames: [JSON.stringify({ ...event, exceptions: [{ name: "Error",
    message: "PRIVATE_CONTEXT SQL error", stack: "PRIVATE_PATH/coordinator-runtime.ts:19:4\nPRIVATE_PATH/auth.ts:25:8" }] })] });
  assert.deepEqual(r.result.events[0].exceptions[0], { name: "Error", category: "sql",
    frames: [{ source: "coordinator-runtime.ts", line: 19, column: 4 }, { source: "auth.ts", line: 25, column: 8 }] });
});
test("safe output budget omits bounded projections and still deletes once", async () => {
  const large = { ...event, exceptions: Array(4).fill({ name: "AggregateError", message: "PRIVATE_MESSAGE memory",
    stack: "PRIVATE_PATH/coordinator-runtime.ts:1234567:1234567\nPRIVATE_PATH/postgres-store.ts:1234567:1234567" }) };
  const r = await run({ frames: Array(200).fill(JSON.stringify(large)) });
  assert.equal(r.result.reason, "safe_output_limit"); assert.equal(r.result.omitted_events, 1);
  assert.ok(r.result.events.length < 200); assert.equal(r.result.delete_attempts, 1);
});
test("delete HTTP refusal preserves safe status and known API code without replay", async () => {
  const r = await run({ deleteDenied: true });
  assert.equal(r.result.delete_http_status, 403); assert.deepEqual(r.result.delete_error_codes, [10000]);
  assert.equal(r.result.cleanup_confirmed, false); assert.equal(r.result.delete_attempts, 1);
  assert.equal(r.result.status, "requires_reconciliation");
});
