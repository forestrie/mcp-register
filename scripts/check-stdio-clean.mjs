#!/usr/bin/env node
/**
 * The one thing InMemoryTransport cannot catch: a stray write to stdout
 * corrupting the JSON-RPC framing of a REAL process. (Copied from
 * @forestrie/mcp-verify's scripts/check-stdio-clean.mjs.)
 *
 * Spawns the bin with no arguments (stdio mode), sends `initialize`, then
 * `tools/list`, `prompts/list` and one `tools/call` that stops at input
 * validation, waits for a quiet spell, and asserts that stdout carries
 * exactly one well-formed reply to each and NOTHING ELSE. A `console.log`
 * anywhere in the server does not warn — it makes an MCP client fail to
 * initialise for no visible reason, and this is the only place that
 * failure is legible.
 *
 * Usage: node scripts/check-stdio-clean.mjs [pathToBin]
 *   default bin: ./bin/mcp-register.mjs
 */
import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const bin =
  process.argv[2] ??
  fileURLToPath(new URL("../bin/mcp-register.mjs", import.meta.url));

// After initialize: list the tools and prompts, and make one tool call that
// fails at input validation (no base URL configured), so a stray write in
// the tool-handling path would land on stdout too. Errors are fine for the
// list calls (a server with no tools does not advertise the capability);
// what is checked is that every byte on stdout is one of these replies.
const INITIALIZE = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "stdio-clean-check", version: "0" },
  },
};
const FOLLOW_UPS = [
  { jsonrpc: "2.0", method: "notifications/initialized" },
  { jsonrpc: "2.0", id: 2, method: "tools/list" },
  { jsonrpc: "2.0", id: 3, method: "prompts/list" },
  {
    jsonrpc: "2.0",
    id: 4,
    method: "tools/call",
    params: {
      name: "register_statement",
      arguments: { payload: { b64: "aGk=" }, contentType: "text/plain" },
    },
  },
];
const EXPECTED_IDS = [1, 2, 3, 4];
const QUIET_MS = 500;

// Run with no Forestrie configuration and a throwaway home, so nothing the
// check provokes can reach a network or a real key file.
const home = mkdtempSync(join(tmpdir(), "mcp-register-stdio-clean-"));
const env = Object.fromEntries(
  Object.entries(process.env).filter(
    ([k]) => !k.startsWith("FORESTRIE_") && !k.startsWith("MCP_REGISTER_"),
  ),
);
env.MCP_REGISTER_HOME = home;

const child = spawn(process.execPath, [bin], {
  stdio: ["pipe", "pipe", "pipe"],
  env,
});

let stdout = "";
let stderr = "";
child.stdout.setEncoding("utf8");
child.stderr.setEncoding("utf8");
child.stderr.on("data", (d) => {
  stderr += d;
});

const send = (msg) => child.stdin.write(`${JSON.stringify(msg)}\n`);

const deadline = setTimeout(() => {
  fail(
    `timed out waiting for replies to ids ${EXPECTED_IDS.join(", ")}.\nstdout:\n${stdout}\nstderr:\n${stderr}`,
  );
}, 20_000);

function cleanup() {
  clearTimeout(deadline);
  rmSync(home, { recursive: true, force: true });
}

function fail(message) {
  cleanup();
  console.error(`stdio-clean check FAILED: ${message}`);
  child.kill("SIGKILL");
  process.exit(1);
}

child.on("error", (err) => fail(`could not spawn ${bin}: ${err.message}`));

/** Parse stdout so far: every complete line must be a JSON-RPC frame. */
function frames() {
  const complete = stdout.slice(0, stdout.lastIndexOf("\n") + 1);
  return complete
    .split("\n")
    .filter((l) => l.trim() !== "")
    .map((line) => {
      let msg;
      try {
        msg = JSON.parse(line);
      } catch (err) {
        fail(
          `stdout carries something other than a JSON-RPC frame (${err.message}):\n${line}`,
        );
      }
      if (msg?.jsonrpc !== "2.0")
        fail(`stdout carries a non-JSON-RPC line:\n${line}`);
      return msg;
    });
}

let followed = false;
let quiet;

function verify() {
  if (!stdout.endsWith("\n"))
    fail(`stdout ends with a partial line:\n${stdout}`);
  const msgs = frames();
  const ids = msgs.map((m) => m.id);
  if (
    msgs.length !== EXPECTED_IDS.length ||
    ids.some((id, i) => id !== EXPECTED_IDS[i])
  )
    fail(
      `expected exactly one reply each to ids ${EXPECTED_IDS.join(", ")}, in order, and nothing else; got ids [${ids.join(", ")}]:\n${stdout}`,
    );
  const init = msgs[0];
  if (init.error !== undefined)
    fail(`initialize returned an error: ${JSON.stringify(init.error)}`);
  const info = init.result?.serverInfo;
  if (info?.name !== "forestrie-mcp-register")
    fail(`unexpected serverInfo: ${JSON.stringify(info)}`);
  cleanup();
  child.stdin.end();
  child.kill("SIGTERM");
  console.log(
    `stdio-clean check passed: one well-formed reply each to initialize, tools/list, prompts/list and a tools/call on stdout, nothing else (serverInfo ${info.name} ${info.version}).`,
  );
  process.exit(0);
}

child.stdout.on("data", (d) => {
  stdout += d;
  const msgs = frames();
  if (!followed && msgs.some((m) => m.id === 1)) {
    followed = true;
    for (const m of FOLLOW_UPS) send(m);
  }
  if (msgs.filter((m) => m.id !== undefined).length >= EXPECTED_IDS.length) {
    // Every reply is in; keep listening a little longer for stray output.
    clearTimeout(quiet);
    quiet = setTimeout(verify, QUIET_MS);
  }
});

send(INITIALIZE);
