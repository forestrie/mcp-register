#!/usr/bin/env node
/**
 * The one thing InMemoryTransport cannot catch: a stray write to stdout
 * corrupting the JSON-RPC framing of a REAL process. (Copied from
 * @forestrie/mcp-verify's scripts/check-stdio-clean.mjs.)
 *
 * Spawns the bin with no arguments (stdio mode), writes a single
 * newline-delimited `initialize` request, and asserts that stdout carries
 * exactly one well-formed response and NOTHING ELSE. A `console.log`
 * anywhere in the server does not warn — it makes an MCP client fail to
 * initialise for no visible reason, and this is the only place that
 * failure is legible.
 *
 * Usage: node scripts/check-stdio-clean.mjs [pathToBin]
 *   default bin: ./bin/mcp-register.mjs
 */
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";

const bin =
  process.argv[2] ??
  fileURLToPath(new URL("../bin/mcp-register.mjs", import.meta.url));

const request = {
  jsonrpc: "2.0",
  id: 1,
  method: "initialize",
  params: {
    protocolVersion: "2025-06-18",
    capabilities: {},
    clientInfo: { name: "stdio-clean-check", version: "0" },
  },
};

const child = spawn(process.execPath, [bin], {
  stdio: ["pipe", "pipe", "pipe"],
});

let stdout = "";
let stderr = "";
child.stdout.setEncoding("utf8");
child.stderr.setEncoding("utf8");
child.stdout.on("data", (d) => {
  stdout += d;
});
child.stderr.on("data", (d) => {
  stderr += d;
});

// The SDK's stdio transport is newline-delimited JSON, not Content-Length.
child.stdin.write(`${JSON.stringify(request)}\n`);

const deadline = setTimeout(() => {
  fail(
    `timed out waiting for an initialize response.\nstdout:\n${stdout}\nstderr:\n${stderr}`,
  );
}, 20_000);

function fail(message) {
  clearTimeout(deadline);
  console.error(`stdio-clean check FAILED: ${message}`);
  child.kill("SIGKILL");
  process.exit(1);
}

function done() {
  clearTimeout(deadline);
  child.stdin.end();
  child.kill("SIGTERM");
}

child.on("error", (err) => fail(`could not spawn ${bin}: ${err.message}`));

const check = () => {
  if (!stdout.includes("\n")) return;
  const lines = stdout.split("\n").filter((l) => l.trim() !== "");
  if (lines.length !== 1) {
    fail(
      `expected exactly one line on stdout, got ${lines.length}. ` +
        `Something other than the transport is writing to stdout:\n${stdout}`,
    );
  }
  let response;
  try {
    response = JSON.parse(lines[0]);
  } catch (err) {
    fail(`stdout is not a JSON-RPC frame (${err.message}):\n${lines[0]}`);
  }
  if (response.jsonrpc !== "2.0" || response.id !== 1) {
    fail(`unexpected JSON-RPC envelope: ${lines[0]}`);
  }
  if (response.error !== undefined) {
    fail(`initialize returned an error: ${JSON.stringify(response.error)}`);
  }
  const info = response.result?.serverInfo;
  if (info?.name !== "forestrie-mcp-register") {
    fail(`unexpected serverInfo: ${JSON.stringify(info)}`);
  }
  done();
  console.log(
    `stdio-clean check passed: one well-formed initialize response on stdout, ` +
      `nothing else (serverInfo ${info.name} ${info.version}).`,
  );
  process.exit(0);
};

child.stdout.on("data", check);
