/**
 * The bin entry, reached via `bin/mcp-register.mjs`.
 *
 *   <no args>          → StdioServerTransport; this is what
 *                        `npx -y @forestrie/mcp-register` does.
 *   --help | --version → text on stdout, exit 0.
 *
 * TWO RULES, both silent-corruption bugs if broken:
 *
 * 1. **Nothing may write to stdout in stdio mode except the transport.** A
 *    stray `console.log` does not produce a warning — it produces a malformed
 *    JSON-RPC frame and an MCP client that mysteriously fails to initialise.
 *    All logging goes to stderr. `scripts/check-stdio-clean.mjs` proves it
 *    against a real spawned process on every CI run.
 *
 * 2. **`main` returns an exit code; it does not call `process.exit`.** Killing
 *    the process mid-write truncates whatever the stdio transport had
 *    buffered. The wrapper sets `process.exitCode` and lets node drain.
 *
 * Serves the tools `createServer()` (`server.ts`) registers (none yet). It is
 * called with no `deps`, so it reads `process.env` and calls the real
 * `globalThis.fetch` — exactly what `npx -y @forestrie/mcp-register` should do.
 */
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  PACKAGE_VERSION,
  RESOLVE_VERSION,
  VERIFIER_VERSION,
} from "../core/index.js";
import { createServer } from "./server.js";
import { TOOL_NAMES, TOOL_TITLES } from "./text.js";

/** One line per tool, generated from the same list the server registers
 *  from — never a hand-typed block. Copes with zero tools. */
const TOOLS_BLOCK =
  TOOL_NAMES.length === 0
    ? "  (none yet)"
    : (TOOL_NAMES as readonly string[])
        .map(
          (name) =>
            `  ${name.padEnd(26)} ${(TOOL_TITLES as Record<string, string>)[name]}`,
        )
        .join("\n");

export const HELP = `forestrie-mcp-register ${PACKAGE_VERSION}

  MCP server that signs statements with a log key, registers them on a
  Forestrie transparency log under a grant you hold, delegates sealing for
  your data log, and verifies the receipt by composing @forestrie/mcp-resolve
  and @forestrie/mcp-verify. Signature bytes never cross the MCP boundary.

USAGE
  forestrie-mcp-register                start the MCP server on stdio (the default)
  forestrie-mcp-register --help
  forestrie-mcp-register --version

TOOLS
${TOOLS_BLOCK}

CLIENT CONFIG
  {"mcpServers": {"forestrie-register":
    {"command": "npx", "args": ["-y", "@forestrie/mcp-register"]}}}

  Verifier: @forestrie/mcp-verify ${VERIFIER_VERSION}
  Resolver: @forestrie/mcp-resolve ${RESOLVE_VERSION}
  Docs:     https://github.com/forestrie/mcp-register#readme
`;

/** stdout is the transport in stdio mode; everything else is stderr. */
const out = (line: string): void => {
  process.stdout.write(`${line}\n`);
};

export async function main(argv: readonly string[]): Promise<number> {
  const args = [...argv];

  if (args.includes("--help") || args.includes("-h") || args[0] === "help") {
    out(HELP);
    return 0;
  }
  if (args.includes("--version") || args.includes("-v")) {
    out(PACKAGE_VERSION);
    return 0;
  }

  const verb = args[0];
  if (verb !== undefined && !verb.startsWith("-")) {
    process.stderr.write(
      `forestrie-mcp-register: unknown command '${verb}'. Try --help.\n`,
    );
    return 1;
  }

  // Default: speak MCP on stdio. From here on, stdout belongs to the
  // transport and nothing else may touch it.
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Wait for the client to go away (stdin ends, the transport closes) or
  // for a signal. `server.server.onclose`, not `transport.onclose`: connect()
  // installed the latter and overwriting it would skip the SDK's own
  // cleanup. Listeners are removed afterwards so nothing here keeps the
  // event loop alive.
  let finish: () => void = () => {};
  const ended = new Promise<void>((resolve) => {
    finish = resolve;
  });
  const onSignal = (): void => finish();
  server.server.onclose = finish;
  process.stdin.once("end", finish);
  process.on("SIGINT", onSignal);
  process.on("SIGTERM", onSignal);
  await ended;
  process.off("SIGINT", onSignal);
  process.off("SIGTERM", onSignal);
  process.stdin.off("end", finish);

  // A signal leaves the transport open, and its stdin listener keeps the
  // process alive for as long as the client holds the pipe. Close it so the
  // event loop drains; the wrapper sets the exit code, never process.exit.
  await server.close();
  return 0;
}

/**
 * Entry point. `process.exitCode` rather than `process.exit()`: node then
 * drains stdout before exiting, which a hard exit would not.
 */
export async function run(): Promise<void> {
  try {
    process.exitCode = await main(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(
      `forestrie-mcp-register: ${err instanceof Error ? (err.stack ?? err.message) : String(err)}\n`,
    );
    process.exitCode = 1;
  }
}

await run();
