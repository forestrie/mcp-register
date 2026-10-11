/**
 * Outward-facing text for the MCP adapter: the server `instructions` string
 * and the per-tool titles and descriptions. Change the wording on purpose,
 * never in passing.
 */

export const INSTRUCTIONS = `@forestrie/mcp-register is the write path of the Forestrie MCP trio. It signs a statement with a log key held behind a signer backend (by default a local ES256 key file it creates), registers it under a Forestrie-Grant you hold, delegates sealing for your data log, and verifies the receipt by composing @forestrie/mcp-resolve (which only fetches) and @forestrie/mcp-verify (which verifies offline) as libraries. It never handles money in this release.

You never handle signature bytes: signing happens inside the server, and no tool takes a signature as input.

This release registers no tools yet.`;

/** Tool names, in registration order — the one list `server.ts` registers
 *  from and `cli.ts`'s `--help` prints, so the two cannot drift.
 *  `test/node/help.test.ts` asserts `--help` names exactly what `tools/list`
 *  returns. Empty until the first tools land. */
export const TOOL_NAMES = [] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

export const TOOL_TITLES: Record<ToolName, string> = {};

export const TOOL_DESCRIPTIONS: Record<ToolName, string> = {};

/** Prompt names, in registration order. Empty until the prompts land. */
export const PROMPT_NAMES = [] as const;
