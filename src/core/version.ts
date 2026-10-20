/**
 * Version strings, as literals.
 *
 * Not read from `package.json`: `src/core` is browser-safe, so it has no
 * `node:fs`, and a JSON import would bake a resolveJsonModule edge into the
 * `"."` bundle for a handful of strings. The MCP smoke test asserts
 * `PACKAGE_VERSION === package.json#version`, so a forgotten bump is a red
 * test rather than a silent lie in `initialize`'s serverInfo.
 *
 * Only the versions this package reports (`--help`, `initialize`) live here.
 * Bump each one in the same commit as the dependency it names.
 */

/** Keep in sync with package.json#version. Asserted by test/node/mcp-smoke. */
export const PACKAGE_VERSION = "0.2.0";

/** Keep in sync with package.json#dependencies["@forestrie/mcp-verify"] — the
 *  verifier this package composes with. Asserted by
 *  test/core/version.test.ts. */
export const VERIFIER_VERSION = "0.7.0";

/** Keep in sync with package.json#dependencies["@forestrie/mcp-resolve"] —
 *  the resolver this package composes with. Asserted by
 *  test/core/version.test.ts. */
export const RESOLVE_VERSION = "0.4.1";
