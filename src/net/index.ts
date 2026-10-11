/**
 * `@forestrie/mcp-register/net` — the ONLY place `fetch` is called.
 *
 * Every function that lands here takes a `fetchImpl` parameter (defaulting to
 * `globalThis.fetch`) and never calls a bare `fetch`, so unit tests inject a
 * fake under the forbidden-fetch global. Empty for now: the SCRAPI
 * registration calls arrive with the first tools.
 */

export {};
