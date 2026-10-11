/**
 * `@forestrie/mcp-register/net` — the ONLY place `fetch` is called.
 *
 * Every function here takes `opts.fetchImpl` (defaulting to
 * `globalThis.fetch`) and never calls a bare `fetch`, so unit tests inject a
 * fake under the forbidden-fetch global. Reads that mcp-resolve already
 * does (receipts, genesis) are imported from `@forestrie/mcp-resolve/net`,
 * not reimplemented.
 */

export { DEFAULT_TIMEOUT_MS, rawRequest } from "./http.js";
export {
  getPendingDelegation,
  getRegistrationStatus,
  postDelegationCertificate,
  postStatement,
  prepareChildLog,
} from "./write.js";
export { delegateSealing } from "./delegate.js";
export type {
  DelegateSealingInput,
  DelegateSealingOutcome,
  DelegateStage,
} from "./delegate.js";
