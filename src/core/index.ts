/**
 * `@forestrie/mcp-register` — the browser-safe core.
 *
 * This is the `"."` export. Everything reachable from here is pure over
 * bytes: no `node:*`, no `fetch`, no filesystem, no MCP SDK, no key
 * material. `"./net"` is the only place `fetch` is called, and `"./server"`
 * is where the MCP adapter, the signer backend and the key file live.
 * `pnpm run check:browser-safe` bundles this file for `platform: "browser"`
 * and fails on any edge to a node builtin.
 *
 */

export {
  PACKAGE_VERSION,
  VERIFIER_VERSION,
  RESOLVE_VERSION,
} from "./version.js";
export type { Es256Signer } from "./signer.js";
export { MAX_STATEMENT_BYTES } from "./limits.js";
export { base64ToBytes, bytesToBase64 } from "./base64.js";
export {
  GrantError,
  inspectGrant,
  prepareGrantProblems,
  statementGrantProblems,
} from "./grant.js";
export type { GrantView } from "./grant.js";
export {
  MAX_PARENT_GRANT_BYTES,
  completeGrant,
  dataLogCreateExtendFlags,
  issueChildGrant,
  parentGrantProblems,
  registerGrantBody,
} from "./issue.js";
export type { IssueGrantInput, IssuedGrant } from "./issue.js";
export {
  DEFAULT_PAY_ASSET,
  DEFAULT_PAY_NETWORK,
  PaymentError,
  TESTNETS,
  readPaymentPayload,
  readPaymentRequired,
  selectWithinCaps,
} from "./x402.js";
export type {
  CapContext,
  CapRefusalCode,
  PaymentCaps,
  PaymentOption,
  PaymentRequired,
  PaymentSummary,
} from "./x402.js";
export { StatementError, signStatement } from "./statement.js";
export type { SignStatementInput, SignedStatement } from "./statement.js";
export {
  readProblem,
  readReceiptResponse,
  readRegisterGrantResponse,
  readRegisterResponse,
  readStatusResponse,
} from "./scrapi.js";
export type {
  Problem,
  ReceiptOutcome,
  RegisterGrantOutcome,
  RegisterOutcome,
  ResponseView,
  StatusOutcome,
} from "./scrapi.js";
export {
  DEFAULT_MMR_END,
  DelegationError,
  buildCertificateSubmission,
  checkVoucher,
  findStandingEntry,
} from "./delegation.js";
export type {
  CertificateSubmission,
  PendingDelegationEntry,
  StandingEntry,
} from "./delegation.js";
