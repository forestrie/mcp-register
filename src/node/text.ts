/**
 * Outward-facing text for the MCP adapter: the server `instructions`, the
 * per-tool titles and descriptions, and the prompts. Change the wording on
 * purpose, never in passing.
 */

export const INSTRUCTIONS = `@forestrie/mcp-register is the write path of the Forestrie MCP trio. It signs statements with a log key it holds (ES256, behind a signer backend; by default a local key file it creates), registers them on a Forestrie transparency log under a Forestrie-Grant you already hold, delegates sealing for your data log, and checks the receipt with @forestrie/mcp-verify's verifier through @forestrie/mcp-resolve. It never handles money.

You never handle signature bytes: you pass the payload, the server signs.

The loop: get_log_key (give its public key to whoever issues your grant) → delegate_sealing once per log → register_statement → check_registration until sealed → verify_registration. The "register" prompt walks through it; the "audit" prompt explains what a verified receipt does and does not prove.

Configuration, each overridable per call: FORESTRIE_BASE_URL (the canopy SCRAPI base URL), FORESTRIE_ROOT_LOG_ID (the forest's root log id, R in /register/{R}/entries), FORESTRIE_GRANT (the grant, as base64 or a file path), FORESTRIE_COORDINATOR_URL and FORESTRIE_KNOWN_SEALER_KEY (for delegate_sealing; the operator publishes both). MCP_REGISTER_HOME holds the key file and the registrations.`;

/** Tool names, in registration order — the one list `server.ts` registers
 *  from and `cli.ts`'s `--help` prints, so the two cannot drift.
 *  `test/node/help.test.ts` asserts `--help` names exactly what `tools/list`
 *  returns. */
export const TOOL_NAMES = [
  "get_log_key",
  "register_statement",
  "check_registration",
  "verify_registration",
  "delegate_sealing",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

export const TOOL_TITLES: Record<ToolName, string> = {
  get_log_key: "Get the log key",
  register_statement: "Sign and register a statement",
  check_registration: "Check a registration",
  verify_registration: "Verify a registration's receipt",
  delegate_sealing: "Delegate sealing for your log",
};

export const TOOL_DESCRIPTIONS: Record<ToolName, string> = {
  get_log_key:
    "Return the public half of this server's log key (ES256, 64 bytes x‖y, as hex and base64) and where the key lives, creating the key on first use. A grant issuer names this key in the grant's grantData; a grant naming any other key cannot carry statements this server signs. Never returns private key material.",
  register_statement:
    "Sign a payload with the log key and register it under your Forestrie-Grant. Takes the payload bytes (inline base64 or a file path, up to canopy's 4 MiB statement limit) and its content type. Returns the content hash that names the registration, the status URL, and the path of the signed statement. Registration is accepted, not yet sequenced: call check_registration next.",
  check_registration:
    "One status check for a registration, by its content hash: pending (not yet sequenced; retry after the given seconds), awaiting_seal (sequenced, entry id known, receipt not yet sealed — sealing takes minutes, and never happens until delegate_sealing has run for the log), or sealed (the receipt is saved and its path returned). Does not sleep; pace the retries yourself.",
  verify_registration:
    "Verify a sealed registration's receipt over the statement you registered, with @forestrie/mcp-verify's verifier, and return its four-question answers unaltered. By default the trust root is this server's own log key, the root of your data log. Pass a known accumulator (from @forestrie/mcp-resolve's fetch_accumulator) to use a root that can also answer split-view.",
  delegate_sealing:
    "Authorise the operator's sealer to publish checkpoints for your data log, signed with the log key. Without it entries sequence but are never sealed. If the coordinator has not learned the log's public root, this calls canopy's prepare with the same grant first. Run once per log; the delegation lasts until the returned expiresAt.",
};

/** Prompt names, in registration order. */
export const PROMPT_NAMES = ["register", "audit"] as const;

export type PromptName = (typeof PROMPT_NAMES)[number];

export const PROMPT_TITLES: Record<PromptName, string> = {
  register: "Register a statement and keep the receipt",
  audit: "Audit a receipt: trust roots and the four questions",
};

export const PROMPT_DESCRIPTIONS: Record<PromptName, string> = {
  register:
    "Walk through checking the key and grant, delegating sealing, registering, waiting for the seal, verifying and keeping the receipt.",
  audit:
    "Explain which of the four trust questions a receipt answers under each trust root, and how to choose a root.",
};

export function registerPromptText(args: {
  what?: string | undefined;
}): string {
  const subject = args.what?.trim()
    ? `The statement to register: ${args.what.trim()}.`
    : "If it is not already clear what is to be registered, ask.";
  return `Register a statement on a Forestrie transparency log with the @forestrie/mcp-register tools, and keep a receipt anyone can verify later. ${subject}

You never handle signature bytes. Pass the payload; the server signs with its log key.

1. Key and grant. Call get_log_key. The grant you register under must name exactly that key (its grantData is the 64-byte x‖y get_log_key returns) and must be for a data log. If you do not hold such a grant, stop: give the public key to the grant issuer for your log (the owner of the authority log above it) and ask for one. Forestrie issues no grants itself.

2. Sealing, once per log. Call delegate_sealing. It authorises the operator's sealer for your data log; if the coordinator never learned the log's public root it runs canopy's prepare with the same grant first. Without it entries are sequenced but never sealed, and check_registration stays at awaiting_seal. If it reports a problem, report its stage and message; do not retry in a loop.

3. Register. Call register_statement with the payload and an accurate content type (application/json, text/plain, application/octet-stream, …). The signed statement may be up to 4 MiB. For anything larger, register a small manifest instead: a JSON document naming the artefact, its size and its sha-256 digest. The receipt then commits to the digest, and the artefact can live anywhere.

4. Wait. Call check_registration with the content hash. pending: wait the suggested seconds and check again. awaiting_seal: the entry is sequenced; sealing typically takes minutes, so check about once a minute. sealed: the receipt is saved and its path returned.

5. Verify. Call verify_registration and report every one of the four answers exactly as returned, with the trust root it used. For what each root can and cannot answer, use the audit prompt.

6. Keep. Tell the user the content hash, the entry id, and the paths of the signed statement and the receipt. With a trust root, those let anyone re-verify offline with @forestrie/mcp-verify, without this server or Forestrie.`;
}

export function auditPromptText(args: {
  contentHash?: string | undefined;
}): string {
  const which = args.contentHash?.trim()
    ? `The registration to audit: content hash ${args.contentHash.trim()}.`
    : "Audit the registration the user names, or ask which.";
  return `Audit a Forestrie receipt: report which of the four trust questions it answers, and under which trust root. ${which}

The verifier (@forestrie/mcp-verify) answers four questions — sealing, split-view, append-authority and attribution — each ok, failed, or not_answered_by_this_root. A trust root is what you take on faith, and each root answers some questions and not others. The roots are not ranked: "not answered by this root" is a real answer, not a failure, and it must reach the user.

Choosing a root:
- Your own log key (verify_registration's default). You hold the root of your data log, so this checks the receipt against the key that delegated its sealing. Like any signature root, it cannot see a split view: it cannot tell you that others are shown the same log.
- A known accumulator: a snapshot of the log's peaks read from the chain the forest is anchored to, which the operator does not control. Get one with @forestrie/mcp-resolve's fetch_accumulator (you need your own RPC access) and pass it to verify_registration, or let @forestrie/mcp-resolve's verify_fetched_receipt read and verify in one call. This kind of root can answer split-view.
- A retained checkpoint chain also answers split-view; the forest genesis document names the operator's bootstrap key. See https://github.com/forestrie/mcp-verify/blob/main/docs/trust-roots.md for when each root applies.

Reporting: list each question with its status exactly as the verifier returned it, name the root, and say where the root came from (this server's key file, a chain read at a given block, someone else). Never turn "not answered" into "ok", and never edit the verifier's answers. If verification failed, quote the failing stage and its reason.

Anyone holding the signed statement, the receipt and a root can re-run the check offline with @forestrie/mcp-verify. The receipt is evidence on its own; it does not depend on trusting this server.`;
}
