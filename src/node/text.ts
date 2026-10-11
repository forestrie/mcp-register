/**
 * Outward-facing text for the MCP adapter: the server `instructions`, the
 * per-tool titles and descriptions, and the prompts. Change the wording on
 * purpose, never in passing.
 */

export const INSTRUCTIONS = `@forestrie/mcp-register is the write path of the Forestrie MCP trio. It signs statements with a log key it holds (ES256, behind a signer backend; by default a local key file it creates), registers them on a Forestrie transparency log under a Forestrie-Grant, delegates sealing for your data log, and checks the receipt with @forestrie/mcp-verify's verifier through @forestrie/mcp-resolve.

It can also act as a requester that is its own grant issuer: issue_grant signs a child grant with a separate authority key, and register_grant registers it with canopy, paying canopy's x402 402 from a configured payer within hard caps, or handing you the payment requirements to pay from your own wallet (relay mode). Forestrie runs no grant issuer.

You never handle signature bytes or keys: you pass the payload, the server signs; the payer key never crosses this boundary, and the spending caps are configuration, not arguments.

The loop with a grant you hold: get_log_key → delegate_sealing once per log → register_statement → check_registration until sealed → verify_registration (the "register" prompt). Buying the grant first: issue_grant → register_grant until complete (the "issue-and-pay" prompt). The "audit" prompt explains what a verified receipt does and does not prove.

Configuration, each overridable per call: FORESTRIE_BASE_URL (the canopy SCRAPI base URL), FORESTRIE_ROOT_LOG_ID (the forest's root log id, R), FORESTRIE_GRANT (the grant, as base64 or a file path), FORESTRIE_AUTHORITY_GRANT (your authority log's grant, for issue_grant), FORESTRIE_COORDINATOR_URL and FORESTRIE_KNOWN_SEALER_KEY (for delegate_sealing; the operator publishes both). Payment, never overridable per call: MCP_REGISTER_PAYER_KEY_FILE and the MCP_REGISTER_PAY_* caps. MCP_REGISTER_HOME holds the key files, the grants, the registrations and the spend ledger.`;

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
  "issue_grant",
  "register_grant",
] as const;

export type ToolName = (typeof TOOL_NAMES)[number];

export const TOOL_TITLES: Record<ToolName, string> = {
  get_log_key: "Get the log key",
  register_statement: "Sign and register a statement",
  check_registration: "Check a registration",
  verify_registration: "Verify a registration's receipt",
  delegate_sealing: "Delegate sealing for your log",
  issue_grant: "Issue a child grant as the requester",
  register_grant: "Register a child grant, paying if canopy asks",
};

export const TOOL_DESCRIPTIONS: Record<ToolName, string> = {
  get_log_key:
    'Return the public half of one of this server\'s keys (ES256, 64 bytes x‖y, as hex, base64 and an SPKI PEM) and where it lives, creating it on first use. which: "log" (the default) is the key that owns your data log: a grant issuer names it in the grant\'s grantData, and a grant naming any other key cannot carry statements this server signs. which: "authority" is the requester\'s key that owns your authority log and signs the grants issue_grant makes. Never returns private key material.',
  register_statement:
    "Sign a payload with the log key and register it under your Forestrie-Grant. Takes the payload bytes (inline base64 or a file path, up to canopy's 4 MiB statement limit) and its content type. The signed statement is saved before it is sent, so the returned content hash always names it, even if the request fails. A payload path may not point at the log key or inside this server's home. Registration is accepted, not yet sequenced: call check_registration next.",
  check_registration:
    "One status check for a registration, by its content hash: pending (not yet sequenced; retry after the given seconds), awaiting_seal (sequenced, entry id known, receipt not yet sealed — sealing takes minutes, and never happens until delegate_sealing has run for the log), or sealed (the receipt is saved and its path returned). Any other answer from canopy is reported as a problem with its reason. canopy answers a statement it never received exactly like a pending one, so after ten minutes of pending this says so. Does not sleep; pace the retries yourself.",
  verify_registration:
    "Verify a sealed registration's receipt over the statement you registered, with @forestrie/mcp-verify's verifier, and return its four-question answers unaltered. By default the trust root is this server's own log key, the root of your data log; verifying never creates a key. Pass a known accumulator (from @forestrie/mcp-resolve's fetch_accumulator) to use a root that can also answer split-view.",
  delegate_sealing:
    "Authorise the operator's sealer to publish checkpoints for your data log, signed with the log key. Without it entries sequence but are never sealed. If the coordinator has not learned the log's public root, this calls canopy's prepare with the same grant first. Run once per log; the delegation lasts until the returned expiresAt. With as: \"authority\" it does the same for your authority log, signed with the authority key, so the child grants you register there get sealed.",
  issue_grant:
    "As the requester, sign a child grant with this server's authority key: a data-log creation grant under your authority log (named by your authority grant, FORESTRIE_AUTHORITY_GRANT), naming the performer's log key (by default this server's own) and sized with maxHeight, the batch ceiling canopy prices it by. Saves the grant under a fresh child log id; nothing is sent. Call register_grant next.",
  register_grant:
    "Register a child grant with canopy (POST /register/{R}/grants, your authority grant as the parent) and follow it to its receipt; call it again with the same logId to resume until it reports complete. If canopy answers 402 and a payer is configured, it pays within the server's hard caps (per call, per UTC day, one network and asset, testnet only by default) and reports any cap that refuses. With no payer it returns the payment requirements: pay them from your own x402 wallet and call again with payment set to the X-PAYMENT value. Every payment for a grant carries a nonce derived from that grant, so retries and overlapping calls can never pay for it twice. When complete it returns the completed grant for delegate_sealing and register_statement.",
};

/** Prompt names, in registration order. */
export const PROMPT_NAMES = ["register", "audit", "issue-and-pay"] as const;

export type PromptName = (typeof PROMPT_NAMES)[number];

export const PROMPT_TITLES: Record<PromptName, string> = {
  register: "Register a statement and keep the receipt",
  audit: "Audit a receipt: trust roots and the four questions",
  "issue-and-pay": "Issue a child grant and pay to register it",
};

export const PROMPT_DESCRIPTIONS: Record<PromptName, string> = {
  register:
    "Walk through checking the key and grant, delegating sealing, registering, waiting for the seal, verifying and keeping the receipt.",
  audit:
    "Explain which of the four trust questions a receipt answers under each trust root, and how to choose a root.",
  "issue-and-pay":
    "As the requester, size and sign a child grant, register it with canopy, pay its 402 within the caps or relay the payment, and hand the completed grant to the performer.",
};

export function registerPromptText(args: {
  what?: string | undefined;
}): string {
  const subject = args.what?.trim()
    ? `The statement to register: ${args.what.trim()}.`
    : "If it is not already clear what is to be registered, ask.";
  return `Register a statement on a Forestrie transparency log with the @forestrie/mcp-register tools, and keep a receipt anyone can verify later. ${subject}

You never handle signature bytes. Pass the payload; the server signs with its log key.

1. Key and grant. Call get_log_key. The grant you register under must name exactly that key (its grantData is the 64-byte x‖y get_log_key returns) and must be for a data log. If you do not hold such a grant and you own an authority log yourself, buy one with the issue-and-pay prompt. Otherwise stop: give the public key to the grant issuer for your log (the owner of the authority log above it) and ask for one. Forestrie issues no grants itself.

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

export function issueAndPayPromptText(args: {
  purpose?: string | undefined;
}): string {
  const purpose = args.purpose?.trim()
    ? `What the grant is for: ${args.purpose.trim()}.`
    : "If it is not clear what the grant is for, and so how large it must be, ask.";
  return `Buy a grant on a Forestrie transparency log as the requester, with the @forestrie/mcp-register tools: sign a child grant under your own authority log, register it with canopy, pay if canopy asks, and hand the completed grant to whoever will write under it. ${purpose}

Forestrie runs no grant issuer. You are the issuer: your authority key owns an authority log that the owner of the root above you created for you once. If that log carries the child-payment-required flag, every child grant registered under it is paid for over x402, and the payment goes straight to the transparency operator.

You never handle keys or signature bytes. The server signs grants with its authority key and pays with its own payer; you never see either key, and you cannot raise its spending caps.

1. Authority. Call get_log_key with which: "authority". You need an authority grant naming that key (FORESTRIE_AUTHORITY_GRANT, or pass parentGrant). If you have none, stop: give the publicKeyPem to the owner of the root above you and ask them to create your authority log for it. Its sealing must be delegated once, with delegate_sealing as: "authority" and that grant, or your child grants are sequenced but never sealed.

2. Size. maxHeight is the grant's batch ceiling, and canopy prices a paid child grant as its unit price × maxHeight. Size it to the work it is for, no larger: a bigger grant costs more, and the server's per-call cap refuses one it cannot afford.

3. Issue. Call issue_grant with maxHeight. By default it names this server's own log key, so the same agent writes (a self-purchase); pass grantee (base64 of a 64-byte x‖y) to issue to another agent's log key. Keep the logId it returns.

4. Register and pay. Call register_grant with that logId.
   - accepted: canopy took the grant (and the payment, if it asked for one). Go to 5.
   - payment_required, no payer configured (relay mode): show the user the amount, asset, network and payee. Pay only with a wallet the user has authorised for this; give it the paymentRequiredHeader, then call register_grant again with the same logId and payment set to the X-PAYMENT value it returns. Never invent or edit a payment value.
   - a cap_… problem: the server's own limit refused the payment. Report which cap and the amounts. Do not try to get around it: do not split the grant to slip under a cap, switch canopy, or retry in a loop. A smaller grant (step 2) or the user's decision are the ways forward.
   - payment_rejected: canopy refused the payment; report its reason. Nothing was registered.
   - a network error: call register_grant again with the same logId. It signs with the grant's own nonce again, so at most one payment can ever settle.

5. Wait. Call register_grant with the logId until it reports complete: pending and awaiting_seal mean wait (seconds, then about a minute) and call again. Sealing takes minutes.

6. Hand over. complete returns grantBase64, the completed grant. If it names this server's log key, continue with the register prompt: delegate_sealing with that grant, then register_statement. Otherwise give it to the performer whose key it names.

Report what was paid, to whom, on which network, and the logId: the spend is recorded in this server's ledger, and the operator's receipt for the grant is the public record of the purchase.`;
}
