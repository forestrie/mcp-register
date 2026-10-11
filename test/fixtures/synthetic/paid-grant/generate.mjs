#!/usr/bin/env node
/**
 * The paid-grant fixture generator: the requester's authority grant (with
 * and without GF_CHILD_PAYMENT_REQUIRED), and one recorded exchange
 * (`<name>.meta.json` + `<name>.body`) for each canopy answer
 * register_grant reads: the x402 402 challenge, a refused payment, the 303,
 * the grant's status and its receipt.
 *
 * SYNTHESISED from canopy's source contract, not captured from a live
 * service. See this directory's PROVENANCE.md.
 *
 * Deterministic in every byte except the ECDSA signatures of the two parent
 * grants. Idempotent: an `outDir` that already has the committed
 * `*-key.jwk.json` files has them reused.
 *
 * Imports only `@forestrie/encoding` and `node:*`, never this package's src/.
 *
 * Usage: `node generate.mjs [outDir]` (defaults to this file's directory).
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  COSE_ALG_ES256,
  encodeCborDeterministic,
  encodeCoseSign1Raw,
  encodeGrantPayloadV0Canonical,
  encodeProblemDetailsCbor,
  encodeSigStructure,
  uuidToBytes,
} from "@forestrie/encoding";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ---- the fixed coordinates every fixture names ---- */

export const COORDINATES = {
  baseUrl: "https://canopy.example.test",
  coordinatorUrl: "https://coordinator.example.test",
  /** R: the forest's root log. */
  rootLogId: "3f1c2d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  /** O: the requester's authority log, created under R by the principal. */
  authorityLogId: "9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a",
  /** T: the child data log the tests issue a grant for. */
  childLogId: "b1c2d3e4-f5a6-4b7c-8d9e-0f1a2b3c4d5e",
  /** The grant commitment in the recorded status URL: a fixed placeholder,
   *  NOT the commitment of any grant a test signs. */
  grantCommitmentHex: "",
  entryId: "5c0ffee5deadbeef0000000000000002",
  massifHeight: 14,
  /** canopy's REGISTER_GRANT_PRICE_ATOMIC in the challenge, × maxHeight 8. */
  unitPriceAtomic: "1000",
  maxHeight: 8,
  network: "eip155:84532",
  /** Circle's USDC on Base Sepolia, as canopy's x402.ts names it. */
  asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
  /** A fabricated payee. */
  payTo: "0x00000000000000000000000000000000000fee01",
  /** Anvil's and Hardhat's account #0: a key the whole world knows. */
  payerPrivateKey:
    "0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80",
  payerAddress: "0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266",
};

const TEST_KEY_WARNING =
  "TEST ONLY. This private key is published in a public repository to " +
  "sign synthetic test fixtures. It must never be trusted, registered, " +
  "granted anything, or used to sign anything else.";

const KEY_FILES = {
  principal: "principal-key.jwk.json",
  authority: "authority-key.jwk.json",
};

const enc = new TextEncoder();

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function b64urlToBytes(s) {
  return new Uint8Array(Buffer.from(s, "base64url"));
}

async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function loadOrCreateKey(outDir, file) {
  const keyPath = path.join(outDir, file);
  const algo = { name: "ECDSA", namedCurve: "P-256" };
  let jwk;
  if (existsSync(keyPath)) {
    jwk = JSON.parse(readFileSync(keyPath, "utf8"));
  } else {
    const { privateKey } = await crypto.subtle.generateKey(algo, true, [
      "sign",
      "verify",
    ]);
    jwk = {
      ...(await crypto.subtle.exportKey("jwk", privateKey)),
      warning: TEST_KEY_WARNING,
    };
    writeFileSync(keyPath, `${JSON.stringify(jwk, null, 2)}\n`);
  }
  const { warning: _warning, ...forImport } = jwk;
  const privateKey = await crypto.subtle.importKey(
    "jwk",
    { ...forImport, key_ops: ["sign"] },
    algo,
    true,
    ["sign"],
  );
  const xy = new Uint8Array(64);
  xy.set(b64urlToBytes(jwk.x), 0);
  xy.set(b64urlToBytes(jwk.y), 32);
  return { jwk, privateKey, xy };
}

/** The parent authority grant: an auth-log creation grant for O under R,
 *  naming the requester's authority key, signed by the principal. */
async function authorityGrant(principal, authorityXY, childPaymentRequired) {
  const flags = new Uint8Array(8);
  // GF_CREATE|GF_EXTEND, plus GF_DERIVED|GF_CHILD_PAYMENT_REQUIRED (adr-0062).
  flags[3] = childPaymentRequired ? 0x0f : 0x03;
  flags[7] = 0x01; // GF_AUTH_LOG
  const grantCbor = encodeGrantPayloadV0Canonical({
    logId: uuidToBytes(COORDINATES.authorityLogId),
    ownerLogId: uuidToBytes(COORDINATES.rootLogId),
    grant: flags,
    maxHeight: 0,
    minGrowth: 0,
    grantData: authorityXY,
  });
  const payload = await sha256(grantCbor);
  const protectedBytes = encodeCborDeterministic(
    new Map([[1, COSE_ALG_ES256]]),
  );
  const sig = new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      principal.privateKey,
      encodeSigStructure(protectedBytes, new Uint8Array(0), payload),
    ),
  );
  return encodeCoseSign1Raw(
    protectedBytes,
    new Map([
      [-65538, grantCbor],
      [-65537, new Uint8Array([1, 2, 3, 4, 5, 6, 7, 9])],
      // The parent is a completed grant: its own receipt rides at 396.
      [396, enc.encode("SYNTHETIC-PARENT-RECEIPT-NOT-A-REAL-COSE-RECEIPT\n")],
    ]),
    payload,
    sig,
  );
}

/** canopy `scrapi/x402.ts` buildPaymentRequiredHeader, byte for byte. */
function paymentRequiredHeader(c, resourceUrl) {
  const requirements = {
    x402Version: 2,
    accepts: [
      {
        scheme: "exact",
        network: c.network,
        amount: String(BigInt(c.unitPriceAtomic) * BigInt(c.maxHeight)),
        asset: c.asset,
        payTo: c.payTo,
        maxTimeoutSeconds: 300,
        extra: { name: "USDC", version: "2" },
      },
    ],
    resource: {
      url: resourceUrl,
      description: "SCRAPI statement registration",
      mimeType: "application/cose",
    },
  };
  return Buffer.from(JSON.stringify(requirements), "utf8").toString("base64");
}

/* ---- recorded exchanges ---- */

const PROBLEM = "application/problem+cbor";

function defineExchanges(c) {
  const grantsUrl = `${c.baseUrl}/register/${c.rootLogId}/grants`;
  const statusUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.authorityLogId}/entries/${c.grantCommitmentHex}?subject=${c.childLogId}`;
  const receiptUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.authorityLogId}/${c.massifHeight}/entries/${c.entryId}/receipt`;
  const amount = String(BigInt(c.unitPriceAtomic) * BigInt(c.maxHeight));
  // canopy register-grant-payment.ts paymentRequired(): a CBOR problem with
  // the challenge header, the same for a missing and a refused payment.
  const challenge = (detail) => ({
    method: "POST",
    url: grantsUrl,
    status: 402,
    contentType: PROBLEM,
    headers: { "x-payment-required": paymentRequiredHeader(c, grantsUrl) },
    body: encodeCborDeterministic(
      new Map([
        ["type", "about:blank"],
        ["title", "Payment Required"],
        ["status", 402],
        ["detail", detail],
        ["reason", "payment_required"],
        ["amountAtomic", amount],
      ]),
    ),
  });
  return [
    {
      name: "register-grant-402",
      ...challenge(
        "Payment required to register a child grant under this authority.",
      ),
      note: "The x402 challenge: no X-PAYMENT, under a payment-gated parent.",
    },
    {
      name: "register-grant-402-refused",
      ...challenge("invalid_exact_evm_payload_signature"),
      note: "An X-PAYMENT the facilitator refused: the same challenge, canopy's reason in detail.",
    },
    {
      name: "register-grant-303",
      method: "POST",
      url: grantsUrl,
      status: 303,
      headers: { location: statusUrl, "retry-after": "5" },
      note: "Grant enqueued for sequencing on the owner log's shard: 303 to its status URL.",
    },
    {
      name: "register-grant-409",
      method: "POST",
      url: grantsUrl,
      status: 409,
      contentType: PROBLEM,
      body: encodeProblemDetailsCbor({
        type: "about:blank",
        title: "Conflict",
        status: 409,
        detail:
          "logId already registered to a different forest (global uniqueness).",
      }),
      note: "univocity refused the creation grant: the child log id is taken.",
    },
    {
      name: "grant-status-pending",
      method: "GET",
      url: statusUrl,
      status: 303,
      headers: { location: statusUrl, "retry-after": "2" },
      note: "Not yet sequenced: 303 to itself.",
    },
    {
      name: "grant-status-sequenced",
      method: "GET",
      url: statusUrl,
      status: 303,
      headers: { location: receiptUrl },
      note: "Sequenced in the authority log: 303 to the permanent receipt URL.",
    },
    {
      name: "grant-receipt-404",
      method: "GET",
      url: receiptUrl,
      status: 404,
      contentType: PROBLEM,
      body: encodeProblemDetailsCbor({
        type: "about:blank",
        title: "Entry receipt not found (checkpoint missing)",
        status: 404,
      }),
      note: "Sequenced but not yet sealed.",
    },
    {
      name: "grant-receipt-200",
      method: "GET",
      url: receiptUrl,
      status: 200,
      contentType: "application/scitt.receipt+cose",
      body: enc.encode("SYNTHETIC-GRANT-RECEIPT-NOT-A-REAL-COSE-RECEIPT\n"),
      note: "Sealed. The body is a placeholder, not a verifiable receipt.",
    },
  ];
}

async function writeExchange(outDir, ex, written) {
  const body = ex.body ?? new Uint8Array(0);
  const headers = { ...(ex.headers ?? {}) };
  if (ex.contentType) headers["content-type"] = ex.contentType;
  headers["content-length"] = String(body.length);
  const bodyFile = body.length > 0 ? `${ex.name}.body` : null;
  const meta = {
    url: ex.url,
    method: ex.method,
    status: ex.status,
    headers,
    contentType: ex.contentType ?? null,
    bodyFile,
    bodyBytes: body.length,
    note: ex.note,
    bodySha256: toHex(await sha256(body)),
  };
  writeFileSync(
    path.join(outDir, `${ex.name}.meta.json`),
    `${JSON.stringify(meta, null, 2)}\n`,
  );
  written.push(`${ex.name}.meta.json`);
  if (bodyFile) {
    writeFileSync(path.join(outDir, bodyFile), body);
    written.push(bodyFile);
  }
}

/* ---- generate ---- */

export async function generate(outDir) {
  mkdirSync(outDir, { recursive: true });
  const written = [];
  const c = { ...COORDINATES };
  c.grantCommitmentHex = toHex(
    await sha256(enc.encode("mcp-register synthetic placeholder grant")),
  );

  const keys = {};
  for (const [k, file] of Object.entries(KEY_FILES)) {
    keys[k] = await loadOrCreateKey(outDir, file);
    written.push(file);
  }

  writeFileSync(
    path.join(outDir, "authority-grant.cose"),
    await authorityGrant(keys.principal, keys.authority.xy, true),
  );
  writeFileSync(
    path.join(outDir, "authority-grant-free.cose"),
    await authorityGrant(keys.principal, keys.authority.xy, false),
  );
  written.push("authority-grant.cose", "authority-grant-free.cose");

  for (const ex of defineExchanges(c)) await writeExchange(outDir, ex, written);

  writeFileSync(
    path.join(outDir, "coordinates.json"),
    `${JSON.stringify(c, null, 2)}\n`,
  );
  written.push("coordinates.json");

  writeFileSync(path.join(outDir, "PROVENANCE.md"), provenance());
  written.push("PROVENANCE.md");

  const files = {};
  for (const name of [...new Set(written)].sort())
    files[name] = toHex(await sha256(readFileSync(path.join(outDir, name))));
  writeFileSync(
    path.join(outDir, "manifest.json"),
    `${JSON.stringify({ generatedBy: "generate.mjs", files }, null, 2)}\n`,
  );
  return { outDir, files: Object.keys(files), coordinates: c };
}

function provenance() {
  return `# SYNTHESISED — paid-grant fixtures

Everything in this directory is FABRICATED. Nothing was captured from a
live canopy or x402 facilitator. The bytes are built by \`generate.mjs\` from
the wire contract in canopy's source: \`scrapi/register-grant.ts\` (the
303, the 409), \`scrapi/register-grant-payment.ts\` (the 402 problem and the
challenge, priced as unit price × the child grant's \`maxHeight\`),
\`scrapi/x402.ts\` (\`buildPaymentRequiredHeader\`, reproduced byte for byte),
\`scrapi/auth-grant.ts\` (the \`{parentGrant}\` body) and
\`scrapi/grant-sequencing.ts\` (the grant status URL on the owner log), using
the published \`@forestrie/encoding\` encoders.

The host \`canopy.example.test\` does not exist. The UUIDs and the payee
address are fixed arbitrary values. Run \`generate.mjs\` again and every
file except the two signed parent grants comes back byte-for-byte.

## The facilitator is a stub

canopy verifies an \`X-PAYMENT\` with an x402 facilitator before it admits a
paid grant. These fixtures record only canopy's two possible answers: 303
(the facilitator accepted) and \`register-grant-402-refused\` (it did not,
with its reason in \`detail\`). Which one a test gets is decided by
\`test/net/stub-facilitator.ts\`, which checks the EIP-3009 authorisation
for real (EIP-712 signature, payee, amount, network, asset, validity
window) against the recorded challenge. No facilitator was called.

## Keys (TEST ONLY)

| File | Role |
|---|---|
| \`principal-key.jwk.json\` | the principal that owns R's subtree; signs the authority grants |
| \`authority-key.jwk.json\` | the requester's authority key; the authority grants name it, and it signs child grants in the tests |

Each private key is committed as a JWK carrying a \`warning\` field. They are
published test keys: never trust, register, grant to, or sign with them.

The payer is Anvil's and Hardhat's account #0
(\`${COORDINATES.payerAddress}\`), whose private key is in \`coordinates.json\`
and in every Ethereum tutorial. Never fund it: anything sent to it is taken.

## Grants

- \`authority-grant.cose\`: the requester's completed authority grant: an
  auth-log creation grant for O = ${COORDINATES.authorityLogId} under
  R = ${COORDINATES.rootLogId}, flags byte 3 = 0x0f
  (GF_CREATE|GF_EXTEND|GF_DERIVED|GF_CHILD_PAYMENT_REQUIRED), byte 7 = 0x01
  (GF_AUTH_LOG), \`grantData\` the authority key's x‖y, signed by the
  principal. Its receipt (396) is a placeholder.
- \`authority-grant-free.cose\`: the same without the payment flags
  (byte 3 = 0x03).

## Recorded exchanges

\`<name>.meta.json\` plus \`<name>.body\` when non-empty: register-grant-402,
register-grant-402-refused, register-grant-303, register-grant-409,
grant-status-pending, grant-status-sequenced, grant-receipt-404,
grant-receipt-200. The challenge asks
${BigInt(COORDINATES.unitPriceAtomic) * BigInt(COORDINATES.maxHeight)} atomic units
(${COORDINATES.unitPriceAtomic} per unit × maxHeight ${COORDINATES.maxHeight}) of
USDC on ${COORDINATES.network}. \`grant-receipt-200\`'s body is a placeholder.

\`manifest.json\` records each file's sha256; \`test/core/fixtures.test.ts\`
checks the committed bytes against it and checks the rest regenerate.
`;
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) {
  const outDir = process.argv[2] ?? HERE;
  const { files } = await generate(outDir);
  console.log(`wrote ${files.length} files to ${outDir}`);
}
