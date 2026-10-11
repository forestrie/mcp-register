#!/usr/bin/env node
/**
 * The write-path fixture generator: a child data-log grant, the delegation
 * coordinator's standing entry and registrar voucher, and one recorded
 * exchange (`<name>.meta.json` + `<name>.body`) for each canopy and
 * coordinator answer the write path reads.
 *
 * SYNTHESISED from canopy's source contract, not captured from a live
 * service. See this directory's PROVENANCE.md.
 *
 * Deterministic in every byte except the ECDSA signatures (WebCrypto ECDSA
 * is randomised). Idempotent: an `outDir` that already has the committed
 * `*-key.jwk.json` files has them reused, so the public keys, the grant
 * payload, and every exchange that carries no signature regenerate
 * byte-for-byte.
 *
 * Imports only `@forestrie/encoding` and `node:*`, never this package's src/.
 *
 * Usage: `node generate.mjs [outDir]` (defaults to this file's directory).
 */
import {
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  writeFileSync,
} from "node:fs";
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
  verifyDelegateKeyVoucher,
} from "@forestrie/encoding";

const HERE = path.dirname(fileURLToPath(import.meta.url));

/* ---- the fixed coordinates every fixture names ---- */

export const COORDINATES = {
  baseUrl: "https://canopy.example.test",
  coordinatorUrl: "https://coordinator.example.test",
  /** R: the forest's root log (the /register/{R}/entries segment). */
  rootLogId: "3f1c2d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f",
  /** T: the child data log the grant authorises. */
  dataLogId: "7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d",
  /** O: the parent authority log that issued the grant. */
  ownerLogId: "9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a",
  /** The id in the recorded status URL: sha256 of a fixed placeholder, NOT
   *  the hash of any statement a test signs (ECDSA signatures are random). */
  statusEntryHash: "",
  entryId: "5c0ffee5deadbeef0000000000000001",
  massifHeight: 14,
  sealerId: "sealer-test-1",
  epoch: 7,
  suggestedTtlSeconds: 3600,
  idtimestampHex: "0102030405060708",
};

const TEST_KEY_WARNING =
  "TEST ONLY. This private key is published in a public repository to " +
  "sign synthetic test fixtures. It must never be trusted, registered, " +
  "granted anything, or used to sign anything else.";

const KEY_FILES = {
  log: "log-key.jwk.json",
  otherLog: "other-log-key.jwk.json",
  authority: "authority-key.jwk.json",
  registrar: "registrar-key.jwk.json",
  sealerDelegate: "sealer-delegate-key.jwk.json",
};

const enc = new TextEncoder();

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++)
    out[i] = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toHex(bytes) {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

function b64(bytes) {
  return Buffer.from(bytes).toString("base64");
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

async function signP1363(privateKey, message) {
  return new Uint8Array(
    await crypto.subtle.sign(
      { name: "ECDSA", hash: "SHA-256" },
      privateKey,
      message,
    ),
  );
}

/** Untagged COSE Sign1, protected {1: -7}, signed over the Sig_structure. */
async function signSign1(privateKey, payload, unprotected) {
  const protectedBytes = encodeCborDeterministic(new Map([[1, COSE_ALG_ES256]]));
  const sig = await signP1363(
    privateKey,
    encodeSigStructure(protectedBytes, new Uint8Array(0), payload),
  );
  return encodeCoseSign1Raw(protectedBytes, unprotected, payload, sig);
}

/** The completed-grant credential: payload = sha256(grant CBOR). */
async function grantCredential(authorityKey, grantFields) {
  const grantCbor = encodeGrantPayloadV0Canonical(grantFields);
  const unprotected = new Map([
    [-65538, grantCbor],
    [-65537, fromHex(COORDINATES.idtimestampHex)],
  ]);
  return signSign1(authorityKey.privateKey, await sha256(grantCbor), unprotected);
}

function dataLogGrantFields(xy) {
  // flags: byte3 = GF_CREATE|GF_EXTEND, byte7 = GF_DATA_LOG.
  const flags = new Uint8Array(8);
  flags[3] = 0x03;
  flags[7] = 0x02;
  return {
    logId: uuidToBytes(COORDINATES.dataLogId),
    ownerLogId: uuidToBytes(COORDINATES.ownerLogId),
    grant: flags,
    maxHeight: 0,
    minGrowth: 0,
    grantData: xy,
  };
}

/** Canonical COSE_Key CBOR for a P-256 public key: {1: 2, -1: 1, -2: x, -3: y}. */
function coseKeyCbor(xy) {
  return encodeCborDeterministic(
    new Map([
      [1, 2],
      [-1, 1],
      [-2, xy.slice(0, 32)],
      [-3, xy.slice(32)],
    ]),
  );
}

async function voucher(signerKey, sealerId, epoch, delegateKeyCbor) {
  const payload = encodeCborDeterministic(
    new Map([
      [1, sealerId],
      [2, epoch],
      [3, delegateKeyCbor],
    ]),
  );
  return signSign1(signerKey.privateKey, payload, new Map());
}

/* ---- recorded exchanges ---- */

const exchanges = [];

function addExchange(name, spec) {
  exchanges.push({ name, ...spec });
}

function writeExchange(outDir, ex, written) {
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
  };
  return sha256(body).then((digest) => {
    meta.bodySha256 = toHex(digest);
    writeFileSync(
      path.join(outDir, `${ex.name}.meta.json`),
      `${JSON.stringify(meta, null, 2)}\n`,
    );
    written.push(`${ex.name}.meta.json`);
    if (bodyFile) {
      writeFileSync(path.join(outDir, bodyFile), body);
      written.push(bodyFile);
    }
  });
}

const PROBLEM = "application/problem+cbor";

function defineExchanges(c, standingEntry, badStandingEntry) {
  const registerUrl = `${c.baseUrl}/register/${c.rootLogId}/entries`;
  const statusUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/entries/${c.statusEntryHash}`;
  const receiptUrl = `${c.baseUrl}/logs/${c.rootLogId}/${c.dataLogId}/${c.massifHeight}/entries/${c.entryId}/receipt`;
  const prepareUrl = `${c.baseUrl}/api/forest/${c.dataLogId}/prepare`;
  const pendingUrl = `${c.coordinatorUrl}/api/logs/${c.dataLogId}/pending-delegation`;
  const certUrl = `${c.coordinatorUrl}/api/delegations/certificate`;
  const json = (v) => enc.encode(`${JSON.stringify(v)}\n`);

  addExchange("register-303", {
    method: "POST",
    url: registerUrl,
    status: 303,
    headers: { location: statusUrl, "retry-after": "5" },
    note: "Statement accepted: 303 to the transient status URL.",
  });
  addExchange("register-403", {
    method: "POST",
    url: registerUrl,
    status: 403,
    contentType: PROBLEM,
    body: encodeProblemDetailsCbor({
      type: "about:blank",
      title: "Forbidden",
      status: 403,
      detail: "statement signer does not match the grant's grantData",
      reason: "signer_mismatch",
    }),
    note: "Signer mismatch refusal.",
  });
  addExchange("status-pending", {
    method: "GET",
    url: statusUrl,
    status: 303,
    headers: { location: statusUrl, "retry-after": "1" },
    note: "Not yet sequenced: 303 to itself.",
  });
  addExchange("status-sequenced", {
    method: "GET",
    url: statusUrl,
    status: 303,
    headers: { location: receiptUrl },
    note: "Sequenced: 303 to the permanent receipt URL.",
  });
  addExchange("receipt-404", {
    method: "GET",
    url: receiptUrl,
    status: 404,
    contentType: PROBLEM,
    body: encodeProblemDetailsCbor({
      type: "about:blank",
      title: "Not Found",
      status: 404,
      detail: "no sealed checkpoint covers this entry yet",
    }),
    note: "Sequenced but not yet sealed.",
  });
  addExchange("receipt-200", {
    method: "GET",
    url: receiptUrl,
    status: 200,
    contentType: "application/scitt.receipt+cose",
    body: enc.encode("SYNTHETIC-RECEIPT-BYTES-NOT-A-REAL-COSE-RECEIPT\n"),
    note: "Sealed. The body is a placeholder, not a verifiable receipt.",
  });
  addExchange("prepare-201", {
    method: "POST",
    url: prepareUrl,
    status: 201,
    contentType: "application/cbor",
    body: encodeCborDeterministic(new Map([["publicRoot", "ok"]])),
    note: "Prepare accepted; the log's public root is published.",
  });
  addExchange("prepare-403", {
    method: "POST",
    url: prepareUrl,
    status: 403,
    contentType: PROBLEM,
    body: encodeProblemDetailsCbor({
      type: "about:blank",
      title: "Forbidden",
      status: 403,
      detail: "grant not accepted for prepare",
      reason: "grant_rejected",
    }),
    note: "Prepare refused the grant.",
  });
  addExchange("pending-empty", {
    method: "GET",
    url: pendingUrl,
    status: 200,
    contentType: "application/json",
    body: json({ entries: [], limit: 50 }),
    note: "The coordinator never learned the log's root: no standing entry.",
  });
  addExchange("pending-standing", {
    method: "GET",
    url: pendingUrl,
    status: 200,
    contentType: "application/json",
    body: json({ entries: [standingEntry], limit: 50 }),
    note: "A standing delegate key, vouched for by the registrar key.",
  });
  addExchange("pending-standing-bad-voucher", {
    method: "GET",
    url: pendingUrl,
    status: 200,
    contentType: "application/json",
    body: json({ entries: [badStandingEntry], limit: 50 }),
    note: "As pending-standing, but the voucher is signed by a different key.",
  });
  addExchange("certificate-200", {
    method: "POST",
    url: certUrl,
    status: 200,
    contentType: "application/json",
    body: json({
      ok: true,
      certificateKey: `delegations/${c.dataLogId}/0000000000000000-ffffffffffffffff.cose`,
    }),
    note: "The coordinator stored the delegation certificate.",
  });
}

/* ---- generate ---- */

export async function generate(outDir) {
  mkdirSync(outDir, { recursive: true });
  const written = [];
  const c = { ...COORDINATES };
  c.statusEntryHash = toHex(
    await sha256(enc.encode("mcp-register synthetic placeholder statement")),
  );

  const keys = {};
  for (const [k, file] of Object.entries(KEY_FILES)) {
    keys[k] = await loadOrCreateKey(outDir, file);
    written.push(file);
  }

  // The grants: the data log named by its own key, and the same grant naming
  // a different key.
  const grant = await grantCredential(keys.authority, dataLogGrantFields(keys.log.xy));
  const grantOther = await grantCredential(
    keys.authority,
    dataLogGrantFields(keys.otherLog.xy),
  );
  writeFileSync(path.join(outDir, "grant.cose"), grant);
  writeFileSync(path.join(outDir, "grant-other-key.cose"), grantOther);
  written.push("grant.cose", "grant-other-key.cose");

  // The sealer's standing delegate key and the registrar's vouchers for it.
  const delegateKeyCbor = coseKeyCbor(keys.sealerDelegate.xy);
  const good = await voucher(keys.registrar, c.sealerId, c.epoch, delegateKeyCbor);
  const bad = await voucher(keys.authority, c.sealerId, c.epoch, delegateKeyCbor);
  writeFileSync(path.join(outDir, "voucher.cose"), good);
  writeFileSync(path.join(outDir, "voucher-bad.cose"), bad);
  written.push("voucher.cose", "voucher-bad.cose");

  const entry = (v) => ({
    delegatedPublicKey: b64(delegateKeyCbor),
    suggestedTtlSeconds: c.suggestedTtlSeconds,
    sealerId: c.sealerId,
    epoch: c.epoch,
    voucher: b64(v),
  });
  writeFileSync(
    path.join(outDir, "standing-entry.json"),
    `${JSON.stringify(entry(good), null, 2)}\n`,
  );
  written.push("standing-entry.json");

  // Self-check: the voucher is what @forestrie/encoding accepts, and the
  // other one is not.
  const pinned = {
    x: keys.registrar.xy.slice(0, 32),
    y: keys.registrar.xy.slice(32),
    curve: "P-256",
  };
  const claims = {
    sealerId: c.sealerId,
    epoch: c.epoch,
    publicKey: delegateKeyCbor,
  };
  if (!(await verifyDelegateKeyVoucher(good, pinned, claims)).ok)
    throw new Error("generated voucher does not verify");
  if ((await verifyDelegateKeyVoucher(bad, pinned, claims)).ok)
    throw new Error("the bad voucher verifies");

  defineExchanges(c, entry(good), entry(bad));
  for (const ex of exchanges) await writeExchange(outDir, ex, written);

  writeFileSync(path.join(outDir, "coordinates.json"), `${JSON.stringify(c, null, 2)}\n`);
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
  return `# SYNTHESISED — write-path fixtures

Everything in this directory is FABRICATED. Nothing was captured from a
live canopy, delegation coordinator or registrar. The bytes are built by
\`generate.mjs\` from the wire contract in canopy's source
(\`scrapi/register-signed-statement.ts\`, \`scrapi/query-registration-status.ts\`,
\`scrapi/resolve-receipt.ts\`, \`forest/prepare-child-log.ts\`) and the
delegation coordinator's pending-delegation and certificate routes, using
the published \`@forestrie/encoding\` encoders.

The hosts \`canopy.example.test\` and \`coordinator.example.test\` do not
exist. The UUIDs are fixed arbitrary values. Run \`generate.mjs\` again and
the unsigned files come back byte-for-byte.

## What is real elsewhere

Real recordings of the read side (status 303 to the receipt URL, the
sealed receipt, an unknown-entry status) live in \`../../lane-a-0.5.0/\`,
copied verbatim from \`@forestrie/mcp-resolve\`'s \`test/fixtures\`. No real
recording of a register, prepare, pending-delegation or certificate
exchange exists in this repository, and none is claimed here: those
exchanges are only as faithful as the contract they were written from.

## Keys (TEST ONLY)

| File | Role |
|---|---|
| \`log-key.jwk.json\` | the data log's ES256 key; \`grant.cose\` names it in \`grantData\` |
| \`other-log-key.jwk.json\` | a different log key; \`grant-other-key.cose\` names it |
| \`authority-key.jwk.json\` | the parent authority; signs the grant credentials, and the bad voucher |
| \`registrar-key.jwk.json\` | the registrar voucher key; signs \`voucher.cose\` |
| \`sealer-delegate-key.jwk.json\` | the sealer's standing delegate key (its public half rides in the voucher and standing entry) |

Each private key is committed as a JWK carrying a \`warning\` field. They are
published test keys: never trust, register, grant to, or sign with them.

## Grants and delegation material

- \`grant.cose\`, \`grant-other-key.cose\`: Forestrie-Grant credentials,
  untagged COSE Sign1, protected \`{1: -7}\`, unprotected
  \`{-65538: <grant CBOR>, -65537: <8-byte idtimestamp>}\`, payload
  \`sha256(grant CBOR)\`, signed by the authority key. The grant is a data-log
  creation grant: flags byte 3 = 0x03 (GF_CREATE|GF_EXTEND), byte 7 = 0x02
  (GF_DATA_LOG), \`logId\` ${COORDINATES.dataLogId} under
  \`ownerLogId\` ${COORDINATES.ownerLogId}, \`grantData\` the 64-byte x‖y of the
  named log key. They differ only in the key named (and so the signature).
- \`voucher.cose\`: untagged COSE Sign1 ES256 by the registrar key, payload
  the canonical CBOR map \`{1: sealerId, 2: epoch, 3: delegate COSE_Key}\`.
  \`voucher-bad.cose\` is the same claims signed by the authority key.
- \`standing-entry.json\`: the coordinator's standing entry for that voucher
  (\`delegatedPublicKey\` = base64 of the canonical COSE_Key
  \`{1: 2, -1: 1, -2: x, -3: y}\`, \`suggestedTtlSeconds\`, \`sealerId\`, \`epoch\`,
  \`voucher\`).

## Recorded exchanges

\`<name>.meta.json\` (url, method, status, headers, contentType, bodyFile,
bodyBytes, bodySha256, note) plus \`<name>.body\` when non-empty: register-303,
register-403, status-pending, status-sequenced, receipt-404, receipt-200,
prepare-201, prepare-403, pending-empty, pending-standing,
pending-standing-bad-voucher, certificate-200. The status URL names the
sha256 of a fixed placeholder string, not of any statement a test signs
(ECDSA signatures are random), and \`receipt-200\`'s body is a placeholder,
not a COSE receipt.

## Regeneration and determinism

\`node generate.mjs [outDir]\` reuses any \`*-key.jwk.json\` already in
\`outDir\`. Everything is deterministic except the ECDSA signatures (WebCrypto
ECDSA is randomised), so \`grant*.cose\`, \`voucher*.cose\`,
\`standing-entry.json\`, and the two \`pending-standing*\` exchanges differ in
their signature bytes on every run; \`test/core/fixtures.test.ts\` asserts the
committed bytes against \`manifest.json\` and checks the rest regenerate
identically.
`;
}

const isMain =
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href;
if (isMain) {
  const outDir = process.argv[2] ?? HERE;
  const result = await generate(outDir);
  console.error(`wrote ${result.files.length} files to ${result.outDir}`);
}
