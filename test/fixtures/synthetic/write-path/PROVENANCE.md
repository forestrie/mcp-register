# SYNTHESISED — write-path fixtures

Everything in this directory is FABRICATED. Nothing was captured from a
live canopy, delegation coordinator or registrar. The bytes are built by
`generate.mjs` from the wire contract in canopy's source
(`scrapi/register-signed-statement.ts`, `scrapi/query-registration-status.ts`,
`scrapi/resolve-receipt.ts`, `forest/prepare-child-log.ts`) and the
delegation coordinator's pending-delegation and certificate routes, using
the published `@forestrie/encoding` encoders.

The hosts `canopy.example.test` and `coordinator.example.test` do not
exist. The UUIDs are fixed arbitrary values. Run `generate.mjs` again and
the unsigned files come back byte-for-byte.

## What is real elsewhere

Real recordings of the read side (status 303 to the receipt URL, the
sealed receipt, an unknown-entry status) live in `../../lane-a-0.5.0/`,
copied verbatim from `@forestrie/mcp-resolve`'s `test/fixtures`. No real
recording of a register, prepare, pending-delegation or certificate
exchange exists in this repository, and none is claimed here: those
exchanges are only as faithful as the contract they were written from.

## Keys (TEST ONLY)

| File | Role |
|---|---|
| `log-key.jwk.json` | the data log's ES256 key; `grant.cose` names it in `grantData` |
| `other-log-key.jwk.json` | a different log key; `grant-other-key.cose` names it |
| `authority-key.jwk.json` | the parent authority; signs the grant credentials, and the bad voucher |
| `registrar-key.jwk.json` | the registrar voucher key; signs `voucher.cose` |
| `sealer-delegate-key.jwk.json` | the sealer's standing delegate key (its public half rides in the voucher and standing entry) |

Each private key is committed as a JWK carrying a `warning` field. They are
published test keys: never trust, register, grant to, or sign with them.

## Grants and delegation material

- `grant.cose`, `grant-other-key.cose`: Forestrie-Grant credentials,
  untagged COSE Sign1, protected `{1: -7}`, unprotected
  `{-65538: <grant CBOR>, -65537: <8-byte idtimestamp>}`, payload
  `sha256(grant CBOR)`, signed by the authority key. The grant is a data-log
  creation grant: flags byte 3 = 0x03 (GF_CREATE|GF_EXTEND), byte 7 = 0x02
  (GF_DATA_LOG), `logId` 7a8b9c0d-1e2f-4a3b-8c4d-5e6f7a8b9c0d under
  `ownerLogId` 9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a, `grantData` the 64-byte x‖y of the
  named log key. They differ only in the key named (and so the signature).
- `voucher.cose`: untagged COSE Sign1 ES256 by the registrar key, payload
  the canonical CBOR map `{1: sealerId, 2: epoch, 3: delegate COSE_Key}`.
  `voucher-bad.cose` is the same claims signed by the authority key.
- `standing-entry.json`: the coordinator's standing entry for that voucher
  (`delegatedPublicKey` = base64 of the canonical COSE_Key
  `{1: 2, -1: 1, -2: x, -3: y}`, `suggestedTtlSeconds`, `sealerId`, `epoch`,
  `voucher`).

## Recorded exchanges

`<name>.meta.json` (url, method, status, headers, contentType, bodyFile,
bodyBytes, bodySha256, note) plus `<name>.body` when non-empty: register-303,
register-403, status-pending, status-sequenced, receipt-404, receipt-200,
prepare-201, prepare-403, pending-empty, pending-standing,
pending-standing-bad-voucher, certificate-200. The status URL names the
sha256 of a fixed placeholder string, not of any statement a test signs
(ECDSA signatures are random), and `receipt-200`'s body is a placeholder,
not a COSE receipt.

## Regeneration and determinism

`node generate.mjs [outDir]` reuses any `*-key.jwk.json` already in
`outDir`. Everything is deterministic except the ECDSA signatures (WebCrypto
ECDSA is randomised), so `grant*.cose`, `voucher*.cose`,
`standing-entry.json`, and the two `pending-standing*` exchanges differ in
their signature bytes on every run; `test/core/fixtures.test.ts` asserts the
committed bytes against `manifest.json` and checks the rest regenerate
identically.
