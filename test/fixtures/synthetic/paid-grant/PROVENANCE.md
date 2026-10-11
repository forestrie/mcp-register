# SYNTHESISED — paid-grant fixtures

Everything in this directory is FABRICATED. Nothing was captured from a
live canopy or x402 facilitator. The bytes are built by `generate.mjs` from
the wire contract in canopy's source: `scrapi/register-grant.ts` (the
303, the 409), `scrapi/register-grant-payment.ts` (the 402 problem and the
challenge, priced as unit price × the child grant's `maxHeight`),
`scrapi/x402.ts` (`buildPaymentRequiredHeader`, reproduced byte for byte),
`scrapi/auth-grant.ts` (the `{parentGrant}` body) and
`scrapi/grant-sequencing.ts` (the grant status URL on the owner log), using
the published `@forestrie/encoding` encoders.

The host `canopy.example.test` does not exist. The UUIDs and the payee
address are fixed arbitrary values. Run `generate.mjs` again and every
file except the two signed parent grants comes back byte-for-byte.

## The facilitator is a stub

canopy verifies an `X-PAYMENT` with an x402 facilitator before it admits a
paid grant. These fixtures record only canopy's two possible answers: 303
(the facilitator accepted) and `register-grant-402-refused` (it did not,
with its reason in `detail`). Which one a test gets is decided by
`test/net/stub-facilitator.ts`, which checks the EIP-3009 authorisation
for real (EIP-712 signature, payee, amount, network, asset, validity
window) against the recorded challenge. No facilitator was called.

## Keys (TEST ONLY)

| File | Role |
|---|---|
| `principal-key.jwk.json` | the principal that owns R's subtree; signs the authority grants |
| `authority-key.jwk.json` | the requester's authority key; the authority grants name it, and it signs child grants in the tests |

Each private key is committed as a JWK carrying a `warning` field. They are
published test keys: never trust, register, grant to, or sign with them.

The payer is Anvil's and Hardhat's account #0
(`0xf39Fd6e51aad88F6F4ce6aB8827279cffFb92266`), whose private key is in `coordinates.json`
and in every Ethereum tutorial. Never fund it: anything sent to it is taken.

## Grants

- `authority-grant.cose`: the requester's completed authority grant: an
  auth-log creation grant for O = 9d8c7b6a-5f4e-4d3c-8b2a-1f0e9d8c7b6a under
  R = 3f1c2d4e-5a6b-4c7d-8e9f-0a1b2c3d4e5f, flags byte 3 = 0x0f
  (GF_CREATE|GF_EXTEND|GF_DERIVED|GF_CHILD_PAYMENT_REQUIRED), byte 7 = 0x01
  (GF_AUTH_LOG), `grantData` the authority key's x‖y, signed by the
  principal. Its receipt (396) is a placeholder.
- `authority-grant-free.cose`: the same without the payment flags
  (byte 3 = 0x03).

## Recorded exchanges

`<name>.meta.json` plus `<name>.body` when non-empty: register-grant-402,
register-grant-402-refused, register-grant-303, register-grant-409,
grant-status-pending, grant-status-sequenced, grant-receipt-404,
grant-receipt-200. The challenge asks
8000 atomic units
(1000 per unit × maxHeight 8) of
USDC on eip155:84532. `grant-receipt-200`'s body is a placeholder.

`manifest.json` records each file's sha256; `test/core/fixtures.test.ts`
checks the committed bytes against it and checks the rest regenerate.
