# @forestrie/mcp-register

An MCP server that signs a statement and registers it on a Forestrie
transparency log under a Forestrie-Grant, then waits for the seal and
verifies the receipt. It can also buy the grant: as the requester, it signs a
child grant under your own authority log and registers it with canopy,
paying canopy's x402 charge within hard caps. It is the write path of the
Forestrie MCP trio:

- [`@forestrie/mcp-verify`](https://github.com/forestrie/mcp-verify) verifies
  receipts offline.
- [`@forestrie/mcp-resolve`](https://github.com/forestrie/mcp-resolve) fetches
  receipts and the material to verify them.
- This package writes. It uses the other two as libraries.

The statement is signed with a log key the server holds. The default backend
for that key is an ES256 key file the server creates. Child grants are signed
with a separate authority key, held the same way. The model never handles
signature bytes: you pass the payload and the server signs it. No tool takes
a signature or a key as input.

Paying is optional, and the payer is yours. The server never creates a payer
key and holds no funds of its own: you choose how payment happens (see
[Choosing a payer](#choosing-a-payer)). Whichever you choose, a payer key
never crosses the MCP boundary, and the spending caps are configuration, not
tool arguments. With no payer configured, the server spends nothing: it
returns canopy's payment requirements, and you pay from your own x402 wallet
(relay mode).

## Status

Version 0.1.1 on npm, published with provenance from `publish.yml`. 0.1.0 was published by hand and has no provenance attestation; use 0.1.1 or later.

## Tools

| Tool                  | What it does                                                                                                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `get_log_key`         | Returns the log key's public half (x‖y). Your grant must name this key. The key is created on first use.                                                                        |
| `delegate_sealing`    | Authorises the operator's sealer for your data log. Runs canopy's `prepare` with the same grant first if the coordinator does not know the log's public root yet. Once per log. |
| `register_statement`  | Signs a payload (inline base64 or a file path, up to 4 MiB, with an explicit content type) and registers it.                                                                    |
| `check_registration`  | Does one status check: `pending`, `awaiting_seal` or `sealed`. Once sealed, it saves the receipt.                                                                               |
| `verify_registration` | Verifies the receipt over the statement with mcp-verify's verifier and returns its four answers unaltered.                                                                      |
| `issue_grant`         | As the requester, signs a child data-log grant with the authority key, naming a log key (by default this server's), sized with `maxHeight`. Sends nothing.                      |
| `register_grant`      | Registers the child grant with canopy, pays its 402 within the caps or relays the requirements, and follows it to its receipt. Resumable by child log id; never pays twice.     |

The prompts walk an agent through the work:

- **`register`** covers the key and the grant, sealing, registering,
  waiting, verifying and keeping the receipt.
- **`audit`** explains which trust questions a receipt answers under which
  trust root.
- **`issue-and-pay`** covers buying a grant as the requester: sizing it,
  issuing it, paying within the caps or relaying the payment, and handing
  the completed grant to the performer.

## Configuration

Every value can be overridden per call.

| Variable                          | Meaning                                                                                           |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| `FORESTRIE_BASE_URL`              | the canopy SCRAPI base URL                                                                        |
| `FORESTRIE_ROOT_LOG_ID`           | the forest's root log id (R in `/register/{R}/entries`)                                           |
| `FORESTRIE_GRANT`                 | your Forestrie-Grant, as base64 or a file path                                                    |
| `FORESTRIE_COORDINATOR_URL`       | the delegation coordinator, for `delegate_sealing`                                                |
| `FORESTRIE_KNOWN_SEALER_KEY`      | the registrar's voucher key, base64 x‖y, for `delegate_sealing`                                   |
| `FORESTRIE_AUTHORITY_GRANT`       | your authority log's grant, for `issue_grant` and `register_grant`                                |
| `MCP_REGISTER_HOME`               | key files, grants, registrations and the spend ledger, default `~/.config/forestrie/mcp-register` |
| `MCP_REGISTER_KEY_FILE`           | the log key file, default `$MCP_REGISTER_HOME/log-key.jwk`                                        |
| `MCP_REGISTER_AUTHORITY_KEY_FILE` | the authority key file, default `$MCP_REGISTER_HOME/authority-key.jwk`                            |

### Choosing a payer

Whoever wants the work done pays for it: the requester, paying canopy
directly. The server supports three ways to do that and prefers none of them.

| Setup            | What you configure                                                                         | Who holds the key                                                                                                                |
| ---------------- | ------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------------------------------------- |
| Relay            | nothing                                                                                    | your own x402 wallet: `register_grant` returns canopy's payment requirements and resumes on a call that carries your `X-PAYMENT` |
| Key file         | `MCP_REGISTER_PAYER_KEY_FILE` and the caps below                                           | a file on the machine that runs the server                                                                                       |
| Your own backend | `createServer({ payer })` from `@forestrie/mcp-register/server`, when you embed the server | whatever your `PayerBackend` uses: a hosted wallet, a KMS, a remote signer                                                       |

A backend of your own must sign an EIP-3009 authorisation with the nonce it
is given. That nonce is what stops one grant being paid for twice (see
[Payment settings](#payment-settings)).

#### Example: a dedicated key file

This is one way to set up the key-file payer, not the way. Any EVM account
works; what matters is that it pays for this and nothing else.

1. Create a private key in a file only you can read. Any wallet tool that
   exports a raw private key will do. With no extra tools:

   ```
   ( umask 077; printf '0x%s\n' "$(openssl rand -hex 32)" > payer.key )
   ```

   The server accepts one line, `0x` and 64 hex digits, in a regular file
   (not a symlink) that no other user can read.

2. Find the account's address with a tool you already trust to derive one
   from a private key, or by importing the key into a wallet you use.

3. Fund the address with the asset canopy charges in. On the default
   network, Base Sepolia, that is testnet USDC, from
   [Circle's faucet](https://faucet.circle.com). The account needs no ETH:
   it only signs an authorisation, and the x402 facilitator submits the
   transfer and pays its gas.

4. Point the server at the file and set the caps:

   ```
   MCP_REGISTER_PAYER_KEY_FILE=/path/to/payer.key
   MCP_REGISTER_PAY_MAX_PER_CALL=100000   # $0.10
   MCP_REGISTER_PAY_MAX_PER_DAY=1000000   # $1.00
   ```

Keep one account per requester. Payments settle on chain, so anyone can link
a payer address to the grants it paid for. To rotate the key, create a new
one, move what is left to it, and point `MCP_REGISTER_PAYER_KEY_FILE` at the
new file.

### Payment settings

These are read from the environment only. No tool argument can set or raise
them.

| Variable                         | Meaning                                                                          |
| -------------------------------- | -------------------------------------------------------------------------------- |
| `MCP_REGISTER_PAYER_KEY_FILE`    | an EVM private key (`0x` + 64 hex, mode 600) that pays; unset means relay mode   |
| `MCP_REGISTER_PAY_MAX_PER_CALL`  | the most one payment may be, in the asset's atomic units (required with a payer) |
| `MCP_REGISTER_PAY_MAX_PER_DAY`   | the most all payments in one UTC day may total (required with a payer)           |
| `MCP_REGISTER_PAY_NETWORK`       | the one network it pays on, default `eip155:84532` (Base Sepolia)                |
| `MCP_REGISTER_PAY_ASSET`         | the one asset it pays in, default USDC on Base Sepolia                           |
| `MCP_REGISTER_PAY_TO`            | optional: the only payee                                                         |
| `MCP_REGISTER_PAY_ALLOW_MAINNET` | `1` to pay on a network that is not a testnet; off by default                    |

The server pays only the canopy named in `FORESTRIE_BASE_URL`, and only for
the request it made. Every payment it signs for a grant uses a nonce derived
from that grant, so the token contract can settle at most one of them: a
retry or two overlapping calls never pay for one grant twice. Each signed
payment is written to the spend ledger before it is sent and counts toward
the daily cap whether or not it settles. The daily cap is approximate when
calls overlap. USDC has 6 decimals, so `10000` is $0.01.

## Where grants come from

Forestrie runs no grant issuer. Whoever owns the authority log above yours
issues your grant, naming the key that `get_log_key` returns. Canopy
sequences grants; it does not issue them.

That owner can be you. If the owner of the root above you creates an
authority log for your authority key (`get_log_key` with
`which: "authority"` returns it as a PEM for forestrie-cli's
`create-log --auth-log --signer-pem`), `issue_grant` and `register_grant`
let you issue and register your own child grants. If that authority log
carries the child-payment-required flag, each registration is paid for over
x402, straight to the transparency operator.

## Install

```
npx -y @forestrie/mcp-register
```

## Layers

- `src/core` is browser-safe and works on bytes only.
- `src/net` is the only place `fetch` is called, always through an injected
  `fetchImpl`.
- `src/node` holds the MCP SDK, stdio, the filesystem, the key files and the
  payer.

See [AGENTS.md](AGENTS.md).

## Licence

MIT.
