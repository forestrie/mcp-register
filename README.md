# @forestrie/mcp-register

An MCP server that signs a statement and registers it on a Forestrie
transparency log, under a Forestrie-Grant you already hold. It then waits
for the seal and verifies the receipt. It is the write path of the
Forestrie MCP trio:

- [`@forestrie/mcp-verify`](https://github.com/forestrie/mcp-verify) verifies
  receipts offline.
- [`@forestrie/mcp-resolve`](https://github.com/forestrie/mcp-resolve) fetches
  receipts and the material to verify them.
- This package writes. It uses the other two as libraries.

The statement is signed with a log key the server holds. The default backend
for that key is an ES256 key file the server creates. The model never handles
signature bytes: you pass the payload and the server signs it. No tool takes
a signature as input. This package never handles money.

## Status

Pre-release, version 0.1.0, not yet published to npm.

## Tools

| Tool                  | What it does                                                                                                                                                                    |
| --------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `get_log_key`         | Returns the log key's public half (x‖y). Your grant must name this key. The key is created on first use.                                                                        |
| `delegate_sealing`    | Authorises the operator's sealer for your data log. Runs canopy's `prepare` with the same grant first if the coordinator does not know the log's public root yet. Once per log. |
| `register_statement`  | Signs a payload (inline base64 or a file path, up to 4 MiB, with an explicit content type) and registers it.                                                                    |
| `check_registration`  | Does one status check: `pending`, `awaiting_seal` or `sealed`. Once sealed, it saves the receipt.                                                                               |
| `verify_registration` | Verifies the receipt over the statement with mcp-verify's verifier and returns its four answers unaltered.                                                                      |

The prompts walk an agent through the work:

- **`register`** covers the key and the grant, sealing, registering,
  waiting, verifying and keeping the receipt.
- **`audit`** explains which trust questions a receipt answers under which
  trust root.

## Configuration

Every value can be overridden per call.

| Variable                     | Meaning                                                                    |
| ---------------------------- | -------------------------------------------------------------------------- |
| `FORESTRIE_BASE_URL`         | the canopy SCRAPI base URL                                                 |
| `FORESTRIE_ROOT_LOG_ID`      | the forest's root log id (R in `/register/{R}/entries`)                    |
| `FORESTRIE_GRANT`            | your Forestrie-Grant, as base64 or a file path                             |
| `FORESTRIE_COORDINATOR_URL`  | the delegation coordinator, for `delegate_sealing`                         |
| `FORESTRIE_KNOWN_SEALER_KEY` | the registrar's voucher key, base64 x‖y, for `delegate_sealing`            |
| `MCP_REGISTER_HOME`          | the key file and registrations, default `~/.config/forestrie/mcp-register` |
| `MCP_REGISTER_KEY_FILE`      | the log key file, default `$MCP_REGISTER_HOME/log-key.jwk`                 |

## Where grants come from

Forestrie runs no grant issuer. Whoever owns the authority log above yours
issues your grant, naming the key that `get_log_key` returns. Canopy
sequences grants; it does not issue them.

## Install

```
npx -y @forestrie/mcp-register
```

(Not yet published.)

## Layers

- `src/core` is browser-safe and works on bytes only.
- `src/net` is the only place `fetch` is called, always through an injected
  `fetchImpl`.
- `src/node` holds the MCP SDK, stdio, the filesystem and the key file.

See [AGENTS.md](AGENTS.md).

## Licence

MIT.
