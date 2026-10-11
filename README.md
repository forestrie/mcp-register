# @forestrie/mcp-register

An MCP server for the write path of the Forestrie MCP trio. It signs a
statement with a log key held behind a signer backend (by default a local
ES256 key file it creates), registers the statement on a Forestrie
transparency log under a Forestrie-Grant you hold, delegates sealing for your
data log, and verifies the receipt by composing
[`@forestrie/mcp-resolve`](https://github.com/forestrie/mcp-resolve) (which
only fetches) and
[`@forestrie/mcp-verify`](https://github.com/forestrie/mcp-verify) (which
verifies offline) as libraries.

The model never handles signature bytes: signing happens inside the server,
and no tool takes a signature as input. This release never handles money.

## Status

Pre-release, version 0.1.0. This package is a skeleton: the server starts and
answers `initialize`, and registers **no tools yet**. Phase 1 scope, coming in
the next change:

- `register_statement`: sign a statement and register it under your grant.
- `delegate_sealing`: delegate sealing for your data log.
- Prompts `register` and `audit`.

## Install

Not yet published to npm.

```
npx -y @forestrie/mcp-register
```

## Layers

`src/core` is browser-safe and pure over bytes; `src/net` is the only place
`fetch` is called, always through an injected `fetchImpl`; `src/node` is the
MCP SDK, stdio, the filesystem and the key file. See [AGENTS.md](AGENTS.md).

## Licence

MIT.
