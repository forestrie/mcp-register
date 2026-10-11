# AGENTS.md — conventions for this repo

Read this before changing anything. Most of it is not style; it is the set of
invariants that make the package's claims checkable, and each one is enforced
by something that will go red.

This repo is the write path of the Forestrie MCP trio: it signs statements
with a log key held behind a signer backend, registers them under a
Forestrie-Grant the caller holds, delegates sealing for the caller's data log,
and verifies the receipt by composing `@forestrie/mcp-resolve` (fetching) and
`@forestrie/mcp-verify` (verifying) as libraries. As the requester it also
issues child grants with a separate authority key and registers them,
paying canopy's x402 charge through a payer backend within hard caps, or
relaying the payment requirements when no payer is configured.

**`@forestrie/mcp-verify` and `@forestrie/mcp-resolve` are dependencies, never
siblings; changes to them happen in their repos.** This package imports only
their published exports. A missing export needs a release there, and this repo
waits for the bump.

## The layer boundary

This is the most important thing in the repo. Three layers.

|              | `src/core/`                                                                                                                           | `src/net/`                                                                                                                             | `src/node/`                                                                   |
| ------------ | ------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| What it is   | Pure over bytes: request construction, response classification, compose logic over already-fetched bytes.                             | The ONLY place `fetch` is called: thin functions over the registration endpoints.                                                      | The adapter: MCP SDK, stdio, filesystem, the signer backend and the key file. |
| Exported as  | `"."`                                                                                                                                 | `"./net"`                                                                                                                              | `"./server"`                                                                  |
| **Must not** | import `node:*`, call `fetch`, read a file, touch the MCP SDK or key material, or take a path or a base64 string as a parameter       | call `fetch` without going through a `fetchImpl` parameter                                                                             | leak back into `src/core` or `src/net`                                        |
| May          | take and return `Uint8Array`                                                                                                          | take and return `Uint8Array`; every function takes `fetchImpl` defaulting to `globalThis.fetch`                                        | do anything Node can                                                          |
| Enforced by  | `pnpm run check:browser-safe` — esbuild bundles `src/core/index.ts` for `platform: "browser"` and fails on any edge to a node builtin | the unit test project's forbidden-fetch global (below); no automated proof that every call site injects `fetchImpl` — reviewed by hand | the same browser-safe gate, from the other side                               |

Every core signature takes `Uint8Array`, never a path and never a base64
string. Base64 decoding and `{path}` resolution live in `src/node/`, which
together with `src/net/` is the **only** place `node:fs` and `fetch` appear.

## Signing keys

The log key is ES256. Every signature this package makes — statements, the
delegation certificate, the on-chain delegation proof — goes through one seam,
`Es256Signer` (`src/core/signer.ts`): `src/core` builds the exact bytes to be
signed and calls `sign(bytes)`; it never holds a key. The default backend,
`src/node/signer-file.ts`, keeps a P-256 JWK in a local file it creates on
first use: `0600` in a `0700` directory, written aside and hard-linked into
place (atomic, never overwritten), and refused, as ssh refuses a loose key,
if it is a symlink or accessible to other users. Read-only tools open it
without creating it. An embedder passes its own signer
(`createServer({ signer })`) for a KMS or a remote signer.

The requester's authority key, which signs the child grants `issue_grant`
makes, is a second ES256 key behind the same seam (`authoritySigner`), in its
own file (`authority-key.jwk`, or `MCP_REGISTER_AUTHORITY_KEY_FILE`). It is
separate from the log key so that whoever can write to the data log cannot
issue grants under the authority log. `src/core/issue.ts` builds the grant
bytes of `@forestrie/grant-builder`'s ES256 profile over the seam;
`test/node/grant-tools.test.ts` asserts they equal grant-builder's own
output (a dev dependency only) but for the signature.

No `{path}` input (a payload, a grant, a known accumulator) may resolve to
any key file or anywhere under the server's home: otherwise a
prompt-injected caller could have a private key signed and registered on a
public log. `test/node/tools.test.ts` and `test/node/grant-tools.test.ts`
cover it.

## Paying

The payer is a third key, and not an ES256 one: an EVM account behind the
`PayerBackend` seam (`src/node/payer.ts`). The default backend is a viem
account loaded from `MCP_REGISTER_PAYER_KEY_FILE`, refused like the log key
if it is a symlink or readable by others. An embedder passes its own
(`createServer({ payer })`). It is never created, and with none configured
`register_grant` runs in relay mode: it returns canopy's payment
requirements and resumes on a call that carries the caller's `X-PAYMENT`.

**One grant is never paid for twice, by construction.** Every EIP-3009
authorisation this server signs for a grant carries
`grantPaymentNonce(grant content, payer address)` (`src/core/x402.ts`), and
the token contract settles at most one authorisation per (payer, nonce);
canopy's claim and settlement de-duplication are keyed by the nonce too. So
overlapping calls, a retry after a lost answer and a second process sharing
the payer all sign the same nonce, and there is no lock. `register_grant`
refuses to send a payment that does not carry it, so a hosted-wallet
`PayerBackend` must honour the nonce it is given. The upstream x402 client
(`@x402/evm`) draws a random nonce and cannot be given one, so the default
backend builds the same payload itself; `test/node/payer.test.ts` checks it
field for field against the upstream client, which is a dev dependency only.

The caps (`MCP_REGISTER_PAY_*`) are read from the environment and never from
a tool argument; `test/node/mcp-smoke.test.ts` asserts no input schema has a
cap or payer field. `src/core/x402.ts` applies them in a fixed order
(testnet only, network, asset, payee, resource, per call, per day), and
`register_grant` refuses any canopy other than `FORESTRIE_BASE_URL`. Each
signed payment is written to the spend ledger
(`<home>/payments/<UTC day>.jsonl`) before it is sent; a nonce counts once.
The daily cap is approximate under concurrency, deliberately: calls that pass
the check before either is recorded can overshoot it by one per-call cap
each.

Signature bytes never cross the MCP boundary as tool inputs: a tool takes the
payload to sign, not a signature. `test/node/mcp-smoke.test.ts` asserts that
no tool's input schema has a signature or key field. Private key material
never enters `src/core` or `src/net`, and is never written to stdout, to a log
line or to a tool result.

## The gates

All CI-blocking, checked before every merge:

1. **`check:browser-safe`** — esbuild bundles `src/core/index.ts` for
   `platform: "browser"` and fails on any `node:*` edge.
2. **No fetch in core, no un-injected fetch in net** — the vitest `unit`
   project replaces `globalThis.fetch` with a thrower for the whole run
   (`test/setup/forbid-fetch.ts`); `src/net` is tested only through injected
   fakes. Any real fetch in a unit test is a red test, not a slow one.
3. **`check:encoding-single-copy`** — exactly one copy of each
   `@forestrie/*` package this repo pins (and the wire packages they pull in),
   run on the repo and on a scratch `npm i` of the packed tarball.
4. **`check:reverse-dependency`** — nothing this package depends on may
   depend back on `@forestrie/mcp-register` (above all, `@forestrie/mcp-verify`
   and `@forestrie/mcp-resolve` must stay read-only). Walks the repo's whole
   installed tree, pnpm's `.pnpm` store included, which holds every
   transitive dependency, and fails on any package of that name. Offline. It
   also fails unless the walk saw both mcp-verify and mcp-resolve, so it can
   never pass by looking at nothing.
5. **`check:stdio-clean`** — the real bin writes exactly one `initialize`
   response to stdout and nothing else.
6. **`check:server-json`** — `server.json` validates with ajv against the
   registry schema vendored at `tools/registry-schema/2025-12-11.json` and
   matches `package.json#mcpName` and `#version`, so npm never publishes a
   `server.json` the registry rejects.

The `live` vitest project (`pnpm test:live`) makes real requests, is opt-in by
`FORESTRIE_LIVE=1`, and is never a required check.

## All relative imports end in `.js`

`tsconfig.json` uses `moduleResolution: "bundler"` for typechecking, but
`tsconfig.build.json` overrides it to `NodeNext` for emit. That is deliberate:
`bundler` resolution lets you write extensionless relative imports that Node's
ESM loader then rejects at runtime — a failure that only appears _after
publish_. Under `NodeNext`, `pnpm build` fails instead.

So: `import { x } from "./thing.js"`, always, even from a `.ts` file.

## Dependencies are exact, and bumped deliberately

`@forestrie/*` and the MCP SDK are pinned to exact versions. There is no
Renovate and no Dependabot in this estate, so exact pins are a manual-bump
discipline, not accidental staleness.

**Never add `pnpm.overrides` for any `@forestrie/*` package.** An override
would _silence_ the exact skew `scripts/check-encoding-single-copy.mjs` exists
to detect, by rewriting a transitive dependency to a version its parent was
never tested against. If a dependency drags in a second copy, fix or drop that
dependency, or wait for its bump — never an override.

Bump in dependency order: `@forestrie/mcp-verify` first, then
`@forestrie/mcp-resolve` (which pins the verifier exactly), then this
package, pinning the verifier at the version mcp-resolve pins. Pinning a
newer verifier than mcp-resolve's puts two copies of the wire packages in
the tree, and `check:encoding-single-copy` fails.

When you bump a version, update `src/core/version.ts` in the same commit.
`test/core/version.test.ts` asserts every `*_VERSION` constant equals the
matching pin in `package.json#dependencies`, and the MCP smoke test asserts
`PACKAGE_VERSION === package.json#version`, so a forgotten bump is a red test
rather than a silent lie.

## Nothing writes to stdout in stdio mode except the transport

A stray `console.log` in `src/node/**` does not produce a warning. It produces
a malformed JSON-RPC frame and an MCP client that mysteriously fails to
initialise. All logging goes to **stderr**.

`pnpm run check:stdio-clean` spawns the real bin and asserts stdout carries
exactly one well-formed `initialize` response and nothing else. Related:
`main()` returns an exit code and does **not** call `process.exit`.

## The honesty rule

Verification results pass through `@forestrie/mcp-verify`'s answers
unaltered: this package may add rows about where bytes came from and what was
registered, and never edits the verifier's answers. `verify_registration`
names the trust root it used and where that root came from (this server's
key file, or supplied by the caller), and its default root — the log key —
answers what a signature root answers and no more: the verifier says
`not_answered_by_this_root` for split-view, and that answer reaches the
caller. The wording of the tool descriptions and the `register` and `audit`
prompts (`src/node/text.ts`) is deliberate; change it on purpose, never in
passing.

## Fixtures

`test/fixtures/synthetic/paid-grant/` is synthesised the same way from
canopy's register-grant and x402 source (the 402 challenge, a refused
payment, the 303, the grant's status and receipt); there is no facilitator
in it. `test/net/stub-facilitator.ts` stands in for one: it verifies each
`X-PAYMENT`'s EIP-712 signature and terms against the recorded challenge and
picks canopy's answer accordingly.

`test/fixtures/lane-a-0.5.0/` is real: lane A recordings copied verbatim from
`@forestrie/mcp-resolve`'s frozen fixtures, used to prove the status, receipt
and verification path on real bytes. `test/fixtures/synthetic/write-path/` is
synthesised from canopy's source contract (register, prepare,
pending-delegation, certificate), because recording those needs a live grant
on a lane. Each directory has a `PROVENANCE.md` and a sha256 `manifest.json`
that the tests check. A live recording of the write path is the system-testing
suite's job, not this repo's.

## Tests

```
pnpm test              # check:browser-safe && check:encoding-single-copy && check:reverse-dependency && check:server-json && unit
pnpm test:unit         # vitest --project unit
pnpm test:live         # vitest --project live (opt-in, FORESTRIE_LIVE=1, never required)
pnpm typecheck
pnpm format:check
pnpm build
```

## Releasing

Merge a version-bump PR, then `git tag v<version> && git push --tags`.
`scripts/assert-publish-version.sh` makes a mistyped tag fail closed.

1. Bump `version` in `package.json` **and** `PACKAGE_VERSION` in
   `src/core/version.ts` in the same PR.
2. Bump `version` (and `packages[0].version`) in `server.json` to match.
   `scripts/assert-server-json.mjs` fails closed if they disagree, or if
   `server.json#name` no longer matches `package.json#mcpName`.
3. Merge to `main`, then tag.
4. `.github/workflows/publish.yml` asserts the tag matches `package.json`,
   runs the full gate, builds, packs, and publishes to npm via OIDC trusted
   publishing with provenance, then lists `dev.forestrie/register` with the
   official MCP registry. It has no self-registration step.

The first publish must be by hand: npm cannot register a trusted publisher
for a package that does not exist yet. The trusted publisher is GitHub
Actions, org `forestrie`, repo `mcp-register`, workflow `publish.yml`,
environment `npm-publish`.

## Links must resolve without org access

Every link in the README, in `--help` text, and in `server.json` must resolve
for someone with no GitHub org membership. Where an internal document is the
source, inline what is needed and cite it by name, not by URL.
