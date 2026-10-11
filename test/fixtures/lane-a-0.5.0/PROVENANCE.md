# lane-a-0.5.0 fixtures — the re-genesised lane A, frozen

Captured 2026-09-22, the day `@forestrie/mcp-verify` 0.5.0 released. Lane
A's content was reset and re-genesised on 2026-09-20 for the signed
checkpoint tree size (ADR-0066, devdocs plan-2609-10), so the recordings
under `../lane-a/` (2026-09-13) name a forest and a publications log that no
longer exist there. They stay as they are: frozen replays of real exchanges,
still the fixtures every unit test runs over. This directory is the same
five exchanges and one chain read against the **new** estate, for the
0.5.0 release's own registration — the pair the README's worked example
names and `test/live/lane-a.test.ts` runs against.

| Coordinate | Value |
|---|---|
| base URL | `https://api-a.forest-2.forestrie.dev` (service id `canopy-dev-1`) |
| forest bootstrap log | `e22c8d55-3f88-b2b5-f225-5d2c2441bcdd` |
| publications log | `da6f297c-4a0c-4c9a-b2ae-e701e558721d` (a data log under thinker's agent-authority log `28b2fcae-6e48-4840-981f-052e6ba80c7b`, created 2026-09-21) |
| content hash | `0d7e2978ab9839c23af68bd949c7e15de6f2f75aae5baf13e602c485e3c0354e` = sha256 of the 0.5.0 tarball's `fixtures/self/statement.cose` |
| entry id | `a0caa672b7030b000000000000000001` |
| massif height | 14 (inside the `Location` the status route returned) |
| chain | id 84532, univocity `0xe22c8d553f88b2b5f2255d2c2441bcdd0d50cd58` (bound in the genesis) |
| `logState` | block 47169412, size 3, one peak |

`coordinates.json` carries the same values for tests to read.

## Files

| Name | URL | Status | Content-Type | Body |
|---|---|---|---|---|
| well-known | `/.well-known/scitt-configuration` | 200 | `application/json` | `well-known.json` |
| genesis | `/api/forest/e22c8d55-3f88-b2b5-f225-5d2c2441bcdd/genesis` | 200 | `application/cbor` | `genesis.cbor` (160 B) |
| status-self | `/logs/e22c8d55-3f88-b2b5-f225-5d2c2441bcdd/da6f297c-4a0c-4c9a-b2ae-e701e558721d/entries/0d7e2978ab9839c23af68bd949c7e15de6f2f75aae5baf13e602c485e3c0354e` | 303 → the receipt URL | — | none |
| receipt-self | `…/14/entries/a0caa672b7030b000000000000000001/receipt` | 200 | `application/scitt.receipt+cose` | `receipt-self.cbor` (438 B) |
| status-unknown | `…/entries/0000…0000` (64 zero hex) | 303 → itself, `retry-after: 1` | — | none |
| chain | three JSON-RPC calls (`eth_chainId`, `eth_getBlockByNumber latest`, `eth_call logState`) to `https://sepolia.base.org`, a public endpoint named as a third-party example | 200 | — | `logState.47169412.json` |

`statement.cose`, `log-key.xy.b64` and `entry-id.txt` are copied
byte-for-byte from the published `@forestrie/mcp-verify@0.5.0` tarball's
`fixtures/self/`. The log owner key is the **fresh** release key the
publications log was created with; it differs from `../lane-a/`'s.

Each HTTP exchange was requested exactly once with `curl` (no redirect
following); `<name>.headers.txt` is the raw response header block,
`<name>.meta.json` the parsed record. The chain file records the three
requests and responses verbatim, the block trimmed to
`number`/`hash`/`parentHash`/`timestamp`, in the shape `../chain/`'s
`logState.46770471.json` uses so the same replay serves both.

These bytes are **FROZEN**; `manifest.json` carries their sha256 and
`test/net/scrapi.test.ts`-style pinning applies. Regenerate only by
recording again and replacing the whole directory.
