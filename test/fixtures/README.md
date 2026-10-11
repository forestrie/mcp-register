# Test fixtures

| Directory | Where it came from | Real or fabricated |
|---|---|---|
| `lane-a-0.5.0/` | Copied verbatim from `@forestrie/mcp-resolve`'s `test/fixtures/lane-a-0.5.0`: recordings of a live Forestrie lane, taken 2026-09-22 | Real, frozen. Do not edit; `manifest.json` pins every byte |
| `synthetic/write-path/` | Generated here by `synthetic/write-path/generate.mjs` from canopy's and the delegation coordinator's wire contract | Fabricated: no live service was contacted. Test-only keys are committed on purpose |

Each directory has a `PROVENANCE.md` saying what is real and what is not, and a
`manifest.json` of sha256 digests that `test/core/fixtures.test.ts` checks.

The replay helper that serves these as fetch responses is
`test/net/replay.ts`.
