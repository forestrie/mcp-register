#!/usr/bin/env node
/**
 * Exactly one copy each of every @forestrie/* wire package this repo
 * pins — @forestrie/encoding, @forestrie/scrapi-client,
 * @forestrie/receipt-verify, @forestrie/chain-rpc and
 * @forestrie/mcp-verify.
 *
 * Multiple copies of a WIRE-TYPE package (encoding: CBOR; scrapi-client:
 * the SCRAPI HTTP exchange shapes; receipt-verify: the genesis label
 * constants and known-accumulator/receipt decode this package uses;
 * chain-rpc: the JSON-RPC envelope `src/net/chain.ts` posts;
 * @forestrie/mcp-verify: the receipt-verify core this package composes
 * with) means two disagreeing implementations of the same bytes, and a
 * package that fetches material for a verifier to check cannot afford that
 * ambiguity. This is a release gate, not a lint. Adapted from
 * @forestrie/mcp-verify's scripts/check-encoding-single-copy.mjs to loop over
 * every @forestrie/* wire package this repo pins.
 *
 * Works on both layouts:
 *   pnpm  — node_modules/.pnpm/@forestrie+<name>@<v>/node_modules/@forestrie/<name>
 *   npm   — nested/flat node_modules/@forestrie/<name>/package.json
 * so the same script gates the repo AND a scratch install of the tarball.
 * The second invocation is the one that matters: it asserts what an
 * `npx -y @forestrie/mcp-register` user actually gets, under npm's flat
 * resolver, which is not what pnpm's isolated store gives us locally.
 *
 * DO NOT "fix" a red run here with a pnpm `overrides` entry for any of
 * these packages. An override SILENCES the exact skew this gate exists to
 * detect, by rewriting a transitive dep to a version its parent was never
 * tested against. If a dependency drags in a second copy, fix or drop that
 * dependency (or wait for its bump), never override.
 *
 * Usage: node scripts/check-encoding-single-copy.mjs [rootDir]
 */
import { readFileSync, readdirSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const MAX_DEPTH = 12;

// name -> expected exact pin
export const EXPECTED = {
  "@forestrie/encoding": "0.9.1",
  "@forestrie/receipt-verify": "3.1.0",
  "@forestrie/chain-rpc": "0.3.0",
  "@forestrie/scrapi-client": "0.2.4",
  "@forestrie/merklelog": "0.5.0",
  "@forestrie/delegation-cose": "0.4.0",
  "@forestrie/mcp-verify": "0.6.0",
  "@forestrie/mcp-resolve": "0.4.0",
};

/**
 * Walk every `node_modules` subtree looking for the named packages' own
 * package directories. Deliberately dumb and exhaustive rather than clever
 * about layouts: pnpm's store, npm's flat tree, npm's nested fallback and a
 * yarn `node_modules` all fall out of the same walk.
 */
export function findCopies(rootDir, names) {
  // shortName -> full name, so the walk can match by directory name alone.
  const byShort = new Map(names.map((n) => [n.split("/")[1], n]));
  // name -> version -> [paths]
  const found = new Map(names.map((n) => [n, new Map()]));

  function record(dir) {
    let pkg;
    try {
      pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
    } catch {
      return;
    }
    if (!found.has(pkg.name)) return;
    const versions = found.get(pkg.name);
    const list = versions.get(pkg.version) ?? [];
    list.push(dir);
    versions.set(pkg.version, list);
  }

  // Realpaths already walked: pnpm links the same store directory from many
  // places, and a symlink cycle must not multiply the walk.
  const visited = new Set();

  function walk(dir, depth) {
    if (depth > MAX_DEPTH) return;
    let real;
    try {
      real = realpathSync(dir);
    } catch {
      return;
    }
    if (visited.has(real)) return;
    visited.add(real);
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }
    for (const e of entries) {
      if (!e.isDirectory() && !e.isSymbolicLink()) continue;
      if (e.name === ".bin" || e.name === ".cache") continue;
      const p = join(dir, e.name);
      if (byShort.has(e.name) && dir.endsWith("@forestrie")) {
        record(p);
        // A tracked package can carry its own nested copy of another one
        // (npm's fallback when hoisting would conflict): look inside too.
        walk(join(p, "node_modules"), depth + 1);
        continue;
      }
      walk(p, depth + 1);
    }
  }

  walk(join(rootDir, "node_modules"), 0);
  return found;
}

function main() {
  const root = process.argv[2] ?? process.cwd();
  const names = Object.keys(EXPECTED);
  const found = findCopies(root, names);

  let failed = false;
  for (const name of names) {
    const versions = found.get(name);
    const expected = EXPECTED[name];

    if (versions.size === 0) {
      console.error(
        `encoding-copy check FAILED: no ${name} found under ${root}`,
      );
      failed = true;
      continue;
    }
    if (versions.size > 1) {
      console.error(`encoding-copy check FAILED: multiple ${name} versions:`);
      for (const [v, paths] of versions)
        for (const p of paths) console.error(`  ${v}  ${p}`);
      console.error(
        "Two copies of a wire-type package is two answers about the same bytes. Fix the pin, do not add an override.",
      );
      failed = true;
      continue;
    }
    const [version] = [...versions.keys()];
    if (version !== expected) {
      console.error(
        `encoding-copy check FAILED: ${name} expected exactly ${expected}, found ${version}`,
      );
      failed = true;
      continue;
    }
    console.log(
      `encoding-copy check passed: exactly one ${name} (${version}).`,
    );
  }

  if (failed) process.exit(1);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
