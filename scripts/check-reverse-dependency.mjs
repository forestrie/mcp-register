#!/usr/bin/env node
/**
 * Neither @forestrie/mcp-verify nor @forestrie/mcp-resolve may depend back on
 * @forestrie/mcp-register.
 *
 * This package (@forestrie/mcp-register) depends on both, with exact pins
 * (see package.json#dependencies), and composes them as libraries. Neither
 * may depend back on this package: a cycle would mean their own dependency
 * trees pull in a second, possibly divergent copy of mcp-register, and would
 * make "install mcp-verify alone" or "install mcp-resolve alone" pull in a
 * signing MCP server nobody asked for.
 *
 * How: walk this repo's whole installed tree (node_modules, including
 * pnpm's `.pnpm` store, which holds every transitive dependency) and fail on
 * any package named @forestrie/mcp-register. This package is never installed
 * into its own node_modules, so a copy there means some dependency — mcp-verify,
 * mcp-resolve or anything beneath them — depends back on it. Offline, and it
 * covers every dependency, not just the two hosts.
 *
 * Whether a published package depends on mcp-register is fixed by its
 * manifest, which is immutable at an exact pin, and pnpm installs every
 * declared dependency just as npm does; so this tree is sufficient evidence
 * and a scratch `npm i` would add a network round trip and nothing else.
 *
 * Not vacuous: the walk must also see both hosts, or the check fails (an
 * uninstalled or unreadable tree is a check that did not run, never a pass).
 *
 * Works on both node_modules layouts:
 *   pnpm  — node_modules/.pnpm/<key>/node_modules/<scope>/<name>
 *   npm   — nested/flat node_modules/<scope>/<name>/package.json
 * by walking generically and reading each candidate's package.json `name`
 * rather than trusting a directory name — a pnpm store key or an npm alias
 * can rename the folder without renaming the package.
 *
 * Usage: node scripts/check-reverse-dependency.mjs [repoRoot]
 */
import { existsSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const TARGET = "@forestrie/mcp-register";
/** The packages that must not contain TARGET anywhere in their trees. */
export const HOSTS = ["@forestrie/mcp-verify", "@forestrie/mcp-resolve"];
const MAX_DEPTH = 16;

/**
 * Pure: walk `rootDir/node_modules` and return every directory whose own
 * package.json declares `name === "@forestrie/mcp-register"`. Handles pnpm's
 * `.pnpm/<key>/node_modules/<scope>/<name>` store layout and plain nested
 * `node_modules/<scope>/<name>` alike, because both fall out of the same
 * walk: an entry with its own package.json is a package (checked, then
 * recursed into via its own node_modules); an entry without one — a scope
 * directory, `.pnpm` itself, or one of its store-key directories — is just
 * a container, recursed into directly. No layout-specific special-casing.
 */
export function findMcpRegisterCopies(rootDir, maxDepth = MAX_DEPTH) {
  return scanInstalledTree(rootDir, maxDepth).hits;
}

/**
 * Pure: the same walk, also returning every package name it saw, so the
 * caller can prove the walk covered what it should have.
 */
export function scanInstalledTree(rootDir, maxDepth = MAX_DEPTH) {
  const hits = [];
  const seen = new Set();

  function pkgNameOf(dir) {
    try {
      const pkg = JSON.parse(readFileSync(join(dir, "package.json"), "utf8"));
      return typeof pkg.name === "string" ? pkg.name : undefined;
    } catch {
      return undefined;
    }
  }

  function walk(dir, depth) {
    if (depth > maxDepth) return;
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
      const name = pkgNameOf(p);
      if (name !== undefined) {
        // `p` has its own package.json: it's a real package directory.
        seen.add(name);
        if (name === TARGET) hits.push(p);
        walk(join(p, "node_modules"), depth + 1);
      } else {
        // No package.json of its own: a scope directory (`@forestrie`), or
        // one of pnpm's containers — `.pnpm` itself, or one of its
        // `<name>@<version>` / `@scope+name@<version>` store-key entries,
        // which hold the real package one level further down, inside their
        // own `node_modules`. All of these are just containers; recurse
        // straight into them (not through a `node_modules` hop, since they
        // don't have deps of their own — their *contents* do).
        walk(p, depth + 1);
      }
    }
  }

  walk(join(rootDir, "node_modules"), 0);
  return { hits, seen };
}

function report(label, hits) {
  if (hits.length === 0) {
    console.log(
      `reverse-dependency check passed: ${label} — no nested ${TARGET}.`,
    );
    return true;
  }
  console.error(
    `reverse-dependency check FAILED: ${label} — ${TARGET} found at:`,
  );
  for (const h of hits) console.error(`  ${h}`);
  return false;
}

function main() {
  const repoRoot = process.argv[2] ?? process.cwd();
  if (!existsSync(join(repoRoot, "node_modules"))) {
    console.error(
      `reverse-dependency check FAILED: no node_modules under ${repoRoot} — run \`pnpm install\` first.`,
    );
    process.exit(1);
  }
  const { hits, seen } = scanInstalledTree(repoRoot);
  const unseen = HOSTS.filter((h) => !seen.has(h));
  if (unseen.length > 0) {
    console.error(
      `reverse-dependency check FAILED: the walk never saw ${unseen.join(", ")}, so it cannot vouch for their trees — is \`pnpm install\` complete?`,
    );
    process.exit(1);
  }
  if (!report(`installed tree of ${repoRoot} (${seen.size} packages)`, hits))
    process.exit(1);
}

function isMain() {
  return process.argv[1] === fileURLToPath(import.meta.url);
}

if (isMain()) {
  main();
}
