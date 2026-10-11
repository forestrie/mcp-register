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
 * Not vacuous, and fails closed: the walk must also see both hosts, and an
 * unreadable directory, a package.json that does not parse, or the depth
 * limit is a failure (a tree it could not read is a check that did not run,
 * never a pass). Symlinks are followed once each, by realpath.
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
import { existsSync, readFileSync, readdirSync, realpathSync } from "node:fs";
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
  /** Why the walk could not vouch for the tree; any entry fails the gate. */
  const problems = [];
  // Realpaths already walked: pnpm links one store directory from many
  // places, and a symlink cycle must not multiply the walk.
  const visited = new Set();

  /** The package name, `undefined` for a container (no package.json), or
   *  a problem recorded when a package.json exists but cannot be read. */
  function pkgNameOf(dir) {
    let text;
    try {
      text = readFileSync(join(dir, "package.json"), "utf8");
    } catch (err) {
      if (err?.code === "ENOENT" || err?.code === "ENOTDIR") return undefined;
      problems.push(
        `cannot read ${join(dir, "package.json")}: ${err?.message ?? err}`,
      );
      return undefined;
    }
    try {
      const pkg = JSON.parse(text);
      if (typeof pkg.name === "string") return pkg.name;
    } catch {
      // fall through
    }
    problems.push(
      `${join(dir, "package.json")} is not a package.json with a name`,
    );
    return undefined;
  }

  function walk(dir, depth) {
    let real;
    try {
      real = realpathSync(dir);
    } catch (err) {
      if (err?.code === "ENOENT") return;
      problems.push(`cannot resolve ${dir}: ${err?.message ?? err}`);
      return;
    }
    if (visited.has(real)) return;
    visited.add(real);
    if (depth > maxDepth) {
      problems.push(`depth limit ${maxDepth} reached at ${dir}`);
      return;
    }
    let entries;
    try {
      entries = readdirSync(dir, { withFileTypes: true });
    } catch (err) {
      if (err?.code === "ENOENT" || err?.code === "ENOTDIR") return;
      problems.push(`cannot list ${dir}: ${err?.message ?? err}`);
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
        // `<name>@<version>` store-key entries, which hold the real package
        // one level further down, inside their own `node_modules`.
        walk(p, depth + 1);
      }
    }
  }

  walk(join(rootDir, "node_modules"), 0);
  return { hits, seen, problems };
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
  const { hits, seen, problems } = scanInstalledTree(repoRoot);
  if (problems.length > 0) {
    console.error(
      "reverse-dependency check FAILED: the walk could not read the whole tree, so it cannot vouch for it:",
    );
    for (const p of problems) console.error(`  ${p}`);
    process.exit(1);
  }
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
