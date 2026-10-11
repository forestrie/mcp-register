#!/usr/bin/env node
/**
 * The registry-listing version guard, copied from @forestrie/mcp-verify's
 * scripts/assert-server-json.mjs.
 *
 * server.json's `version` (and `packages[0].version`) cannot be read from
 * package.json at build time — it is a static file the MCP registry fetches
 * over HTTP, not a build artifact — so a version bump can silently leave it
 * behind. This script is the release gate that makes that impossible:
 *
 *   - server.json#version         === package.json#version
 *   - server.json#packages[0].version === package.json#version
 *   - server.json#name            === package.json#mcpName
 *   - server.json#description     non-empty, at most 100 characters (registry schema)
 *   - server.json validates against the vendored registry schema
 *     (tools/registry-schema/2025-12-11.json) — the exact $schema
 *     server.json names, not just the two hand-picked caps above.
 *
 * A mismatch on any of these is a hard failure, not a warning — an
 * out-of-date server.json is a false claim to a registry an outside agent
 * queries directly, and package.json#mcpName is what the registry checks
 * to verify npm package ownership (official-registry-requirements.md).
 *
 * The schema check exists because the two hand-picked caps below do not
 * cover the whole registry schema: v0.1.1 shipped to npm with a server.json
 * the registry then rejected at publish time — a 422, after `npm publish`
 * had already run. Validating the full vendored schema here, the same
 * $schema server.json names, fetched once and committed so the check stays
 * hermetic, closes that gap instead of merely narrowing it.
 *
 * Wired into `pnpm test` (ci.yml), exactly like
 * scripts/check-encoding-single-copy.mjs.
 *
 * Usage: node scripts/assert-server-json.mjs [repoDir]
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import Ajv from "ajv";
import addFormats from "ajv-formats";

// The registry schema server.json's `$schema` names, fetched once in CI
// and vendored here so this check is hermetic. Re-vendor under a new dated
// file and update this constant if server.json's `$schema` date segment
// ever changes.
const SCHEMA_PATH = "tools/registry-schema/2025-12-11.json";

const DESCRIPTION_MAX = 100;

function readJson(path) {
  return JSON.parse(readFileSync(path, "utf8"));
}

/**
 * Pure check, no fs and no process.exit: given the parsed package.json,
 * server.json and vendored registry schema, returns an array of
 * human-readable failure strings (empty array = pass). Exported so tests
 * can exercise it directly against fixture objects.
 */
export function checkServerJson(pkg, server, schema) {
  const failures = [];

  if (server.version !== pkg.version) {
    failures.push(
      `server.json#version is "${server.version}" but package.json#version is "${pkg.version}"`,
    );
  }

  const firstPackage = server.packages?.[0];
  if (!firstPackage) {
    failures.push("server.json#packages[0] is missing");
  } else if (firstPackage.version !== pkg.version) {
    failures.push(
      `server.json#packages[0].version is "${firstPackage.version}" but package.json#version is "${pkg.version}"`,
    );
  }

  if (!pkg.mcpName) {
    failures.push(
      "package.json#mcpName is missing; the registry checks it to verify npm package ownership",
    );
  } else if (server.name !== pkg.mcpName) {
    failures.push(
      `server.json#name is "${server.name}" but package.json#mcpName is "${pkg.mcpName}"`,
    );
  }

  // The registry schema (2025-12-11) caps `description` and `title` at 100
  // characters and requires a non-empty description; mcp-publisher only
  // finds out at publish time with a 422, after `npm publish` has already
  // shipped the version (release v0.1.1, 2026-09-13). Fail here instead.
  if (
    typeof server.description !== "string" ||
    server.description.length === 0
  ) {
    failures.push("server.json#description is missing or empty");
  } else if (server.description.length > DESCRIPTION_MAX) {
    failures.push(
      `server.json#description is ${server.description.length} characters; the registry schema allows at most ${DESCRIPTION_MAX}`,
    );
  }
  if (
    typeof server.title === "string" &&
    server.title.length > DESCRIPTION_MAX
  ) {
    failures.push(
      `server.json#title is ${server.title.length} characters; the registry schema allows at most ${DESCRIPTION_MAX}`,
    );
  }

  // server.json must name the exact schema we vendored and validate
  // against below. An unvendored $schema means everything past this point
  // would be validating against the wrong version of the registry's rules.
  if (server["$schema"] !== schema["$id"]) {
    const dateSegment =
      /\/schemas\/([^/]+)\/server\.schema\.json$/.exec(
        String(server["$schema"] ?? ""),
      )?.[1] ?? "<date>";
    failures.push(
      `server.json#$schema is "${server["$schema"]}" but the vendored schema's $id is "${schema["$id"]}"; vendor the new schema at tools/registry-schema/${dateSegment}.json and update SCHEMA_PATH in scripts/assert-server-json.mjs`,
    );
  }

  const ajv = new Ajv({ allErrors: true, strict: false });
  addFormats(ajv);
  const validate = ajv.compile(schema);
  if (!validate(server)) {
    for (const err of validate.errors ?? []) {
      failures.push(
        `server.json failed schema validation: ${err.instancePath || "(root)"} ${err.message}`,
      );
    }
  }

  return failures;
}

const isMain =
  process.argv[1] !== undefined &&
  fileURLToPath(import.meta.url) === process.argv[1];

if (isMain) {
  const root = process.argv[2] ?? process.cwd();

  const pkg = readJson(join(root, "package.json"));
  const server = readJson(join(root, "server.json"));
  const schema = readJson(join(root, SCHEMA_PATH));

  const failures = checkServerJson(pkg, server, schema);

  if (failures.length > 0) {
    console.error("assert-server-json FAILED:");
    for (const f of failures) console.error(`  - ${f}`);
    process.exit(1);
  }

  console.log(
    `assert-server-json OK: server.json and package.json agree at ${pkg.version} (${pkg.mcpName}).`,
  );
}
