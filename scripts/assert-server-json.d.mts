/** Type declaration for `assert-server-json.mjs` (a plain, dependency-light
 *  Node script importing only `ajv`, `ajv-formats` and `node:*` — not part
 *  of the package's own TS build) so `test/scripts/assert-server-json.test.ts`
 *  can import its pure `checkServerJson` check typed. */
export declare function checkServerJson(
  pkg: Record<string, unknown>,
  server: Record<string, unknown>,
  schema: Record<string, unknown>,
): string[];
