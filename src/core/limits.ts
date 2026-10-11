/**
 * canopy's statement size limit, `maxStatementSize` in its SCITT
 * configuration (canopy `scrapi/transparency-configuration.ts`): 4 MiB,
 * checked against the signed statement's Content-Length. The limit is on
 * the COSE Sign1 as sent, so the payload must leave room for the headers
 * and the signature.
 */
export const MAX_STATEMENT_BYTES = 4 * 1024 * 1024;
