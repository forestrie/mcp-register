/**
 * Hand-written type declaration for check-encoding-single-copy.mjs, so
 * test/scripts/check-encoding-single-copy.test.ts can import its pure walk
 * under `tsc --noEmit`.
 */
export declare const EXPECTED: Record<string, string>;
export declare function findCopies(
  rootDir: string,
  names: string[],
): Map<string, Map<string, string[]>>;
