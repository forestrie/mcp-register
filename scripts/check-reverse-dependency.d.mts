/**
 * Hand-written type declaration for check-reverse-dependency.mjs, so
 * test/node/check-reverse-dependency.test.ts can import the pure functions
 * under `tsc --noEmit` (moduleResolution: "bundler" resolves a relative
 * `.mjs` import against a sibling `.d.mts`, same as @forestrie/mcp-verify's
 * own scripts do).
 */
export declare const HOSTS: string[];
export declare function findMcpRegisterCopies(
  rootDir: string,
  maxDepth?: number,
): string[];
export declare function scanInstalledTree(
  rootDir: string,
  maxDepth?: number,
): { hits: string[]; seen: Set<string>; problems: string[] };
