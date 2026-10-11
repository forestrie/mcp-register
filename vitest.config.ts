import { defineConfig } from "vitest/config";

/**
 * Two named projects so `pnpm test` stays hermetic and a live run against a
 * real lane never becomes a required check by accident.
 */
export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: "unit",
          environment: "node",
          include: [
            "test/core/**/*.test.ts",
            "test/net/**/*.test.ts",
            "test/node/**/*.test.ts",
            "test/scripts/**/*.test.ts",
          ],
          // Every test in this project runs with a fetch that
          // throws. src/core never fetches and src/net is tested only
          // through injected fakes.
          setupFiles: ["./test/setup/forbid-fetch.ts"],
        },
      },
      {
        test: {
          name: "live",
          environment: "node",
          include: ["test/live/**/*.test.ts"],
          // No setup file: this project deliberately makes real requests.
          // Opt-in by FORESTRIE_LIVE=1 and never a required check: it runs
          // against a real lane and the caller's own RPC URL, and the public
          // lanes share a request quota.
          testTimeout: 60_000,
        },
      },
    ],
  },
});
