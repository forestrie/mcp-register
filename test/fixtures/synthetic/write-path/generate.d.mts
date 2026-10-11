/** Type declaration for `generate.mjs`, so tests can import it typed. */
export declare const COORDINATES: {
  baseUrl: string;
  coordinatorUrl: string;
  rootLogId: string;
  dataLogId: string;
  ownerLogId: string;
  statusEntryHash: string;
  entryId: string;
  massifHeight: number;
  sealerId: string;
  epoch: number;
  suggestedTtlSeconds: number;
  idtimestampHex: string;
};
export declare function generate(outDir: string): Promise<{
  outDir: string;
  files: string[];
  coordinates: typeof COORDINATES;
}>;
