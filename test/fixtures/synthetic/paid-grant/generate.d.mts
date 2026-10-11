/** Type declaration for `generate.mjs`, so tests can import it typed. */
export declare const COORDINATES: {
  baseUrl: string;
  coordinatorUrl: string;
  rootLogId: string;
  authorityLogId: string;
  childLogId: string;
  grantCommitmentHex: string;
  entryId: string;
  massifHeight: number;
  unitPriceAtomic: string;
  maxHeight: number;
  network: string;
  asset: string;
  payTo: string;
  payerPrivateKey: string;
  payerAddress: string;
};
export declare function generate(outDir: string): Promise<{
  outDir: string;
  files: string[];
  coordinates: typeof COORDINATES;
}>;
