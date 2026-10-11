/**
 * Where registrations are kept between tool calls:
 * `<home>/registrations/<contentHash>/{record.json, statement.cose, receipt.cose}`.
 *
 * The statement and receipt live on disk so tools can hand back paths
 * rather than megabytes of base64, and so `@forestrie/mcp-verify` (which
 * takes `{path}` inputs) can be pointed straight at them. The record is
 * the caller's evidence of what was registered where; nothing here is
 * secret.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface RegistrationRecord {
  contentHash: string;
  statusUrl: string;
  baseUrl: string;
  rootLogId: string;
  logId: string;
  contentType: string;
  issuer: string;
  subject: string;
  registeredAt: string;
  entryId?: string;
  massifHeight?: number;
  receiptUrl?: string;
  sealedAt?: string;
}

export class StoreError extends Error {
  readonly code = "unknown_registration" as const;
}

const HASH = /^[0-9a-f]{64}$/;

export class RegistrationStore {
  constructor(readonly root: string) {}

  dir(contentHash: string): string {
    if (!HASH.test(contentHash))
      throw new StoreError(
        `contentHash must be 64 lowercase hex characters (the sha256 register_statement returned)`,
      );
    return join(this.root, "registrations", contentHash);
  }

  statementPath(contentHash: string): string {
    return join(this.dir(contentHash), "statement.cose");
  }

  receiptPath(contentHash: string): string {
    return join(this.dir(contentHash), "receipt.cose");
  }

  saveStatement(record: RegistrationRecord, statement: Uint8Array): void {
    mkdirSync(this.dir(record.contentHash), { recursive: true, mode: 0o700 });
    writeFileSync(this.statementPath(record.contentHash), statement);
    this.saveRecord(record);
  }

  saveRecord(record: RegistrationRecord): void {
    writeFileSync(
      join(this.dir(record.contentHash), "record.json"),
      JSON.stringify(record, null, 2) + "\n",
    );
  }

  saveReceipt(contentHash: string, receipt: Uint8Array): void {
    writeFileSync(this.receiptPath(contentHash), receipt);
  }

  load(contentHash: string): RegistrationRecord {
    try {
      return JSON.parse(
        readFileSync(join(this.dir(contentHash), "record.json"), "utf8"),
      ) as RegistrationRecord;
    } catch (err) {
      if (err instanceof StoreError) throw err;
      throw new StoreError(
        `no registration ${contentHash} in ${this.root}: register_statement records each registration there`,
      );
    }
  }

  readStatement(contentHash: string): Uint8Array {
    return new Uint8Array(readFileSync(this.statementPath(contentHash)));
  }

  readReceipt(contentHash: string): Uint8Array | undefined {
    try {
      return new Uint8Array(readFileSync(this.receiptPath(contentHash)));
    } catch {
      return undefined;
    }
  }
}
