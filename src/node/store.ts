/**
 * Where registrations are kept between tool calls:
 * `<home>/registrations/<contentHash>/{record.json, statement.cose, receipt.cose}`.
 *
 * The statement and receipt live on disk so tools can hand back paths
 * rather than megabytes of base64, and so `@forestrie/mcp-verify` (which
 * takes `{path}` inputs) can be pointed straight at them. The record is
 * the caller's evidence of what was registered where; nothing here is
 * secret.
 *
 * The signed statement is saved BEFORE it is sent (`state: "signed"`), so a
 * failure after canopy has accepted it never loses the handle: the status
 * URL is derived from the content hash, and check_registration can still
 * find it. Every filesystem failure is a `StoreError` with a code.
 */
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export interface RegistrationRecord {
  contentHash: string;
  /** "signed": saved, not (yet) known to be accepted. "accepted": canopy answered 303. */
  state: "signed" | "accepted";
  /** From canopy's 303; absent until accepted. */
  statusUrl?: string;
  baseUrl: string;
  rootLogId: string;
  logId: string;
  contentType: string;
  issuer: string;
  subject: string;
  signedAt: string;
  acceptedAt?: string;
  /** When check_registration first saw it pending; bounds the wait. */
  firstPendingAt?: string;
  entryId?: string;
  massifHeight?: number;
  receiptUrl?: string;
  sealedAt?: string;
}

export class StoreError extends Error {
  constructor(
    readonly code: "unknown_registration" | "corrupt_record" | "store_failed",
    message: string,
  ) {
    super(message);
  }
}

const HASH = /^[0-9a-f]{64}$/;

function io<T>(what: string, run: () => T): T {
  try {
    return run();
  } catch (err) {
    throw new StoreError(
      "store_failed",
      `${what}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }
}

function isRecord(v: unknown): v is RegistrationRecord {
  const r = v as Partial<RegistrationRecord> | null;
  return (
    typeof r === "object" &&
    r !== null &&
    typeof r.contentHash === "string" &&
    HASH.test(r.contentHash) &&
    (r.state === "signed" || r.state === "accepted") &&
    typeof r.baseUrl === "string" &&
    typeof r.rootLogId === "string" &&
    typeof r.logId === "string" &&
    (r.statusUrl === undefined || typeof r.statusUrl === "string") &&
    (r.receiptUrl === undefined || typeof r.receiptUrl === "string") &&
    (r.entryId === undefined || /^[0-9a-f]{32}$/.test(r.entryId))
  );
}

export class RegistrationStore {
  constructor(readonly root: string) {}

  dir(contentHash: string): string {
    if (!HASH.test(contentHash))
      throw new StoreError(
        "unknown_registration",
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
    io(`cannot save the signed statement under ${this.root}`, () => {
      mkdirSync(this.dir(record.contentHash), {
        recursive: true,
        mode: 0o700,
      });
      writeFileSync(this.statementPath(record.contentHash), statement);
    });
    this.saveRecord(record);
  }

  saveRecord(record: RegistrationRecord): void {
    io(`cannot save the registration record under ${this.root}`, () =>
      writeFileSync(
        join(this.dir(record.contentHash), "record.json"),
        JSON.stringify(record, null, 2) + "\n",
      ),
    );
  }

  saveReceipt(contentHash: string, receipt: Uint8Array): void {
    io(`cannot save the receipt under ${this.root}`, () =>
      writeFileSync(this.receiptPath(contentHash), receipt),
    );
  }

  load(contentHash: string): RegistrationRecord {
    const path = join(this.dir(contentHash), "record.json");
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT")
        throw new StoreError(
          "unknown_registration",
          `no registration ${contentHash} in ${this.root}: register_statement records each registration there`,
        );
      throw new StoreError(
        "store_failed",
        `cannot read ${path}: ${(err as Error).message}`,
      );
    }
    let record: unknown;
    try {
      record = JSON.parse(text);
    } catch {
      record = undefined;
    }
    if (!isRecord(record) || record.contentHash !== contentHash)
      throw new StoreError(
        "corrupt_record",
        `${path} is not a registration record for ${contentHash}`,
      );
    return record;
  }

  readStatement(contentHash: string): Uint8Array {
    return io(
      `cannot read the signed statement for ${contentHash}`,
      () => new Uint8Array(readFileSync(this.statementPath(contentHash))),
    );
  }

  /** The saved receipt, or `undefined` when there is none yet. */
  readReceipt(contentHash: string): Uint8Array | undefined {
    try {
      return new Uint8Array(readFileSync(this.receiptPath(contentHash)));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw new StoreError(
        "store_failed",
        `cannot read the receipt for ${contentHash}: ${(err as Error).message}`,
      );
    }
  }
}
