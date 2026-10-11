/**
 * Where child grants are kept between issue_grant and register_grant:
 * `<home>/grants/<logId>/` holding `record.json`, `grant.cose` (as signed),
 * `parent.cose` (the requester's authority grant, when known),
 * `payment.txt` (an `X-PAYMENT` sent but not yet answered), `receipt.cose`
 * and `completed.cose` (the grant with its receipt: the credential).
 *
 * The record is keyed by the child log id, so register_grant resumes from
 * whatever state the last call reached, and never pays twice for one grant:
 * a payment once sent is re-sent on retry (canopy's claim is idempotent per
 * authorisation and grant), never replaced by a new one. Nothing here is
 * secret except `payment.txt`, a signed authorisation to pay canopy's payee
 * for this grant, which is written `0600` and removed once canopy answers.
 */
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import type { PaymentRequired, PaymentSummary } from "../core/x402.js";
import { StoreError } from "./store.js";

export type GrantState =
  /** Signed (or supplied), not yet accepted by canopy. */
  | "issued"
  /** canopy answered 402; waiting for a payment (relay mode). */
  | "payment_required"
  /** canopy answered 303: enqueued for sequencing under the owner log. */
  | "accepted"
  /** Sealed, and completed with its receipt. */
  | "complete";

export interface GrantRecord {
  logId: string;
  ownerLogId: string;
  state: GrantState;
  /** True when issue_grant signed it here. */
  issuedHere: boolean;
  /** The key the grant names, hex x‖y. */
  granteeHex: string;
  maxHeight?: number;
  flagsHex: string;
  /** Whether the parent grant carries GF_CHILD_PAYMENT_REQUIRED. */
  parentRequiresPayment?: boolean;
  issuedAt: string;
  baseUrl?: string;
  rootLogId?: string;
  paymentRequired?: PaymentRequired;
  payment?: PaymentSummary & { via: "payer" | "relay"; at: string };
  statusUrl?: string;
  acceptedAt?: string;
  firstPendingAt?: string;
  entryId?: string;
  massifHeight?: number;
  receiptUrl?: string;
  completedAt?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const STATES: GrantState[] = [
  "issued",
  "payment_required",
  "accepted",
  "complete",
];

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

export class GrantStore {
  constructor(readonly root: string) {}

  dir(logId: string): string {
    if (!UUID.test(logId))
      throw new StoreError(
        "unknown_registration",
        `logId must be a lowercase UUID (the child log id issue_grant returned); got ${logId}`,
      );
    return join(this.root, "grants", logId);
  }

  path(logId: string, file: string): string {
    return join(this.dir(logId), file);
  }

  has(logId: string): boolean {
    try {
      readFileSync(this.path(logId, "record.json"));
      return true;
    } catch {
      return false;
    }
  }

  save(record: GrantRecord, files: Record<string, Uint8Array> = {}): void {
    io(`cannot save grant ${record.logId} under ${this.root}`, () => {
      mkdirSync(this.dir(record.logId), { recursive: true, mode: 0o700 });
      for (const [name, bytes] of Object.entries(files))
        writeFileSync(this.path(record.logId, name), bytes);
      writeFileSync(
        this.path(record.logId, "record.json"),
        JSON.stringify(record, null, 2) + "\n",
      );
    });
  }

  load(logId: string): GrantRecord {
    const path = this.path(logId, "record.json");
    let text: string;
    try {
      text = readFileSync(path, "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT")
        throw new StoreError(
          "unknown_registration",
          `no grant for log ${logId} in ${this.root}: issue_grant records each grant it signs there, or pass the grant itself`,
        );
      throw new StoreError(
        "store_failed",
        `cannot read ${path}: ${(err as Error).message}`,
      );
    }
    let record: Partial<GrantRecord> | undefined;
    try {
      record = JSON.parse(text) as Partial<GrantRecord>;
    } catch {
      record = undefined;
    }
    if (
      record === undefined ||
      record.logId !== logId ||
      typeof record.ownerLogId !== "string" ||
      !STATES.includes(record.state as GrantState)
    )
      throw new StoreError(
        "corrupt_record",
        `${path} is not a grant record for ${logId}`,
      );
    return record as GrantRecord;
  }

  read(logId: string, file: string): Uint8Array | undefined {
    try {
      return new Uint8Array(readFileSync(this.path(logId, file)));
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return undefined;
      throw new StoreError(
        "store_failed",
        `cannot read ${file} for grant ${logId}: ${(err as Error).message}`,
      );
    }
  }

  savePendingPayment(logId: string, header: string): void {
    io(`cannot save the pending payment for grant ${logId}`, () =>
      writeFileSync(this.path(logId, "payment.txt"), header, { mode: 0o600 }),
    );
  }

  pendingPayment(logId: string): string | undefined {
    const bytes = this.read(logId, "payment.txt");
    return bytes === undefined ? undefined : new TextDecoder().decode(bytes);
  }

  clearPendingPayment(logId: string): void {
    io(`cannot remove the pending payment for grant ${logId}`, () =>
      rmSync(this.path(logId, "payment.txt"), { force: true }),
    );
  }
}
