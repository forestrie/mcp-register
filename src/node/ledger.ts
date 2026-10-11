/**
 * What the payer backend has committed, per UTC day:
 * `<home>/payments/<YYYY-MM-DD>.jsonl`, one line per signed authorisation.
 *
 * An entry is written BEFORE the payment is sent: once signed, an
 * authorisation can be settled whether or not this server ever sees
 * canopy's answer, so the daily cap counts every authorisation signed, not
 * only the ones known to have settled. The cap is approximate under
 * concurrency: two calls can both pass the check before either is written.
 */
import { appendFileSync, mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { StoreError } from "./store.js";

export interface LedgerEntry {
  at: string;
  network: string;
  asset: string;
  amount: string;
  payTo: string;
  from: string;
  nonce: string;
  /** The child log whose grant the payment is for. */
  logId: string;
}

export class SpendLedger {
  constructor(readonly root: string) {}

  private file(day: string): string {
    return join(this.root, "payments", `${day}.jsonl`);
  }

  static day(now: Date): string {
    return now.toISOString().slice(0, 10);
  }

  entries(now: Date): LedgerEntry[] {
    let text: string;
    try {
      text = readFileSync(this.file(SpendLedger.day(now)), "utf8");
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === "ENOENT") return [];
      throw new StoreError(
        "store_failed",
        `cannot read the spend ledger: ${(err as Error).message}`,
      );
    }
    const out: LedgerEntry[] = [];
    for (const line of text.split("\n")) {
      if (line.trim() === "") continue;
      try {
        out.push(JSON.parse(line) as LedgerEntry);
      } catch {
        // Refuse rather than guess: an unreadable line could be a payment.
        throw new StoreError(
          "corrupt_record",
          `the spend ledger ${this.file(SpendLedger.day(now))} has a line that is not JSON; fix or remove it before paying again`,
        );
      }
    }
    return out;
  }

  /**
   * Atomic units committed today on this network and asset. Each nonce
   * counts once: a retry re-signs a grant's payment with the same nonce,
   * and at most one authorisation per nonce can ever settle.
   */
  spentToday(now: Date, network: string, asset: string): bigint {
    let total = 0n;
    const seen = new Set<string>();
    for (const e of this.entries(now)) {
      if (e.network !== network || e.asset.toLowerCase() !== asset) continue;
      const key = `${e.from.toLowerCase()} ${e.nonce.toLowerCase()}`;
      if (seen.has(key)) continue;
      seen.add(key);
      total += BigInt(e.amount);
    }
    return total;
  }

  record(now: Date, entry: LedgerEntry): void {
    try {
      mkdirSync(join(this.root, "payments"), { recursive: true, mode: 0o700 });
      appendFileSync(
        this.file(SpendLedger.day(now)),
        JSON.stringify(entry) + "\n",
        { mode: 0o600 },
      );
    } catch (err) {
      throw new StoreError(
        "store_failed",
        `cannot write the spend ledger: ${(err as Error).message}`,
      );
    }
  }
}
