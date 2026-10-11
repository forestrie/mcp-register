/**
 * The signer seam: every signature this package makes goes through one
 * `Es256Signer`. Core code builds the exact bytes to be signed and hands
 * them over; it never sees a private key, and no signature byte ever
 * arrives from a tool argument. Where the key lives — a local key file
 * (the default, `src/node/signer-file.ts`), a KMS, a remote signer — is the
 * backend's business.
 *
 * ES256 only: canopy's child-log paths (register-grant auto-forward and
 * `POST /api/forest/{child}/prepare`) accept 64-byte P-256 roots only, so a
 * KS256 log key could not delegate its own sealing without an operator.
 */
export interface Es256Signer {
  /** The P-256 public key as 64 bytes x‖y — what a grant's `grantData` names. */
  publicKeyXY(): Promise<Uint8Array>;
  /**
   * ECDSA P-256 with SHA-256 over `message` (the signer hashes), returned as
   * IEEE P1363 r‖s, 64 bytes. For COSE that message is the Sig_structure.
   */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /** Where the key lives, for humans: never key material. */
  readonly description: string;
}
