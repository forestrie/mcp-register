/**
 * Base64 without `Buffer`, so `src/core` stays browser-safe. Accepts the
 * standard and URL-safe alphabets, as canopy does for a Forestrie-Grant.
 */
export function base64ToBytes(b64: string): Uint8Array {
  const std = b64.trim().replace(/-/g, "+").replace(/_/g, "/");
  const padded = std + "=".repeat((4 - (std.length % 4)) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function bytesToBase64(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}
