/**
 * SM9's SM3-based hash layer: H1, H2 and the KDF.
 *
 * H1/H2 — GM/T 0044.4 clauses 5.4.2.2 and 5.4.2.3.
 * KDF   — GM/T 0044.3 clause 5.4.3 (Part 4 clause 5.4.3 defers to it, so there
 *         is exactly one KDF in SM9, not one per part).
 *
 * This layer is pure SM3: no pairing, no curve arithmetic. That makes it the
 * cheapest honest test in the lab, and it is deliberately the first thing the
 * page runs — a visitor sees the standard's own printed sub-values reproduced
 * before any elliptic curve is touched.
 *
 * H1 and H2 are the SAME construction separated by one leading byte: 0x01 for
 * H1, 0x02 for H2. For SM9's 256-bit N, hlen works out to 320 bits, so each is
 * exactly two SM3 calls concatenated and truncated to 40 bytes.
 *
 * VERIFIED, three ways, before being written here: against all 20 H1/H2/KDF
 * sub-values the GM/T 0044.5 annexes print; against the same constructions over
 * OpenSSL's SM3 (a different SM3 codebase); and against GmSSL's own C
 * `sm9_z256_hash1` compiled and run as a separate binary. Zero disagreements.
 * See src/sm9/hash.test.ts and src/sm9/fixtures.ts.
 */
import { sm3 } from '@li0ard/sm3';
import { N } from './params';

/** SM3's output length v, in bits. */
export const V_BITS = 256;

function u8(values: number[]): Uint8Array {
  return Uint8Array.from(values);
}

export function concatBytes(...arrays: Uint8Array[]): Uint8Array {
  const total = arrays.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const a of arrays) {
    out.set(a, offset);
    offset += a.length;
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array {
  const s = hex.replace(/[^0-9a-fA-F]/g, '');
  if (s.length % 2 !== 0) throw new RangeError(`hexToBytes: odd length ${s.length}`);
  const out = new Uint8Array(s.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  let s = '';
  for (const b of bytes) s += b.toString(16).padStart(2, '0');
  return s;
}

function counterBytes(ct: number): Uint8Array {
  return u8([(ct >>> 24) & 0xff, (ct >>> 16) & 0xff, (ct >>> 8) & 0xff, ct & 0xff]);
}

/** Leftmost `bits` bits of `bytes`, zeroing the tail of the final partial byte. */
function leftmostBits(bytes: Uint8Array, bits: number): Uint8Array {
  const whole = bits >> 3;
  const rem = bits & 7;
  const out = bytes.slice(0, whole + (rem ? 1 : 0));
  if (rem) out[whole] &= (0xff << (8 - rem)) & 0xff;
  return out;
}

function bitLength(n: bigint): number {
  return n.toString(2).length;
}

export interface HashToRangeResult {
  /** The output h, in [1, n-1]. */
  h: bigint;
  /** The concatenated-and-truncated digest Ha, before reduction. 40 bytes for SM9. */
  Ha: Uint8Array;
  /** hlen in bits. 320 for SM9's 256-bit N. */
  hlen: number;
  /** How many SM3 invocations the counter chain made. 2 for SM9. */
  blocks: number;
  /** Length of the SM3 message actually hashed, in bytes — 1 + |Z| + 4. */
  sm3InputBytes: number;
  /** How many 64-byte SM3 compression blocks that message occupies. */
  sm3Blocks: number;
}

/** The shared H1/H2 construction. `prefix` is 0x01 for H1, 0x02 for H2. */
function hashToRange(prefix: number, Z: Uint8Array, n: bigint): HashToRangeResult {
  const v = V_BITS;
  // Step 2: hlen = 8 * ceil( (5 * ceil(log2 n)) / 32 ), in bits.
  const hlen = 8 * Math.ceil((5 * bitLength(n)) / 32);
  const blocks = Math.ceil(hlen / v);
  let ct = 1; // Step 1
  const parts: Uint8Array[] = [];
  for (let i = 1; i <= blocks; i++) {
    // Step 3: Ha_i = Hv(prefix || Z || ct)
    parts.push(sm3(concatBytes(u8([prefix]), Z, counterBytes(ct))));
    ct++;
  }
  // Step 4: truncate the last block when hlen is not a whole number of v.
  if (hlen % v !== 0) {
    const tailBits = hlen - v * Math.floor(hlen / v);
    parts[parts.length - 1] = leftmostBits(parts[parts.length - 1], tailBits);
  }
  const Ha = concatBytes(...parts); // Step 5
  const HaInt = Ha.length === 0 ? 0n : BigInt('0x' + bytesToHex(Ha));
  const sm3InputBytes = 1 + Z.length + 4;
  return {
    h: (HaInt % (n - 1n)) + 1n, // Step 6
    Ha,
    hlen,
    blocks,
    sm3InputBytes,
    sm3Blocks: Math.ceil((sm3InputBytes + 9) / 64),
  };
}

/** H1(Z, n) — GM/T 0044.4 clause 5.4.2.2. Used to turn an identity into a scalar. */
export function H1(Z: Uint8Array, n: bigint = N): HashToRangeResult {
  return hashToRange(0x01, Z, n);
}

/** H2(Z, n) — GM/T 0044.4 clause 5.4.2.3. Used to bind a message to a pairing value. */
export function H2(Z: Uint8Array, n: bigint = N): HashToRangeResult {
  return hashToRange(0x02, Z, n);
}

/**
 * KDF(Z, klen) — GM/T 0044.3 clause 5.4.3. `klen` is in BITS, matching the
 * standard's own notation; passing bytes here is the easiest way to get a
 * plausible-looking wrong answer, so callers convert explicitly.
 */
export function KDF(Z: Uint8Array, klenBits: number): Uint8Array {
  const v = V_BITS;
  const blocks = Math.ceil(klenBits / v);
  let ct = 1; // Step 1
  const parts: Uint8Array[] = [];
  for (let i = 1; i <= blocks; i++) {
    parts.push(sm3(concatBytes(Z, counterBytes(ct)))); // Step 2
    ct++;
  }
  if (klenBits % v !== 0) {
    // Step 3
    const tailBits = klenBits - v * Math.floor(klenBits / v);
    parts[parts.length - 1] = leftmostBits(parts[parts.length - 1], tailBits);
  }
  return concatBytes(...parts); // Step 4
}

/** Encode an identity string plus its hid byte, the argument H1 takes everywhere. */
export function identityWithHid(identity: string, hid: number): Uint8Array {
  if (!Number.isInteger(hid) || hid < 0 || hid > 0xff) {
    throw new RangeError(`identityWithHid: hid must be one byte, got ${hid}`);
  }
  return concatBytes(new TextEncoder().encode(identity), u8([hid]));
}
