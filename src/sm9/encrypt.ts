/**
 * SM9 key encapsulation (GM/T 0044.4 clause 6) and public key encryption
 * (GM/T 0044.4 clause 7), including BOTH of the encryption modes the standard
 * defines: mode a), the KDF stream cipher, and mode b), a block cipher — SM4
 * in CBC with an all-zero IV, which is what GM/T 0044.5 Annex D exercises.
 *
 * WHY THE TWO MECHANISMS ARE IN ONE FILE. They share every step up to and
 * including w = g^r, and they differ in exactly one place that this lab exists
 * to show: what happens when decryption is given the wrong thing.
 *
 *   Key encapsulation, clause 6.2.1, is B1 check C is in G1, B2 pair, B3 KDF,
 *   B4 output K'. The ONLY error in the whole procedure is K' = 0. There is no
 *   MAC, no tag and no redundancy, so decapsulating with a different user's
 *   private key returns a DIFFERENT KEY and reports success. The failure is
 *   silent by construction, not by oversight — a KEM's job ends at producing a
 *   key, and whatever uses that key is what is expected to notice.
 *
 *   Public key encryption, clause 7.2.1, adds C3 = MAC(K2, C2) and step B4:
 *   "u = MAC(K2', C2); if u != C3, report an error and exit". That one
 *   comparison is the entire difference between the two mechanisms' failure
 *   behaviour, and it is why `decrypt` returns a named cause while
 *   `kemDecapsulate` has almost nothing to report.
 *
 * So `kemDecapsulate` is deliberately NOT given an integrity check it does not
 * have, and its success type carries `integrityChecked: false` to stop a caller
 * reading `ok: true` as "this was the right key". `compareKemKeys` is the only
 * honest way to find that out, and it needs the encapsulated key to do it —
 * which is precisely the point: the decapsulator alone cannot tell.
 *
 * THREE ENGINE HAZARDS are handled here rather than documented and hoped for:
 *   - point_mul returns a Jacobian point and point_add reads its SECOND operand
 *     as affine, so `mulG1`/`addG1` normalise on the way in and out, and
 *     `g1ToBytes` normalises again before serialising. That is defence in depth
 *     rather than three separate requirements: remove any ONE of them and the
 *     results are unchanged, because the next one along still normalises.
 *     Remove the producer's and the serialiser's together and C leaves this
 *     module as an off-curve x||y that its own B1 refuses — which is what
 *     src/sm9/encrypt.test.ts demonstrates on the raw engine rather than
 *     asserting here.
 *   - the annexes print the 1-2-4-12 tower in DESCENDING coefficient order and
 *     the engine stores it ASCENDING, so `fp12ToBytes` reverses all three
 *     levels. This is not cosmetic: w goes into the KDF, so the order decides K.
 *   - fp12_pow reduces its exponent mod q, the FIELD characteristic, not mod N.
 *     Every r is range-checked into [1, N-1] before it reaches it.
 *
 * Verified end to end against GM/T 0044.5 Annex C (KEM) and Annex D (public key
 * encryption, both modes) — every printed intermediate, not just the outputs.
 * See src/sm9/encrypt.test.ts.
 */
import { sm3 } from '@li0ard/sm3';
import { decryptCBC, encryptCBC } from '@li0ard/sm4';
import { N, Q } from './params';
import { isValidScalar } from './fn';
import { H1, KDF, bytesToHex, concatBytes, identityWithHid } from './hash';
import { pairing, toAffineG1, type G1Point, type G2Point, type Gt } from './pairing';
import {
  SM9_P1,
  SM9_P2,
  fp12_new,
  fp12_pow,
  point_add,
  point_is_at_infinity,
  point_is_on_curve,
  point_mul,
  point_new,
} from '../vendor/gmssl-sm9.js';

/** An affine G1 point serialises as x||y, 32 bytes each. */
export const G1_POINT_BYTES = 64;
/** C3 is one SM3 digest. */
export const MAC_BYTES = 32;
/** An Fp12 element serialises as 12 field elements of 32 bytes. */
export const FP12_BYTES = 384;
/** SM4's block length, GB/T 32907-2016. Mode b)'s padding quantum. */
export const SM4_BLOCK_BYTES = 16;

/**
 * An identity is bytes. The string form is a convenience for the annexes, whose
 * ID_B is the ASCII "Bob"; nothing in the standard restricts an identity to text.
 */
export type Identity = string | Uint8Array;

/**
 * The two encryption modes of GM/T 0044.4 clause 7.1.1 step A6, named by the
 * standard's own letters rather than renamed, so a reader can follow the clause.
 *   a) K1 is a one-time pad the length of the message: C2 = M xor K1.
 *   b) K1 is a block cipher key: C2 = Enc(K1, M || padding).
 */
export type CipherMode = 'a' | 'b';

// ---------------------------------------------------------------------------
// byte and field plumbing
// ---------------------------------------------------------------------------

/** The engine's Fp12: three Fp4, each two Fp2, each two Fp. */
type Fp12 = bigint[][][];

function bigIntTo32Bytes(a: bigint): Uint8Array {
  if (a < 0n || a >= 1n << 256n) throw new RangeError('bigIntTo32Bytes: out of range');
  const hex = a.toString(16).padStart(64, '0');
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  return bytes.length === 0 ? 0n : BigInt('0x' + bytesToHex(bytes));
}

/** Compare without an early exit. K and C3 are secret-dependent. */
function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

function isAllZero(bytes: Uint8Array): boolean {
  let acc = 0;
  for (const b of bytes) acc |= b;
  return acc === 0;
}

/**
 * Serialise an Fp12 element the way the standard prints it.
 *
 * GM/T 0044.5's annexes print every coefficient of the 1-2-4-12 tower in
 * DESCENDING index order; the engine stores it ascending. The reversal is at all
 * three levels — i = 2..0 over the Fp4s, j = 1..0 over the Fp2s, k = 1..0 over
 * the Fp — which was established from the printed P2 and then confirmed on six
 * 768-hex-character Fp12 blocks across Annexes C and D.
 *
 * This is load-bearing rather than presentational: w is hashed into the KDF at
 * clause 6.1.1 step A6, so getting the order wrong changes K while leaving every
 * curve operation correct. The symptom looks cryptographic and is not.
 */
export function fp12ToBytes(a: Gt): Uint8Array {
  const f = a as Fp12;
  const parts: Uint8Array[] = [];
  for (let i = 2; i >= 0; i--) {
    for (let j = 1; j >= 0; j--) {
      for (let k = 1; k >= 0; k--) parts.push(bigIntTo32Bytes(f[i][j][k]));
    }
  }
  return concatBytes(...parts);
}

/** Serialise a G1 point as the standard concatenates it: x||y, affine, 64 bytes. */
export function g1ToBytes(p: G1Point): Uint8Array {
  const a = toAffineG1(p);
  if (a.Z === 0n) throw new RangeError('g1ToBytes: the point at infinity has no x||y encoding');
  return concatBytes(bigIntTo32Bytes(a.X), bigIntTo32Bytes(a.Y));
}

/** [k]P in G1, normalised on the way in (point_mul's addend must be affine) and out. */
function mulG1(k: bigint, p: G1Point): G1Point {
  const out = point_new();
  point_mul(out, k, toAffineG1(p));
  return toAffineG1(out as G1Point);
}

/** P + Q in G1. point_add reads Q as affine and ignores its Z, so Q is normalised first. */
function addG1(p: G1Point, q: G1Point): G1Point {
  const out = point_new();
  point_add(out, p, toAffineG1(q));
  return toAffineG1(out as G1Point);
}

function identityBytes(identity: Identity): Uint8Array {
  return typeof identity === 'string' ? new TextEncoder().encode(identity) : identity;
}

/** ID || hid, the argument H1 takes at clause 5.4.2.2. */
function identityWithHidBytes(identity: Identity, hid: number): Uint8Array {
  if (typeof identity === 'string') return identityWithHid(identity, hid);
  if (!Number.isInteger(hid) || hid < 0 || hid > 0xff) {
    throw new RangeError(`identityWithHidBytes: hid must be one byte, got ${hid}`);
  }
  return concatBytes(identity, Uint8Array.of(hid));
}

// ---------------------------------------------------------------------------
// primitives shared by both mechanisms
// ---------------------------------------------------------------------------

/**
 * MAC(K2, Z) = Hv(Z || K2) — GM/T 0044.4 clause 5.4.5.
 *
 * MESSAGE FIRST, KEY SECOND. The argument order of the function and the order of
 * the concatenation are opposites, which is the whole reason this is a named
 * function here rather than an inline sm3() call. Swapping them still produces a
 * 32-byte value that round-trips against itself, so a test that only encrypts and
 * decrypts with the same code cannot see the mistake; only the annex's printed C3
 * can. src/sm9/encrypt.test.ts pins both directions.
 */
export function mac(K2: Uint8Array, Z: Uint8Array): Uint8Array {
  return sm3(concatBytes(Z, K2));
}

/**
 * Q_B = [H1(ID_B || hid, N)]P1 + Ppub-e — clause 6.1.1 step A1, and the identical
 * step A1 of clause 7.1.1. This is the whole of "identity-based": the sender
 * derives the receiver's public point from the receiver's NAME and the master
 * public key, with no certificate and no round trip.
 */
export function receiverPublicPoint(
  identity: Identity,
  hid: number,
  Ppube: G1Point,
): { h1: bigint; Qb: G1Point } {
  const h1 = H1(identityWithHidBytes(identity, hid), N).h;
  return { h1, Qb: addG1(mulG1(h1, SM9_P1 as G1Point), Ppube) };
}

/**
 * g = e(Ppub-e, P2) — clause 6.1.1 step A4.
 *
 * It depends only on the master public key, so it is the same for every
 * recipient and every message and is worth computing once. The argument order
 * reads backwards against the standard's notation on purpose: `pairing` takes
 * the G2 element first, as the engine does, and P2 is the G2 element here.
 */
export function pairingBase(Ppube: G1Point): Gt {
  return pairing(SM9_P2 as G2Point, Ppube);
}

/**
 * A uniform scalar in [1, N-1], for clause 6.1.1 step A2.
 *
 * Rejection sampling rather than reduction: N is within a factor of 2^-32 of
 * 2^256, so a modulo would be almost uniform and "almost" is not a property
 * anyone can check later. Rejection is exact and costs a redraw roughly once in
 * four billion.
 */
export function randomScalar(): bigint {
  const buf = new Uint8Array(32);
  for (;;) {
    globalThis.crypto.getRandomValues(buf);
    const candidate = bytesToBigInt(buf);
    if (isValidScalar(candidate)) return candidate;
  }
}

/** w = g^r, with the exponent range-checked before fp12_pow sees it. */
function powGt(g: Gt, r: bigint): Gt {
  // fp12_pow reduces its exponent mod q, the FIELD characteristic, and q > N.
  // An r outside [1, N-1] would therefore not be reduced into the group order and
  // would produce a w that no decapsulator can reach.
  if (!isValidScalar(r)) throw new RangeError('powGt: r must be in [1, N-1]');
  const out = fp12_new();
  fp12_pow(out, g, r);
  return out as Gt;
}

// ---------------------------------------------------------------------------
// the B1 admissibility check, shared by clause 6.2.1 and clause 7.2.1
// ---------------------------------------------------------------------------

/**
 * Is this point a member of G1?
 *
 * SM9's cofactor is 1 (GM/T 0044.5 clause 3.1), so #E(F_q) = N and every
 * on-curve point other than the identity has order N. "On the curve and not the
 * identity" therefore IS membership of G1 here, with no subgroup multiplication
 * needed — a property of these parameters, not a general fact about pairing
 * groups, which is why it is stated rather than assumed.
 *
 * The identity is excluded explicitly because the engine cannot exclude it: its
 * `point_is_on_curve` returns TRUE for the infinity representation (1, 1, 0),
 * which satisfies the curve equation in Jacobian form. That matters beyond
 * tidiness — e(O, de_B) = 1, so a C of O would give every receiver the same K',
 * independent of their private key.
 */
export function isInG1(point: G1Point): boolean {
  return !point_is_at_infinity(point) && point_is_on_curve(point);
}

/** Why a received G1 ENCODING was refused at step B1. */
export type G1RejectionCause =
  /** The encoding was not 64 bytes of x||y. */
  | 'MALFORMED'
  /** A coordinate was >= q, so this is not a canonical field element. */
  | 'COORDINATE_OUT_OF_RANGE'
  /** y^2 != x^3 + 5 over F_q. */
  | 'NOT_ON_CURVE';

export type G1Admission =
  | { ok: true; point: G1Point }
  | { ok: false; cause: G1RejectionCause; message: string };

/**
 * Decode a 64-byte x||y and decide whether it is in G1 — clause 6.2.1 step B1
 * and clause 7.2.1 step B1.
 *
 * There is no AT_INFINITY cause here and that is not an omission: the identity
 * of G1 has no affine (x, y), so this 64-byte form cannot express it, and the
 * case is closed by the encoding rather than by a check. A cause that can never
 * be returned would read as a check being performed. `isInG1` above is for
 * callers holding a POINT, where the identity is reachable and does have to be
 * excluded.
 *
 * The range check is the engine's other gap: `fp_from_hex` does not reduce, so a
 * coordinate >= q would reach the curve test and be judged as its own residue —
 * a non-canonical encoding admitted as though it were the canonical one.
 */
export function admitG1(bytes: Uint8Array): G1Admission {
  if (bytes.length !== G1_POINT_BYTES) {
    return {
      ok: false,
      cause: 'MALFORMED',
      message: `B1: expected ${G1_POINT_BYTES} bytes of x||y, got ${bytes.length}`,
    };
  }
  const x = bytesToBigInt(bytes.subarray(0, 32));
  const y = bytesToBigInt(bytes.subarray(32, 64));
  if (x >= Q || y >= Q) {
    return { ok: false, cause: 'COORDINATE_OUT_OF_RANGE', message: 'B1: a coordinate is >= q' };
  }
  const point: G1Point = { X: x, Y: y, Z: 1n };
  if (!isInG1(point)) {
    return { ok: false, cause: 'NOT_ON_CURVE', message: 'B1: y^2 != x^3 + 5 over F_q' };
  }
  return { ok: true, point };
}

// ---------------------------------------------------------------------------
// clause 6: key encapsulation
// ---------------------------------------------------------------------------

export interface KemEncapsulateOptions {
  /**
   * Pin r rather than drawing it. The annexes print their own r, so reproducing
   * them requires this; nothing else should use it.
   */
  r?: bigint;
  /** How many times step A6 may send us back to A2 before giving up. */
  maxRestarts?: number;
}

export interface KemEncapsulation {
  /** The encapsulated key, klen bits. */
  K: Uint8Array;
  /** C = [r]Q_B, the ciphertext the receiver needs. */
  C: G1Point;
  /** C as the standard concatenates it, x||y. */
  CBytes: Uint8Array;
  /** H1(ID_B || hid, N) — step A1. */
  h1: bigint;
  /** Q_B — step A1. */
  Qb: G1Point;
  /** The r actually used — step A2. Displayed by the lab; a secret in real use. */
  r: bigint;
  /** g = e(Ppub-e, P2) — step A4. */
  g: Gt;
  /** w = g^r — step A5. */
  w: Gt;
  /** w serialised in the standard's descending coefficient order. */
  wBytes: Uint8Array;
  /** C || w || ID_B — the KDF input at step A6. */
  kdfInput: Uint8Array;
  /** How many times an all-zero K sent step A6 back to A2. Effectively always 0. */
  restarts: number;
}

/**
 * Key encapsulation — GM/T 0044.4 clause 6.1.1, steps A1 to A7.
 *
 * `klenBits` is in BITS, matching the standard's own klen. Annex C uses 256.
 */
export function kemEncapsulate(
  identity: Identity,
  hid: number,
  Ppube: G1Point,
  klenBits: number,
  options: KemEncapsulateOptions = {},
): KemEncapsulation {
  const maxRestarts = options.maxRestarts ?? 8;
  const idBytes = identityBytes(identity);
  const { h1, Qb } = receiverPublicPoint(identity, hid, Ppube); // A1
  const g = pairingBase(Ppube); // A4 — independent of r, so hoisted out of the loop

  for (let restarts = 0; restarts <= maxRestarts; restarts++) {
    // A2: r in [1, N-1]. A pinned r cannot be redrawn, so a restart with one is
    // a dead end and says so rather than looping on the same value.
    const r = options.r ?? randomScalar();
    if (!isValidScalar(r)) throw new RangeError('kemEncapsulate: r must be in [1, N-1]');

    const C = mulG1(r, Qb); // A3
    const CBytes = g1ToBytes(C);
    const w = powGt(g, r); // A5
    const wBytes = fp12ToBytes(w);
    const kdfInput = concatBytes(CBytes, wBytes, idBytes); // A6: C || w || ID_B
    const K = KDF(kdfInput, klenBits);

    // A6: "if K is the all-zero bit string, go back to A2."
    if (isAllZero(K)) {
      if (options.r !== undefined) {
        throw new Error('kemEncapsulate: step A6 produced an all-zero K and r was pinned, so A2 cannot be retried');
      }
      continue;
    }
    return { K, C, CBytes, h1, Qb, r, g, w, wBytes, kdfInput, restarts }; // A7
  }
  throw new Error(`kemEncapsulate: step A6 produced an all-zero K ${maxRestarts + 1} times`);
}

/** Why decapsulation refused. The list is short because clause 6.2.1 is short. */
export type KemDecapsulateFailureCause = `C_${G1RejectionCause}` | 'K_ALL_ZERO';

export interface KemDecapsulateFailure {
  ok: false;
  /** The step of clause 6.2.1 that refused. */
  step: 'B1' | 'B3';
  cause: KemDecapsulateFailureCause;
  message: string;
}

export interface KemDecapsulateSuccess {
  ok: true;
  /** K' — step B4. */
  K: Uint8Array;
  C: G1Point;
  CBytes: Uint8Array;
  /** w' = e(C, de_B) — step B2. */
  w: Gt;
  wBytes: Uint8Array;
  /** C || w' || ID_B — step B3. */
  kdfInput: Uint8Array;
  /**
   * Always false, and present so that it has to be read.
   *
   * Clause 6.2.1 has no integrity check of any kind: B1 is a membership test on
   * C, B3's only error is K' = 0, and nothing binds K' to the private key that
   * produced it. `ok: true` therefore means "the procedure completed", never
   * "this was the right key". Use `compareKemKeys` to establish the second, and
   * note that it needs a value the decapsulating side does not have.
   */
  integrityChecked: false;
}

export type KemDecapsulateResult = KemDecapsulateSuccess | KemDecapsulateFailure;

/**
 * Decapsulation — GM/T 0044.4 clause 6.2.1, steps B1 to B4.
 *
 * `deB` is the receiver's encryption private key, a point of G2 issued by the KGC.
 */
export function kemDecapsulate(
  CBytes: Uint8Array,
  identity: Identity,
  deB: G2Point,
  klenBits: number,
): KemDecapsulateResult {
  const admission = admitG1(CBytes); // B1
  if (!admission.ok) {
    return { ok: false, step: 'B1', cause: `C_${admission.cause}`, message: admission.message };
  }
  const C = admission.point;
  const w = pairing(deB, C); // B2: w' = e(C, de_B)
  const wBytes = fp12ToBytes(w);
  const kdfInput = concatBytes(g1ToBytes(C), wBytes, identityBytes(identity)); // B3
  const K = KDF(kdfInput, klenBits);
  if (isAllZero(K)) {
    // The one and only error clause 6.2.1 defines past B1.
    return { ok: false, step: 'B3', cause: 'K_ALL_ZERO', message: "B3: K' is the all-zero bit string" };
  }
  return { ok: true, K, C, CBytes: g1ToBytes(C), w, wBytes, kdfInput, integrityChecked: false }; // B4
}

export interface KemAgreement {
  /** Did decapsulation reach the key that was encapsulated? */
  agreed: boolean;
  /**
   * Did decapsulation SUCCEED and still produce a different key?
   *
   * This is the KEM's failure mode, and the reason this function exists: nothing
   * inside clause 6.2.1 can set this flag, because the decapsulating side never
   * sees the encapsulated K. A caller that has both — a test, or a lab page
   * showing the two runs side by side — is the only party that can.
   */
  silentDivergence: boolean;
  note: string;
}

/** Compare an encapsulated key with what a decapsulation produced. */
export function compareKemKeys(
  encapsulated: Uint8Array,
  decapsulated: KemDecapsulateResult,
): KemAgreement {
  if (!decapsulated.ok) {
    return {
      agreed: false,
      silentDivergence: false,
      note: `decapsulation reported an error at ${decapsulated.step}: ${decapsulated.cause}`,
    };
  }
  const agreed = bytesEqual(encapsulated, decapsulated.K);
  return {
    agreed,
    silentDivergence: !agreed,
    note: agreed
      ? 'the decapsulated key matches'
      : 'decapsulation succeeded and produced a DIFFERENT key: clause 6.2.1 has no integrity check, '
        + 'so a wrong private key is indistinguishable from a right one until something uses the key',
  };
}

// ---------------------------------------------------------------------------
// clause 7: public key encryption
// ---------------------------------------------------------------------------

export interface EncryptOptions {
  /** a) KDF stream cipher, or b) SM4-CBC. Default a), the mode with no cipher dependency. */
  mode?: CipherMode;
  /** Pin r. As for the KEM: the annexes print theirs. */
  r?: bigint;
  /** K1_len in bits — mode b) only, where K1 is the SM4 key. Default 128. */
  k1LenBits?: number;
  /** K2_len in bits, the MAC key. Default 256, as Annex D uses. */
  k2LenBits?: number;
  /** How many times step A6 may send us back to A2. */
  maxRestarts?: number;
}

export interface Encryption {
  mode: CipherMode;
  /** C1 = [r]Q_B — step A3. */
  C1: G1Point;
  C1Bytes: Uint8Array;
  /** C2, the enciphered message — step A6. */
  C2: Uint8Array;
  /** C3 = MAC(K2, C2) — step A7. */
  C3: Uint8Array;
  /** The ciphertext as the standard concatenates it: C1 || C3 || C2 — step A8. */
  bytes: Uint8Array;
  h1: bigint;
  Qb: G1Point;
  r: bigint;
  g: Gt;
  w: Gt;
  wBytes: Uint8Array;
  kdfInput: Uint8Array;
  /** klen the KDF was asked for: mlen + K2_len in mode a), K1_len + K2_len in mode b). */
  klenBits: number;
  /** K = K1 || K2. */
  K: Uint8Array;
  K1: Uint8Array;
  K2: Uint8Array;
  /** M || padding — mode b) only. The annex prints this as its M'. */
  paddedMessage?: Uint8Array;
  restarts: number;
}

/**
 * Mode b)'s padding — GM/T 0044.4 clause 7.1.1 step A6 b) 2).
 *
 * l = K1_len/8 and the message is extended with l - (m mod l) bytes, each equal
 * to that count. A message that is already a whole number of blocks gains a
 * FULL block, which is what makes the padding unambiguous to remove: the count
 * is never zero, so the last byte always says how much to drop. Annex D's
 * 20-byte message takes 12 bytes of 0x0C.
 */
export function padForBlockCipher(message: Uint8Array, blockBytes: number): Uint8Array {
  if (blockBytes <= 0 || blockBytes > 255) throw new RangeError('padForBlockCipher: implausible block size');
  const padLength = blockBytes - (message.length % blockBytes);
  return concatBytes(message, new Uint8Array(padLength).fill(padLength));
}

/** Remove the padding above, or say why it is not removable. */
export function stripBlockCipherPadding(
  padded: Uint8Array,
  blockBytes: number,
): { ok: true; message: Uint8Array } | { ok: false; message: string } {
  if (padded.length === 0 || padded.length % blockBytes !== 0) {
    return { ok: false, message: `padding: ${padded.length} bytes is not a whole number of ${blockBytes}-byte blocks` };
  }
  const padLength = padded[padded.length - 1];
  if (padLength < 1 || padLength > blockBytes || padLength > padded.length) {
    return { ok: false, message: `padding: final byte 0x${padLength.toString(16)} is not a valid pad length` };
  }
  for (let i = padded.length - padLength; i < padded.length; i++) {
    if (padded[i] !== padLength) return { ok: false, message: 'padding: the pad bytes are not all equal to the pad length' };
  }
  return { ok: true, message: padded.subarray(0, padded.length - padLength) };
}

/**
 * Public key encryption — GM/T 0044.4 clause 7.1.1, steps A1 to A8.
 *
 * Steps A1 to A5 are identical to the KEM's, deliberately: SM9's encryption IS
 * its KEM with a DEM bolted on, and the shared code here makes that visible
 * rather than being a remark.
 */
export function encrypt(
  message: Uint8Array,
  identity: Identity,
  hid: number,
  Ppube: G1Point,
  options: EncryptOptions = {},
): Encryption {
  const mode = options.mode ?? 'a';
  const k2LenBits = options.k2LenBits ?? 256;
  const k1LenBits = options.k1LenBits ?? 128;
  const maxRestarts = options.maxRestarts ?? 8;
  if (k2LenBits <= 0 || k2LenBits % 8 !== 0) throw new RangeError('encrypt: K2_len must be a positive whole number of bytes');
  if (mode === 'b' && (k1LenBits <= 0 || k1LenBits % 8 !== 0)) {
    throw new RangeError('encrypt: K1_len must be a positive whole number of bytes');
  }

  const idBytes = identityBytes(identity);
  const { h1, Qb } = receiverPublicPoint(identity, hid, Ppube); // A1
  const g = pairingBase(Ppube); // A4

  // Mode a) makes K1 a one-time pad, so its length is the message's; mode b)
  // makes K1 a block cipher key, so its length is fixed by the cipher.
  const mlenBits = message.length * 8;
  const k1Bytes = mode === 'a' ? message.length : k1LenBits / 8;
  const klenBits = (mode === 'a' ? mlenBits : k1LenBits) + k2LenBits;

  for (let restarts = 0; restarts <= maxRestarts; restarts++) {
    const r = options.r ?? randomScalar(); // A2
    if (!isValidScalar(r)) throw new RangeError('encrypt: r must be in [1, N-1]');

    const C1 = mulG1(r, Qb); // A3
    const C1Bytes = g1ToBytes(C1);
    const w = powGt(g, r); // A5
    const wBytes = fp12ToBytes(w);
    const kdfInput = concatBytes(C1Bytes, wBytes, idBytes); // A6: C1 || w || ID_B
    const K = KDF(kdfInput, klenBits);
    const K1 = K.subarray(0, k1Bytes);
    const K2 = K.subarray(k1Bytes);

    // A6: "if K1 is the all-zero bit string, go back to A2."
    if (isAllZero(K1)) {
      if (options.r !== undefined) {
        throw new Error('encrypt: step A6 produced an all-zero K1 and r was pinned, so A2 cannot be retried');
      }
      continue;
    }

    let C2: Uint8Array;
    let paddedMessage: Uint8Array | undefined;
    if (mode === 'a') {
      C2 = Uint8Array.from(message, (byte, i) => byte ^ K1[i]);
    } else {
      // A6 b): pad, then Enc. The IV is all zeros — CBC needs one and the
      // standard supplies none, so Annex D's worked example fixes it at zero.
      paddedMessage = padForBlockCipher(message, SM4_BLOCK_BYTES);
      C2 = Uint8Array.from(encryptCBC(K1, paddedMessage, new Uint8Array(SM4_BLOCK_BYTES)));
    }
    const C3 = mac(K2, C2); // A7
    const bytes = concatBytes(C1Bytes, C3, C2); // A8: C = C1 || C3 || C2

    return {
      mode, C1, C1Bytes, C2, C3, bytes,
      h1, Qb, r, g, w, wBytes, kdfInput, klenBits,
      K, K1: Uint8Array.from(K1), K2: Uint8Array.from(K2), paddedMessage, restarts,
    };
  }
  throw new Error(`encrypt: step A6 produced an all-zero K1 ${maxRestarts + 1} times`);
}

/** Why decryption refused, by name. Every one of these is a DIFFERENT event. */
export type DecryptFailureCause =
  /** Shorter than C1 || C3, so there is nothing to check. */
  | 'CIPHERTEXT_TRUNCATED'
  | `C1_${G1RejectionCause}`
  /** Mode b) only: C2's length is not a whole number of SM4 blocks. */
  | 'C2_NOT_BLOCK_ALIGNED'
  /** Step B3's only error. */
  | 'K1_ALL_ZERO'
  /** Step B4: u != C3. The integrity check, and the one the KEM does not have. */
  | 'MAC_MISMATCH'
  /** Mode b) only, after B4 has already accepted: the plaintext's padding is malformed. */
  | 'PADDING_INVALID';

export interface DecryptFailure {
  ok: false;
  /** The step of clause 7.2.1 that refused. */
  step: 'B1' | 'B3' | 'B4' | 'B5';
  cause: DecryptFailureCause;
  message: string;
}

export interface DecryptSuccess {
  ok: true;
  /** M' — step B5. */
  message: Uint8Array;
  mode: CipherMode;
  C1: G1Point;
  C1Bytes: Uint8Array;
  C2: Uint8Array;
  C3: Uint8Array;
  /** w' = e(C1, de_B) — step B2. */
  w: Gt;
  wBytes: Uint8Array;
  kdfInput: Uint8Array;
  klenBits: number;
  K: Uint8Array;
  K1: Uint8Array;
  K2: Uint8Array;
  /** u = MAC(K2', C2) — step B4. Equal to C3, or this would be a failure. */
  u: Uint8Array;
  /** M' before the padding was removed — mode b) only. The annex prints this. */
  paddedMessage?: Uint8Array;
}

export type DecryptResult = DecryptSuccess | DecryptFailure;

export interface DecryptOptions {
  mode?: CipherMode;
  /** K1_len in bits — mode b) only. Must match what the sender used. Default 128. */
  k1LenBits?: number;
  /** K2_len in bits. Must match what the sender used. Default 256. */
  k2LenBits?: number;
}

/** C1 || C3 || C2, split at the two fixed-length fields. */
export function parseCiphertext(
  bytes: Uint8Array,
): { ok: true; C1Bytes: Uint8Array; C3: Uint8Array; C2: Uint8Array } | { ok: false; message: string } {
  const header = G1_POINT_BYTES + MAC_BYTES;
  if (bytes.length < header) {
    return { ok: false, message: `ciphertext is ${bytes.length} bytes, shorter than C1||C3 (${header})` };
  }
  return {
    ok: true,
    C1Bytes: bytes.subarray(0, G1_POINT_BYTES),
    C3: bytes.subarray(G1_POINT_BYTES, header),
    C2: bytes.subarray(header),
  };
}

/**
 * Decryption — GM/T 0044.4 clause 7.2.1, steps B1 to B5.
 *
 * The step order is the standard's, and where it matters it is followed rather
 * than improved on. In particular B3's M' for mode b) is the PADDED plaintext —
 * Annex D prints exactly that at its own B3 — so the padding comes off at B5,
 * AFTER the MAC has accepted the ciphertext. That ordering is the standard's,
 * and it also happens to be the safe one: a padding failure that could be
 * reported before the MAC is checked is a padding oracle, and here it cannot be,
 * because nothing with a wrong C2 reaches B5.
 */
export function decrypt(
  ciphertext: Uint8Array,
  identity: Identity,
  deB: G2Point,
  options: DecryptOptions = {},
): DecryptResult {
  const mode = options.mode ?? 'a';
  const k1LenBits = options.k1LenBits ?? 128;
  const k2LenBits = options.k2LenBits ?? 256;

  const parsed = parseCiphertext(ciphertext);
  if (!parsed.ok) {
    return { ok: false, step: 'B1', cause: 'CIPHERTEXT_TRUNCATED', message: `B1: ${parsed.message}` };
  }
  const { C1Bytes, C3, C2 } = parsed;

  const admission = admitG1(C1Bytes); // B1
  if (!admission.ok) {
    return { ok: false, step: 'B1', cause: `C1_${admission.cause}`, message: admission.message };
  }
  if (mode === 'b' && (C2.length === 0 || C2.length % SM4_BLOCK_BYTES !== 0)) {
    return {
      ok: false,
      step: 'B3',
      cause: 'C2_NOT_BLOCK_ALIGNED',
      message: `B3: C2 is ${C2.length} bytes, not a whole number of ${SM4_BLOCK_BYTES}-byte SM4 blocks`,
    };
  }
  const C1 = admission.point;

  const w = pairing(deB, C1); // B2: w' = e(C1, de_B)
  const wBytes = fp12ToBytes(w);
  const kdfInput = concatBytes(g1ToBytes(C1), wBytes, identityBytes(identity)); // B3

  // mlen is recovered from the ciphertext in mode a), where C2 is the message
  // length; in mode b) K1 is the cipher key and its length is a parameter.
  const k1Bytes = mode === 'a' ? C2.length : k1LenBits / 8;
  const klenBits = k1Bytes * 8 + k2LenBits;
  const K = KDF(kdfInput, klenBits);
  const K1 = Uint8Array.from(K.subarray(0, k1Bytes));
  const K2 = Uint8Array.from(K.subarray(k1Bytes));
  if (isAllZero(K1)) {
    return { ok: false, step: 'B3', cause: 'K1_ALL_ZERO', message: "B3: K1' is the all-zero bit string" };
  }

  // B3 continued: M' = C2 xor K1' in mode a), Dec(K1', C2) in mode b).
  const decrypted = mode === 'a'
    ? Uint8Array.from(C2, (byte, i) => byte ^ K1[i])
    : Uint8Array.from(decryptCBC(K1, C2, new Uint8Array(SM4_BLOCK_BYTES)));

  // B4: "u = MAC(K2', C2); if u != C3, report an error and exit."
  // This is the step the KEM has no equivalent of.
  const u = mac(K2, C2);
  if (!bytesEqual(u, C3)) {
    return {
      ok: false,
      step: 'B4',
      cause: 'MAC_MISMATCH',
      message: `B4: u != C3, so this ciphertext was altered or was not encrypted to this identity `
        + `(u = ${bytesToHex(u).slice(0, 16)}..., C3 = ${bytesToHex(C3).slice(0, 16)}...)`,
    };
  }

  if (mode === 'a') {
    return { ok: true, message: decrypted, mode, C1, C1Bytes, C2, C3, w, wBytes, kdfInput, klenBits, K, K1, K2, u }; // B5
  }
  const stripped = stripBlockCipherPadding(decrypted, SM4_BLOCK_BYTES);
  if (!stripped.ok) {
    // Unreachable for anything this module produced: B4 has already accepted, so
    // C2 and K1' are the sender's. It is reported rather than thrown because a
    // ciphertext can be built by something other than `encrypt`.
    return { ok: false, step: 'B5', cause: 'PADDING_INVALID', message: `B5: ${stripped.message}` };
  }
  return {
    ok: true, message: stripped.message, mode, C1, C1Bytes, C2, C3,
    w, wBytes, kdfInput, klenBits, K, K1, K2, u, paddedMessage: decrypted,
  };
}
