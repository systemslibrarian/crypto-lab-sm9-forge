/**
 * SM9 identity-based key exchange — GM/T 0044.3-2016 clause 6.1, steps A1-A8 and
 * B1-B8, together with the encryption-key extraction of clause 5.3 that feeds it.
 *
 * WHAT THIS MODULE IS FOR. The protocol itself is eight lines of algebra. What the
 * lab is actually about is the interoperability fault line underneath it: the same
 * master key, the same two identities and the same two nonces produce two different
 * session keys depending on which one-byte `hid` the KGC publishes, and the standard
 * and the widest-deployed implementations do not agree on the byte. So `hid` is a
 * parameter here, never a constant, and every result is labelled by the SOURCE that
 * declares its hid rather than by a verdict. See HID_CONVENTIONS below.
 *
 * WHY g1, g2 AND g3 DO NOT DEPEND ON hid — the algebra, because it is the deepest
 * point in the exhibit and it is not obvious from the clause text.
 *
 *   hid enters in exactly one place: the scalar H1(ID || hid, N). For B that scalar
 *   is t3 - ke, so writing h_B = H1(ID_B || hid, N):
 *
 *     Q_B  = [h_B]P1 + Ppub-e = [h_B + ke]P1 = [t3]P1        (A1, with clause 5.3's t3)
 *     R_A  = [r_A]Q_B         = [r_A * t3]P1                 (A3)
 *     de_B = [t4]P2           = [ke * t3^-1]P2               (clause 5.3)
 *
 *     g1   = e(R_A, de_B) = e(P1, P2)^(r_A * t3 * ke * t3^-1)
 *                         = e(P1, P2)^(r_A * ke)
 *                         = e([ke]P1, P2)^r_A = e(Ppub-e, P2)^r_A
 *
 *   t3 cancels. hid is inside t3 and nowhere else, so g1 is hid-independent — and it
 *   is also, in the same line, the proof that A's g1' (computed as e(Ppub-e,P2)^r_A,
 *   which never touches hid at all) equals B's g1. The identical argument with t1 on
 *   A's side gives g2 = g2' = e(Ppub-e, P2)^r_B, and g3 = g1^r_B = (g2')^r_A follows.
 *
 *   So changing hid changes SK ONLY through R_A and R_B in the KDF input — the group
 *   elements the two sides pair are byte-identical at 0x02 and at 0x03. This is the
 *   same structural cancellation the signature side shows, and the two together are
 *   the lab's deepest point. src/sm9/exchange.test.ts asserts it rather than asserting
 *   the prose: it runs both hid values and compares g1, g2, g3 byte for byte.
 *
 * THE ENGINE HAZARDS THIS MODULE IS WRITTEN AROUND. The vendored GmSSL-JS engine has
 * three edges that corrupt results silently, with no throw:
 *   1. `point_mul` / `twist_point_mul` RETURN Jacobian points, while `point_add`,
 *      `twist_point_add` and `sm9_pairing` READ their point arguments as affine and
 *      ignore Z. `point_mul` itself calls `point_add(Q, Q, P)`, so even its own P
 *      argument must already be affine. Every point that crosses a boundary here is
 *      therefore normalised first — via src/sm9/pairing.ts's helpers, which is also
 *      why every pairing in this lab goes through `pairing()` and never `sm9_pairing`.
 *   2. Fp2 and Fp12 limb order: the standard's annexes print the tower DESCENDING,
 *      the engine stores it ASCENDING. The serialisers below are the only place that
 *      reversal happens.
 *   3. `fp12_pow` reduces its exponent mod SM9_P, the field characteristic, NOT mod N.
 *      `gtPow` range-checks instead of relying on that.
 *
 * Provenance of the expected values: GM/T 0044.5-2016 Annex B, extracted from the
 * official text by line number into src/sm9/fixtures/sm9-keyexchange-vectors.json,
 * plus GmSSL C's own `test_sm9_z256_exchange` vectors for the 0x02 convention.
 */
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
  twist_point_mul,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';
import { sm3 } from '@li0ard/sm3';
import { HID, N } from './params';
import { add, inv, isValidScalar, mul } from './fn';
import {
  pairing,
  toAffineG1,
  toAffineG2,
  type G1Point,
  type G2Point,
  type Gt,
} from './pairing';
import { H1, KDF, bytesToHex, concatBytes } from './hash';

/** The engine's generators, typed. Both are stored affine. */
const P1 = SM9_P1 as G1Point;
const P2 = SM9_P2 as G2Point;

/** An Fp12 element as the engine lays it out: g[i][j][k], i<3, j<2, k<2. */
type Fp12Limbs = bigint[][][];

// ---------------------------------------------------------------------------
// Data-type conversion — GM/T 0044.1-2016 clause 6.2
// ---------------------------------------------------------------------------

/** Field element to 32 big-endian octets. q is 256 bits, so the width is fixed. */
function fieldElementToBytes(x: bigint): Uint8Array {
  const hex = x.toString(16).padStart(64, '0');
  if (hex.length !== 64) throw new RangeError(`field element out of range: ${hex.length / 2} bytes`);
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

/**
 * Fp2 to 64 octets, in the STANDARD's print order (a1 || a0).
 *
 * HAZARD 2. GmSSL-JS stores an Fp2 element ascending — a[0] is the constant term —
 * and GM/T 0044's annexes print it descending. Getting this backwards produces an
 * Fp12 comparison that fails in a way that looks cryptographic rather than clerical,
 * so the reversal lives here and nowhere else.
 */
function fp2ToBytes(a: bigint[]): Uint8Array {
  return concatBytes(fieldElementToBytes(a[1]), fieldElementToBytes(a[0]));
}

/**
 * A point of G1 to 64 octets, x || y.
 *
 * GM/T 0044.1 clause 6.2.8 converts a point to an octet string; clause 6.1 step B5
 * of this part cites 6.2.8 and 6.2.5 for R_A and R_B. The uncompressed form of 6.2.8
 * carries a leading PC octet 0x04, which the derived key input does NOT include:
 * Annex B's own KDF input is 1288 octets = |ID_A| 5 + |ID_B| 3 + 64 + 64 + 3 * 384,
 * so R_A and R_B contribute 64 octets each. The annex's printed input is the evidence
 * for the encoding; nothing here is inferred from the clause alone.
 */
export function g1ToBytes(p: G1Point): Uint8Array {
  const a = toAffineG1(p); // HAZARD 1: p may be Jacobian, straight out of point_mul
  return concatBytes(fieldElementToBytes(a.X), fieldElementToBytes(a.Y));
}

/** A point of G2 to 128 octets, x || y with each coordinate an Fp2 pair. */
export function g2ToBytes(p: G2Point): Uint8Array {
  const a = toAffineG2(p);
  return concatBytes(fp2ToBytes(a.X), fp2ToBytes(a.Y));
}

/**
 * An element of GT to 384 octets — GM/T 0044.1 clauses 6.2.6 and 6.2.5, cited by
 * steps B4 and A5.
 *
 * HAZARD 2 again, one level up: the whole 1-2-4-12 tower is reversed, not just each
 * Fp2. The engine's flat walk i = 0..2, j = 0..1, k = 0..1 is the element-wise
 * reverse of the standard's printed order, so the walk is reversed wholesale.
 */
export function gtToBytes(g: Gt): Uint8Array {
  const limbs = g as Fp12Limbs;
  const flat: bigint[] = [];
  for (let i = 0; i < 3; i++) for (let j = 0; j < 2; j++) for (let k = 0; k < 2; k++) flat.push(limbs[i][j][k]);
  flat.reverse();
  return concatBytes(...flat.map(fieldElementToBytes));
}

export const g1ToHex = (p: G1Point): string => bytesToHex(g1ToBytes(p));
export const g2ToHex = (p: G2Point): string => bytesToHex(g2ToBytes(p));
export const gtToHex = (g: Gt): string => bytesToHex(gtToBytes(g));

// ---------------------------------------------------------------------------
// Group operations, each with the precondition the engine will not check
// ---------------------------------------------------------------------------

/**
 * [k]P in G1, returned affine.
 *
 * HAZARD 1. `point_mul` is not merely a producer of Jacobian points, it is also a
 * CONSUMER of affine ones: its inner loop is `point_add(Q, Q, P)` and `point_add`
 * ignores its second operand's Z. Passing a Jacobian P gives a wrong answer with no
 * throw, so P is normalised on the way in as well as R on the way out.
 */
export function g1ScalarMul(k: bigint, p: G1Point): G1Point {
  if (!isValidScalar(k)) throw new RangeError('g1ScalarMul: scalar must be in [1, N-1]');
  const r = point_new();
  point_mul(r, k, toAffineG1(p));
  return toAffineG1(r as G1Point);
}

/** [k]P in G2, returned affine. Same precondition, same reason. */
export function g2ScalarMul(k: bigint, p: G2Point): G2Point {
  if (!isValidScalar(k)) throw new RangeError('g2ScalarMul: scalar must be in [1, N-1]');
  const r = twist_point_new();
  twist_point_mul(r, k, toAffineG2(p));
  return toAffineG2(r as G2Point);
}

/**
 * g^k in GT.
 *
 * HAZARD 3. The engine's `fp12_pow` opens with `k %= SM9_P` — the FIELD
 * characteristic, not the group order N. For a scalar the protocol actually uses that
 * reduction is a no-op, because N < q, but that is a fact about these parameters and
 * not something the engine promises. The range check is what makes it safe to rely
 * on: an exponent outside [1, N-1] is refused here rather than silently reduced
 * against the wrong modulus.
 */
export function gtPow(g: Gt, k: bigint): Gt {
  if (!isValidScalar(k)) throw new RangeError('gtPow: exponent must be in [1, N-1]');
  const r = fp12_new();
  fp12_pow(r, g, k);
  return r as Gt;
}

/**
 * Membership in G1 — GM/T 0044.1-2016 clause 4.5, required by steps B4 and A5.
 *
 * Three conditions: not the identity, on the curve, and of order N. The cofactor of
 * this curve is 1 (GM/T 0044.5 clause 3.1), so for a point already known to be on the
 * curve the order check cannot fail — it is performed anyway because the clause asks
 * for it and because the cofactor is a parameter, not a law.
 */
export function isInG1(p: G1Point): boolean {
  const a = toAffineG1(p);
  if (point_is_at_infinity(a)) return false;
  if (!point_is_on_curve(a)) return false;
  const t = point_new();
  point_mul(t, N, a);
  return point_is_at_infinity(t) === true;
}

/**
 * Byte equality for confirmation tags.
 *
 * The tags are public, so a variable-time compare leaks nothing here. The accumulate
 * form costs nothing and keeps the habit in the one place a reader will copy from.
 */
export function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * ID || hid, the argument H1 takes in clause 5.3 and in steps A1 and B1.
 *
 * The byte-typed sibling of hash.ts's `identityWithHid`, which takes a string. Annex B
 * publishes its identities as hex ("Alice" = 416c696365), and an identity is a byte
 * string in the standard rather than text, so the protocol layer works in bytes.
 */
function withHid(identity: Uint8Array, hid: number): Uint8Array {
  if (!Number.isInteger(hid) || hid < 0 || hid > 0xff) {
    throw new RangeError(`hid must be one byte, got ${hid}`);
  }
  return concatBytes(identity, Uint8Array.of(hid));
}

// ---------------------------------------------------------------------------
// The hid conventions — the exhibit
// ---------------------------------------------------------------------------

export interface HidConvention {
  /** The one-byte identifier itself. */
  readonly hid: number;
  /** Who declares it. Results are labelled by this, never by a verdict. */
  readonly source: string;
  /** What KIND of authority that source is. The two are not the same kind. */
  readonly kind: string;
  /** Where the declaration can be read. */
  readonly declaredAt: string;
  /** Is this value written down anywhere in GM/T 0044? */
  readonly inTheStandard: boolean;
}

/**
 * The two conventions this lab runs, and the reason `hid` is a parameter.
 *
 * NEITHER IS WRONG. GM/T 0044.2/.3/.4 clause 5.3 each say only that the KGC "chooses
 * a one-byte ... identifier hid and makes it public" — the normative text pins no
 * value at all, so 0x02 does not contradict the standard, and 0x03 is a choice made
 * by an informative annex rather than a requirement. What the divergence produces is
 * an interoperability failure with no error message: two conforming implementations
 * complete the protocol, each internally consistent, and derive different keys.
 */
export const HID_CONVENTIONS: readonly HidConvention[] = [
  {
    hid: HID.ENCRYPT,
    source: 'GM/T 0044.5-2016 Annex B',
    kind: 'national standard, informative annex',
    declaredAt: 'Annex B, "the identifier of the generating function of the encryption private key hid: 0x03"',
    inTheStandard: true,
  },
  {
    hid: HID.EXCHANGE_GMSSL,
    source: 'GmSSL, emmansun/gmsm and (reportedly) Bouncy Castle',
    kind: 'implementation convention',
    declaredAt: 'gmssl-sm9.h: #define SM9_HID_EXCH 0x02',
    inTheStandard: false,
  },
];

/** The convention that declares this hid, or undefined if this lab knows of none. */
export function hidConvention(hid: number): HidConvention | undefined {
  return HID_CONVENTIONS.find((c) => c.hid === hid);
}

// ---------------------------------------------------------------------------
// Clause 5.3 — the encryption master key and the user encryption private key
// ---------------------------------------------------------------------------

export interface EncryptionMasterKey {
  /** ke, the master private key, in [1, N-1]. */
  readonly ke: bigint;
  /** Ppub-e = [ke]P1, in G1, affine. */
  readonly Ppube: G1Point;
}

/** "computes the element Ppub-e = [ke]P1 in G1" — clause 5.3. */
export function encryptionMasterKey(ke: bigint): EncryptionMasterKey {
  if (!isValidScalar(ke)) throw new RangeError('encryptionMasterKey: ke must be in [1, N-1] (clause 5.3)');
  return { ke, Ppube: g1ScalarMul(ke, P1) };
}

export interface UserEncryptionKey {
  /** H1(ID || hid, N). */
  readonly h1: bigint;
  /** t1 = H1(ID || hid, N) + ke over F_N. Named t3 for B in the clause's own text. */
  readonly t1: bigint;
  /** t2 = ke * t1^-1 over F_N. Named t4 for B. */
  readonly t2: bigint;
  /** de = [t2]P2, in G2, affine. */
  readonly de: G2Point;
  /** The exact bytes hashed, ID || hid — what the annex prints beside its H1 value. */
  readonly hashInput: Uint8Array;
}

/**
 * The KGC's extraction of a user encryption private key — clause 5.3.
 *
 * "computes t1 = H1(ID_A || hid, N) + ke over the finite field F_N. If t1 = 0, it
 * regenerates the encryption master private key ... Otherwise, it computes
 * t2 = ke * t1^-1, and then computes de_A = [t2]P2."
 *
 * The t1 = 0 branch is a re-key, not an error the caller can retry through, so it is
 * thrown rather than returned: there is no de to hand back. It is unreachable for any
 * master key a real KGC would hold — it requires H1(ID || hid, N) = -ke — and it is
 * implemented because the clause makes it a named step, which is also why fn.inv
 * throws on 0 rather than returning a plausible wrong scalar.
 */
export function extractEncryptionKey(
  master: EncryptionMasterKey,
  identity: Uint8Array,
  hid: number,
): UserEncryptionKey {
  const hashInput = withHid(identity, hid);
  const h1 = H1(hashInput, N).h;
  const t1 = add(h1, master.ke);
  if (t1 === 0n) {
    throw new Error('extractEncryptionKey: t1 = 0, the master key must be regenerated (clause 5.3)');
  }
  const t2 = mul(master.ke, inv(t1));
  return { h1, t1, t2, de: g2ScalarMul(t2, P2), hashInput };
}

// ---------------------------------------------------------------------------
// Clause 6.1 — the protocol
// ---------------------------------------------------------------------------

export interface PeerPoint {
  /** H1(ID_peer || hid, N). */
  readonly h1: bigint;
  /** Q = [H1(ID_peer || hid, N)]P1 + Ppub-e, in G1, affine. */
  readonly Q: G1Point;
  /** The exact bytes hashed. The two lines Annex B misprints are these. */
  readonly hashInput: Uint8Array;
}

/**
 * A1 / B1: "Compute the element Q_B = [H1(ID_B || hid, N)]P1 + Ppub-e over G1".
 *
 * Both steps are this one function — A1 with the peer's identity ID_B, B1 with ID_A.
 * They are written once because they are the same formula, and because a second copy
 * is where a mirror error would live.
 *
 * Note what Q actually is: [h + ke]P1, which is [t1]P1 for that peer's t1 from clause
 * 5.3. Nothing in this step is secret — it is the peer's identity-derived public point
 * and anyone holding Ppub-e can compute it. That is what "identity-based" means here.
 */
export function peerPublicPoint(
  master: EncryptionMasterKey,
  identity: Uint8Array,
  hid: number,
): PeerPoint {
  const hashInput = withHid(identity, hid);
  const h1 = H1(hashInput, N).h;
  const hP1 = g1ScalarMul(h1, P1);
  const sum = point_new();
  // HAZARD 1: point_add reads its SECOND operand as affine. Both are affine here —
  // g1ScalarMul normalises its result, and Ppube is stored affine — and both are
  // passed that way deliberately rather than by luck.
  point_add(sum, hP1, master.Ppube);
  return { h1, Q: toAffineG1(sum as G1Point), hashInput };
}

/** The three GT elements one side computes. */
export interface SideValues {
  readonly g1: Gt;
  readonly g2: Gt;
  readonly g3: Gt;
}

/**
 * B4, the responder's side:
 *
 *   "Verify R_A in G1 ... Otherwise, compute over GT:
 *    g1 = e(R_A, de_B),  g2 = e(Ppub-e, P2)^r_B,  g3 = g1^r_B."
 *
 * ARGUMENT ORDER. The standard writes e(.,.) with its G1 argument FIRST; this lab's
 * `pairing()` takes G2 first, following the engine. So e(R_A, de_B) is
 * `pairing(deB, RA)` and e(Ppub-e, P2) is `pairing(P2, Ppube)`. Reading this function
 * against the clause means reading both arguments, not the order.
 *
 * THE SWAP. Compare this with `initiatorValues` below: g1 and g2 exchange FORMULAS
 * between the two sides. B pairs the received point with its own private key and
 * exponentiates the master pairing; A does the mirror. Both sides reach the same three
 * values, so a side that ran the wrong one of these two functions still agrees with
 * itself, still produces a well-formed SK, and still verifies its own tag against
 * itself — it just disagrees with the peer, and only at the very end. That is why the
 * two sides are separate functions with no shared body: there is no line here for a
 * copy-paste to keep.
 */
export function responderValues(
  master: EncryptionMasterKey,
  deB: G2Point,
  RA: G1Point,
  rB: bigint,
): SideValues {
  if (!isInG1(RA)) throw new Error('B4: R_A is not in G1, the protocol fails (GM/T 0044.1 clause 4.5)');
  const g1 = pairing(deB, RA);
  const g2 = gtPow(pairing(P2, master.Ppube), rB);
  const g3 = gtPow(g1, rB);
  return { g1, g2, g3 };
}

/**
 * A5, the initiator's side:
 *
 *   "Verify R_B in G1 ... Otherwise, compute over GT:
 *    g1' = e(Ppub-e, P2)^r_A,  g2' = e(R_B, de_A),  g3' = (g2')^r_A."
 *
 * Note g3' is raised from g2', where B raises g3 from g1 — the swap runs through the
 * third value as well, and taking g3' from g1' is self-consistent on this side too.
 */
export function initiatorValues(
  master: EncryptionMasterKey,
  deA: G2Point,
  RB: G1Point,
  rA: bigint,
): SideValues {
  if (!isInG1(RB)) throw new Error('A5: R_B is not in G1, the protocol fails (GM/T 0044.1 clause 4.5)');
  const g1 = gtPow(pairing(P2, master.Ppube), rA);
  const g2 = pairing(deA, RB);
  const g3 = gtPow(g2, rA);
  return { g1, g2, g3 };
}

/** The exact octets KDF is called on in B5 and A7 — 1288 for Annex B's parameters. */
export function sessionKeyInput(
  idA: Uint8Array,
  idB: Uint8Array,
  RA: G1Point,
  RB: G1Point,
  v: SideValues,
): Uint8Array {
  return concatBytes(
    idA,
    idB,
    g1ToBytes(RA),
    g1ToBytes(RB),
    gtToBytes(v.g1),
    gtToBytes(v.g2),
    gtToBytes(v.g3),
  );
}

export interface SessionKey {
  /** ID_A || ID_B || R_A || R_B || g1 || g2 || g3, the KDF's Z. */
  readonly kdfInput: Uint8Array;
  /** SK, klen bits of it. */
  readonly sk: Uint8Array;
}

/**
 * B5 / A7: "SK = KDF(ID_A || ID_B || R_A || R_B || g1 || g2 || g3, klen)".
 *
 * The identities are in protocol-role order — initiator then responder — on BOTH
 * sides, not "mine then theirs". `klenBits` is in bits because the clause's klen is.
 */
export function deriveSessionKey(
  idA: Uint8Array,
  idB: Uint8Array,
  RA: G1Point,
  RB: G1Point,
  v: SideValues,
  klenBits: number,
): SessionKey {
  const kdfInput = sessionKeyInput(idA, idB, RA, RB, v);
  return { kdfInput, sk: KDF(kdfInput, klenBits) };
}

export interface ConfirmationTags {
  /** g2 || g3 || ID_A || ID_B || R_A || R_B — 904 octets for Annex B's parameters. */
  readonly innerInput: Uint8Array;
  /** Hv(innerInput). */
  readonly inner: Uint8Array;
  /** 0x82 || g1 || inner. */
  readonly tag82Input: Uint8Array;
  /** Hv(0x82 || g1 || inner) — S_B at B6, and the same value A recomputes as S1 at A6. */
  readonly tag82: Uint8Array;
  /** 0x83 || g1 || inner. */
  readonly tag83Input: Uint8Array;
  /** Hv(0x83 || g1 || inner) — S_A at A8, and the same value B recomputes as S2 at B8. */
  readonly tag83: Uint8Array;
}

/**
 * The optional key confirmation of steps B6, A6, A8 and B8.
 *
 * All four steps are ONE construction, Hv(prefix || g1 || Hv(g2 || g3 || ID_A || ID_B
 * || R_A || R_B)), separated by a single leading byte and by who computes it:
 *
 *   B6  S_B = Hv(0x82 || g1  || inner)   B sends it
 *   A6  S1  = Hv(0x82 || g1' || inner')  A recomputes and checks S1 = S_B
 *   A8  S_A = Hv(0x83 || g1' || inner')  A sends it
 *   B8  S2  = Hv(0x83 || g1  || inner)   B recomputes and checks S2 = S_A
 *
 * So each side computes both tags from its own values and uses one to send and one to
 * check. That is why this returns both rather than taking a direction: the direction
 * lives in the protocol driver, and the function has nothing to get backwards.
 *
 * The prefix is what stops the two directions being the same string — without it S_B
 * and S_A would be identical and B's own tag would verify as A's reply. Note also
 * that g1 is OUTSIDE the inner hash while g2 and g3 are inside it: the outer hash is
 * what binds the tag to the shared secret, and Hv here is SM3, v = 256.
 */
export function confirmationTags(
  idA: Uint8Array,
  idB: Uint8Array,
  RA: G1Point,
  RB: G1Point,
  v: SideValues,
): ConfirmationTags {
  const innerInput = concatBytes(
    gtToBytes(v.g2),
    gtToBytes(v.g3),
    idA,
    idB,
    g1ToBytes(RA),
    g1ToBytes(RB),
  );
  const inner = sm3(innerInput);
  const g1Bytes = gtToBytes(v.g1);
  const tag82Input = concatBytes(Uint8Array.of(0x82), g1Bytes, inner);
  const tag83Input = concatBytes(Uint8Array.of(0x83), g1Bytes, inner);
  return {
    innerInput,
    inner,
    tag82Input,
    tag82: sm3(tag82Input),
    tag83Input,
    tag83: sm3(tag83Input),
  };
}

// ---------------------------------------------------------------------------
// The whole protocol, with every intermediate kept
// ---------------------------------------------------------------------------

export interface KeyExchangeInput {
  /** The KGC's encryption master private key. */
  readonly ke: bigint;
  /** ID_A, the initiator's identity, as octets. */
  readonly idA: Uint8Array;
  /** ID_B, the responder's identity, as octets. */
  readonly idB: Uint8Array;
  /** A2's r_A, in [1, N-1]. Supplied rather than generated so runs are reproducible. */
  readonly rA: bigint;
  /** B2's r_B, in [1, N-1]. */
  readonly rB: bigint;
  /** klen, in BITS. Annex B uses 0x80 = 128. */
  readonly klenBits: number;
  /** The hid the KGC publishes, used by clause 5.3 extraction. */
  readonly hid: number;
  /**
   * The hid used by steps A1 and B1, if it differs from the extraction hid.
   *
   * It should not differ, and in any real deployment it cannot — the standard uses one
   * hid symbol throughout. This parameter exists for exactly one experiment: Annex B
   * prints 0x03 in both extraction steps and 0x02 in the two exchange steps, and the
   * only way to settle whether those two 02 bytes are a third convention or a misprint
   * is to run them as written and look at the output. See the test file's third leg.
   */
  readonly protocolHid?: number;
}

/** One side's complete output. */
export interface SideTranscript extends SideValues, SessionKey, ConfirmationTags {}

export interface KeyExchangeTranscript {
  readonly hid: number;
  readonly protocolHid: number;
  /** Who declares this hid, or undefined if neither convention this lab knows does. */
  readonly convention: HidConvention | undefined;
  readonly master: EncryptionMasterKey;
  readonly deA: UserEncryptionKey;
  readonly deB: UserEncryptionKey;
  /** A1: Q_B, with the H1 scalar and hashed bytes behind it. */
  readonly qB: PeerPoint;
  /** B1: Q_A. */
  readonly qA: PeerPoint;
  /** A3: R_A = [r_A]Q_B. */
  readonly RA: G1Point;
  /** B3: R_B = [r_B]Q_A. */
  readonly RB: G1Point;
  /** B4-B6: g1, g2, g3, SK_B, S_B (tag82) and S2 (tag83). */
  readonly responder: SideTranscript;
  /** A5-A8: g1', g2', g3', SK_A, S1 (tag82) and S_A (tag83). */
  readonly initiator: SideTranscript;
  /** Do the two sides hold the same SK? The whole point of the protocol. */
  readonly agree: boolean;
  /** A6: does S1 = S_B? Key confirmation from B to A. */
  readonly confirmBtoA: boolean;
  /** B8: does S2 = S_A? Key confirmation from A to B. */
  readonly confirmAtoB: boolean;
}

/**
 * Run clause 6.1 end to end for one hid, keeping every intermediate the annex prints.
 *
 * Both parties are computed here, which a real deployment obviously does not do — A
 * never holds de_B and B never holds r_A. This is the lab's transcript view, and the
 * separation that matters is preserved where it matters: `responderValues` and
 * `initiatorValues` each see only what their own party holds, so neither side's
 * derivation can reach across for a value it should not have.
 */
export function runKeyExchange(input: KeyExchangeInput): KeyExchangeTranscript {
  const { ke, idA, idB, rA, rB, klenBits, hid } = input;
  const protocolHid = input.protocolHid ?? hid;

  const master = encryptionMasterKey(ke);
  const deA = extractEncryptionKey(master, idA, hid); // clause 5.3, t1/t2
  const deB = extractEncryptionKey(master, idB, hid); // clause 5.3, t3/t4

  const qB = peerPublicPoint(master, idB, protocolHid); // A1
  const RA = g1ScalarMul(rA, qB.Q); // A3 (A2 supplies r_A; A4 sends R_A)
  const qA = peerPublicPoint(master, idA, protocolHid); // B1
  const RB = g1ScalarMul(rB, qA.Q); // B3 (B2 supplies r_B; B7 sends R_B)

  const bValues = responderValues(master, deB.de, RA, rB); // B4
  const bKey = deriveSessionKey(idA, idB, RA, RB, bValues, klenBits); // B5
  const bTags = confirmationTags(idA, idB, RA, RB, bValues); // B6 and B8

  const aValues = initiatorValues(master, deA.de, RB, rA); // A5
  const aTags = confirmationTags(idA, idB, RA, RB, aValues); // A6 and A8
  const aKey = deriveSessionKey(idA, idB, RA, RB, aValues, klenBits); // A7

  return {
    hid,
    protocolHid,
    convention: protocolHid === hid ? hidConvention(hid) : undefined,
    master,
    deA,
    deB,
    qB,
    qA,
    RA,
    RB,
    responder: { ...bValues, ...bKey, ...bTags },
    initiator: { ...aValues, ...aKey, ...aTags },
    agree: bytesEqual(bKey.sk, aKey.sk),
    confirmBtoA: bytesEqual(aTags.tag82, bTags.tag82), // A6: S1 = S_B
    confirmAtoB: bytesEqual(bTags.tag83, aTags.tag83), // B8: S2 = S_A
  };
}
