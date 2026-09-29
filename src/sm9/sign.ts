/**
 * The SM9 digital signature algorithm — GM/T 0044.2 clause 6.1 (generation) and
 * clause 7.1 (verification).
 *
 * WHAT A ROUND TRIP DOES NOT PROVE. This is the most important comment in the
 * module, so it is first.
 *
 * An SM9 sign -> verify round trip does NOT establish that H1, the identity
 * encoding, or hid is correct. Extraction (see extract.ts) sets
 *     t1 = H1(ID||hid) + ks        t2 = ks * t1^-1
 * so t1 * t2 == ks for ANY value of H1 whatsoever. Verification then forms
 *     P = [H1]P2 + Ppub-s = [t1]P2        S = [l]ds_A = [l * t2]P1
 * and takes
 *     u = e(S, P) = e(P1, P2)^(l * t2 * t1) = e(P1, P2)^(l * ks).
 * H1 cancels when both sides use the same one. The equation does not pin WHICH
 * identity-to-scalar map produced the key —
 * only that extraction and verification used the SAME one.
 *
 * This was established by running it, not by reading the algebra: an H1 with a
 * deliberately wrong domain prefix, used consistently on both sides, yields a
 * DIFFERENT ds_A, the SAME u, the SAME signature component h, and VERIFIES.
 * The demonstration is sign.test.ts's
 * "a wrong H1 used consistently still verifies" block, which is the evidence
 * behind the lab's section 4.1d negative claim.
 *
 * The consequence for this lab, and for anyone reading it as an example: the
 * only thing that catches a wrong H1 is GM/T 0044.5 Annex A's PINNED
 * intermediates — H1, t1, t2 and ds_A — which is why sign.test.ts checks every
 * one of them rather than the final (h, S) pair alone.
 *
 * ENGINE HAZARDS OBSERVED HERE. (1) every multiplied point is normalised to
 * affine before it is added or paired, via extract.ts's mulG1/mulG2 and
 * pairing.ts. (2) Fp12 octet order is the standard's printed order, which is the
 * reverse of the engine's storage order — fp12Components() is the only place
 * that conversion happens. (3) the engine's fp12_pow reduces its exponent modulo
 * the field characteristic p, not modulo N, so r and h are range-checked here;
 * inheriting that check from the engine would mean not checking it.
 */
import { fp12_mul, fp12_new, fp12_pow, point_is_on_curve, twist_point_add_full, twist_point_new } from '../vendor/gmssl-sm9.js';
import { HID, N } from './params';
import { isValidScalar, sub } from './fn';
import { H2, bytesToHex, concatBytes, hexToBytes } from './hash';
import { pairing, toAffineG2 } from './pairing';
import type { G1Point, G2Point, Gt } from './pairing';
import {
  encodeIdentity,
  generatorP1,
  generatorP2,
  identityHashH1,
  mulG1,
  mulG2,
  toFieldHex,
} from './extract';
import type { IdentityHash } from './extract';

/** The engine's Fp12 storage shape: 3 x 2 x 2 base-field elements. */
type Fp12Raw = bigint[][][];

function fp12Flat(element: Gt): bigint[] {
  const a = element as Fp12Raw;
  return [
    a[0][0][0], a[0][0][1], a[0][1][0], a[0][1][1],
    a[1][0][0], a[1][0][1], a[1][1][0], a[1][1][1],
    a[2][0][0], a[2][0][1], a[2][1][0], a[2][1][1],
  ];
}

/**
 * The twelve components of an Fp12 element in the order GM/T 0044.5's annexes
 * print them — a FULL reversal of the engine's flattened order (i = 2..0,
 * j = 1..0, k = 1..0), because the annexes write the 1-2-4-12 tower descending
 * and the engine stores it ascending.
 *
 * This is not cosmetic. H2 hashes w as octets, so the component order is part of
 * the signature: get it wrong and every h disagrees with the standard while both
 * sides of your own round trip still agree with each other.
 */
export function fp12Components(element: Gt): string[] {
  return fp12Flat(element).map(toFieldHex).reverse();
}

/** An Fp12 element as the 384 octets the standard hashes. */
export function fp12ToOctets(element: Gt): Uint8Array {
  return hexToBytes(fp12Components(element).join(''));
}

/** An SM9 signature: the pair (h, S) of GM/T 0044.2 clause 6.1 step A7. */
export interface Sm9Signature {
  /** h in [1, N-1]. */
  h: bigint;
  /** S = [l]ds_A, a point of G1, affine. */
  S: G1Point;
}

/**
 * The signature as octets: h is 32 bytes big-endian, S is the uncompressed
 * 0x04 || x || y form GM/T 0044.5 Annex A prints.
 */
export function signatureToHex(signature: Sm9Signature): { h: string; S: string } {
  return {
    h: toFieldHex(signature.h),
    S: '04' + toFieldHex(signature.S.X) + toFieldHex(signature.S.Y),
  };
}

/**
 * A source of the per-signature nonce r, GM/T 0044.2 clause 6.1 step A2:
 * "produce a random number r in [1, N-1]".
 *
 * Injectable so that Annex A's PINNED r can be replayed — the annex's worked
 * example is only reproducible if r is fixed — and so the reused-nonce attack
 * exhibit can hand the same r to two signatures on purpose. Defaults to
 * crypto.getRandomValues; nothing in this module ever reaches for a default
 * that is not cryptographically random.
 */
export type NonceSource = () => bigint;

/**
 * Uniform r in [1, N-1] by rejection sampling over 32 bytes.
 *
 * Rejection rather than reduction: reducing a 256-bit sample mod N biases the
 * low end of the range, and for the signature nonce that bias is exactly what
 * lattice attacks on (EC)DSA-shaped schemes eat. The rejection probability here
 * is under 2^-32 per draw.
 */
export const randomNonce: NonceSource = () => {
  const bytes = new Uint8Array(32);
  for (;;) {
    crypto.getRandomValues(bytes);
    const candidate = BigInt('0x' + bytesToHex(bytes));
    if (isValidScalar(candidate)) return candidate;
  }
};

/** Every intermediate of clause 6.1, kept so the page can render the algorithm. */
export interface SignResult {
  signature: Sm9Signature;
  /** A1: g = e(P1, Ppub-s), an element of GT. */
  g: Gt;
  /** A2: the nonce r actually used. */
  r: bigint;
  /** A4: w = g^r. */
  w: Gt;
  /** A5: the octet string M || w that H2 consumed. */
  messageWithW: Uint8Array;
  /** A5: h = H2(M || w, N). */
  h: bigint;
  /** A6: l = (r - h) mod N. */
  l: bigint;
  /** A7: S = [l]ds_A, affine. */
  S: G1Point;
  /** How many nonces were drawn. More than one means l == 0 came up. */
  attempts: number;
}

export interface SignOptions {
  nonce?: NonceSource;
  /** Guard on the clause 6.1 step A6 restart. A deterministic nonce that yields l == 0 would otherwise loop forever. */
  maxAttempts?: number;
}

/**
 * Sign a message — GM/T 0044.2 clause 6.1.
 *
 * Note what signing does NOT touch: H1, the identity, and hid appear nowhere
 * below. The signer's whole claim to the identity is carried by ds_A, which the
 * KGC issued. That is the structural reason the cancellation documented at the
 * top of this file is possible at all.
 */
export function sign(
  message: Uint8Array,
  dsA: G1Point,
  Ppubs: G2Point,
  options: SignOptions = {},
): SignResult {
  const nonce = options.nonce ?? randomNonce;
  const maxAttempts = options.maxAttempts ?? 8;

  // A1: g = e(P1, Ppub-s). pairing() takes the G2 argument first and normalises
  // both, so this line IS the standard's e(P1, Ppub-s).
  const g = pairing(Ppubs, generatorP1());

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    // A2: r in [1, N-1], checked here rather than trusted. The engine's fp12_pow
    // reduces its exponent mod p, so an out-of-range r would be silently
    // accepted below instead of rejected.
    const r = nonce();
    if (!isValidScalar(r)) {
      throw new RangeError(`sign: nonce source returned r outside [1, N-1]: ${r}`);
    }

    // A4: w = g^r.
    const w = fp12_new();
    fp12_pow(w, g, r);

    // A5: h = H2(M || w, N), with w in the standard's printed component order.
    const messageWithW = concatBytes(message, fp12ToOctets(w));
    const h = H2(messageWithW, N).h;

    // A6: l = (r - h) mod N; if l == 0, go back to A2 and draw a fresh r.
    const l = sub(r, h);
    if (l === 0n) continue;

    // A7: S = [l]ds_A. ds_A is affine (extract.ts normalises it) and the result
    // is normalised, so nothing downstream inherits a Jacobian point.
    const S = mulG1(l, dsA);

    return { signature: { h, S }, g, r, w, messageWithW, h, l, S, attempts: attempt };
  }

  throw new RangeError(
    `sign: l == 0 on all ${maxAttempts} attempts. With a random nonce this is a ` +
      '2^-256-per-draw event; with an injected nonce source it means the source ' +
      'is returning the same r, which clause 6.1 step A6 cannot escape.',
  );
}

/** Why a verification failed, in the order clause 7.1 checks them. */
export type VerifyFailure =
  | 'H-OUT-OF-RANGE'
  | 'S-AT-INFINITY'
  | 'S-NOT-ON-CURVE'
  | 'HASH-MISMATCH';

/** Every intermediate of clause 7.1 that was reached before the verdict. */
export interface VerifySteps {
  /** S3: g = e(P1, Ppub-s), recomputed by the verifier. */
  g?: Gt;
  /** S4: t = g^h'. */
  t?: Gt;
  /** S5: h1 = H1(ID_A || hid, N). */
  h1?: bigint;
  /** S5: P = [h1]P2 + Ppub-s, affine. */
  P?: G2Point;
  /** S5: u = e(S', P). */
  u?: Gt;
  /** S5: w' = u * t. */
  wPrime?: Gt;
  /** S6: the octet string M' || w'. */
  messageWithWPrime?: Uint8Array;
  /** S6: h2 = H2(M' || w', N). */
  h2?: bigint;
}

export interface VerifyResult {
  accepted: boolean;
  /** null exactly when `accepted` is true. */
  failure: VerifyFailure | null;
  steps: VerifySteps;
}

export interface VerifyOptions {
  /** Defaults to HID.SIGN (0x01), the value GM/T 0044.5 Annex A declares. */
  hid?: number;
  /**
   * Defaults to the real H1. A verifier and a KGC that agree on a WRONG identity
   * hash still accept every signature between them — see the module header.
   */
  identityHash?: IdentityHash;
}

/**
 * Verify a signature — GM/T 0044.2 clause 7.1.
 *
 * The step order is the standard's, and it matters: the range check on h' comes
 * FIRST, before any curve or pairing work, because the engine's fp12_pow would
 * otherwise reduce an out-of-range h modulo p and produce a well-formed answer
 * to a malformed question.
 */
export function verify(
  message: Uint8Array,
  identity: string | Uint8Array,
  signature: Sm9Signature,
  Ppubs: G2Point,
  options: VerifyOptions = {},
): VerifyResult {
  const hid = options.hid ?? HID.SIGN;
  const identityHash = options.identityHash ?? identityHashH1;
  const steps: VerifySteps = {};

  // S1: h' in [1, N-1].
  if (!isValidScalar(signature.h)) {
    return { accepted: false, failure: 'H-OUT-OF-RANGE', steps };
  }

  // S2: S' is a point of G1. The cofactor is 1 (params.ts COFACTOR), so on the
  // curve and not at infinity is the whole of "in G1" here — there is no
  // small-subgroup residue for a cofactor-1 curve.
  if (signature.S.Z === 0n) {
    return { accepted: false, failure: 'S-AT-INFINITY', steps };
  }
  if (!point_is_on_curve(signature.S)) {
    return { accepted: false, failure: 'S-NOT-ON-CURVE', steps };
  }

  // S3: g = e(P1, Ppub-s).
  const g = pairing(Ppubs, generatorP1());
  steps.g = g;

  // S4: t = g^h'.
  const t = fp12_new();
  fp12_pow(t, g, signature.h);
  steps.t = t;

  // S5: h1 = H1(ID_A || hid, N); P = [h1]P2 + Ppub-s; u = e(S', P); w' = u * t.
  const h1 = identityHash(encodeIdentity(identity, hid));
  steps.h1 = h1;
  const h1P2 = mulG2(h1, generatorP2());
  const sum = twist_point_new();
  twist_point_add_full(sum, h1P2, Ppubs);
  const P = toAffineG2(sum as G2Point);
  steps.P = P;
  const u = pairing(P, signature.S);
  steps.u = u;
  const wPrime = fp12_new();
  fp12_mul(wPrime, u, t);
  steps.wPrime = wPrime;

  // S6: h2 = H2(M' || w', N); accept iff h2 == h'.
  const messageWithWPrime = concatBytes(message, fp12ToOctets(wPrime));
  steps.messageWithWPrime = messageWithWPrime;
  const h2 = H2(messageWithWPrime, N).h;
  steps.h2 = h2;

  const accepted = h2 === signature.h;
  return { accepted, failure: accepted ? null : 'HASH-MISMATCH', steps };
}
