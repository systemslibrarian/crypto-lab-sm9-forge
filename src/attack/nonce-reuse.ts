/**
 * DELIBERATELY BROKEN TEACHING PATH — the SM9 reused-nonce key recovery.
 *
 * ============================================================================
 * ISOLATION. Nothing in the normal signing path imports this file, and nothing
 * here must ever be called from one. Every export below recovers, or helps
 * recover, a private key from signatures that a correct signer would never have
 * produced. It exists so the lab can DEMONSTRATE the break against its own real
 * verifier, not so anything can perform it in earnest. The one honest use of
 * this module is the exhibit in src/attack/nonce-reuse.test.ts and PANE 5 of the
 * UI; a second importer is a bug.
 * ============================================================================
 *
 * THE MATHEMATICS, and the one way SM9 differs from every ECDSA-shaped scheme.
 *
 * SM9 signing (GM/T 0044.2 clause 6.1) draws a nonce r, sets h = H2(M || g^r),
 * l = (r - h) mod N, and outputs S = [l]ds_A, where ds_A is the signer's PRIVATE
 * KEY POINT in G1. Sign two different messages under the SAME r:
 *
 *     S1 = [(r - h1)]ds_A          S2 = [(r - h2)]ds_A
 *     S1 - S2 = [(r - h1) - (r - h2)]ds_A = [h2 - h1]ds_A
 *     therefore  ds_A = [(h2 - h1)^-1 mod N] (S1 - S2)
 *
 * The r CANCELS. The attacker never learns it and never needs it: h1 and h2 are
 * public (they are half of each signature), and the recovery is one scalar
 * inversion mod N followed by one scalar multiplication in G1.
 *
 * WHAT IS RECOVERED IS A POINT, AND NO SCALAR. This is the whole exhibit.
 * crypto-lab-sm2-forge's equivalent attack recovers a scalar d
 * (see its src/attack/nonce-reuse.ts:38), because an SM2 private key IS a scalar
 * in Z_N and the reused nonce yields a linear equation d satisfies. An SM9
 * private key is a GROUP ELEMENT ds_A in G1. There is no scalar it "is", so
 * there is nothing to solve for and nothing to return but the point itself.
 * A recovery result here carries ds_A and no private scalar — the result type
 * has no field for one, and nonce-reuse.test.ts asserts that.
 *
 * THE DEGENERATE CASE. When h1 == h2 the two signatures are the same equation
 * written twice: h2 - h1 = 0 has no inverse mod N, and S1 - S2 is the point at
 * infinity. There is no second independent equation and no key to recover. This
 * module RETURNS a structured refusal in that case; it never fabricates a
 * plausible-looking key from a singular system. (fn.inv would throw on the zero
 * scalar regardless, so the refusal is a deliberate, named result rather than a
 * caught exception.)
 *
 * ENGINE HAZARD 1 (the affine precondition) applies to the subtraction. The
 * engine's point_add — which point_sub calls — reads its second operand as
 * affine and ignores its Z. Both operands are normalised before the subtraction
 * and the result is normalised after, through toAffineG1, so no Jacobian point
 * ever reaches point_add or the caller.
 */
import { point_equ, point_is_on_curve, point_mul, point_new, point_sub } from '../vendor/gmssl-sm9.js';
import { inv, sub } from '../sm9/fn';
import { toAffineG1 } from '../sm9/pairing';
import type { G1Point } from '../sm9/pairing';
import type { Sm9Signature } from '../sm9/sign';

/**
 * A recovered SM9 signing key.
 *
 * NOTE what is NOT here: any private scalar. dsA is a point of G1; its X, Y, Z
 * are field coordinates, not the key as a number, because the key is not a
 * number. `sDifference` is the intermediate S1 - S2 = [h2 - h1]ds_A, kept so the
 * UI can show the step. Neither is a scalar the attacker "solved for".
 */
export interface KeyRecovered {
  ok: true;
  method: 'two-signatures-reused-nonce' | 'single-signature-known-nonce';
  /** The recovered private key POINT ds_A in G1, affine. */
  dsA: G1Point;
  /** For the two-signature method, the point S1 - S2. Undefined otherwise. */
  sDifference?: G1Point;
}

/** The recovery was refused because the system is singular or malformed. */
export interface RecoveryRefused {
  ok: false;
  reason:
    | 'IDENTICAL-HASHES-NO-SECOND-EQUATION'
    | 'DIFFERENCE-AT-INFINITY'
    | 'NONCE-OUT-OF-RANGE'
    | 'RECOVERED-POINT-OFF-CURVE';
  detail: string;
}

export type RecoveryResult = KeyRecovered | RecoveryRefused;

/**
 * [k]P in G1, both operands kept affine (HAZARD 1). Written locally rather than
 * imported from extract.ts's mulG1: that function is part of the honest
 * key-issuance path, and the attack should not read as though it borrows it.
 */
function scalarMulG1(k: bigint, base: G1Point): G1Point {
  const affineBase = base.Z === 1n ? base : toAffineG1(base);
  const out = point_new();
  point_mul(out, k, affineBase);
  return toAffineG1(out as G1Point);
}

/**
 * NEVER CALL ON REAL SIGNATURES. Recover ds_A from two signatures made under one
 * reused nonce r over two different messages.
 *
 * The two signatures must share the nonce; this function cannot check that, and
 * on independent nonces it returns a wrong point that is NOT the key (S1 - S2 is
 * then [(r1 - h1) - (r2 - h2)]ds_A, and the scalar the attacker divides out is
 * the wrong one). The caller — only ever the exhibit — is responsible for the
 * reuse. What this function does guarantee: it refuses the singular h1 == h2
 * case rather than returning garbage, and it never returns a point off the curve.
 */
export function recoverFromReusedNonce(
  sig1: Sm9Signature,
  sig2: Sm9Signature,
): RecoveryResult {
  // The degenerate case: identical message hashes are one equation twice.
  if (sig1.h === sig2.h) {
    return {
      ok: false,
      reason: 'IDENTICAL-HASHES-NO-SECOND-EQUATION',
      detail:
        'h1 == h2, so h2 - h1 = 0 has no inverse mod N and S1 - S2 is the point ' +
        'at infinity. Two signatures with the same h under the same r are the ' +
        'same equation; there is no second, independent one to solve.',
    };
  }

  // S1 - S2 = [h2 - h1]ds_A. Both operands normalised; HAZARD 1.
  const difference = subtractG1(sig1.S, sig2.S);

  // The difference is at infinity only when [h2 - h1]ds_A = O, which for the
  // cofactor-1 group means h2 - h1 == 0 mod N — already handled above unless the
  // caller passed signatures under DIFFERENT keys. Guard anyway.
  if (difference.Z === 0n) {
    return {
      ok: false,
      reason: 'DIFFERENCE-AT-INFINITY',
      detail: 'S1 - S2 is the point at infinity, so no key can be recovered.',
    };
  }

  // ds_A = [(h2 - h1)^-1] (S1 - S2). fn.inv throws on a zero scalar, but the
  // guard above means the argument is non-zero here.
  const deltaH = sub(sig2.h, sig1.h); // (h2 - h1) mod N
  const dsA = scalarMulG1(inv(deltaH), difference);

  if (!point_is_on_curve(dsA)) {
    return {
      ok: false,
      reason: 'RECOVERED-POINT-OFF-CURVE',
      detail: 'The recovered point is not on y^2 = x^3 + 5; the inputs were not two SM9 signatures under one nonce.',
    };
  }

  return { ok: true, method: 'two-signatures-reused-nonce', dsA, sDifference: difference };
}

/**
 * NEVER CALL ON REAL SIGNATURES. The single-signature variant: if the nonce r is
 * known for even one signature, ds_A = [(r - h)^-1] S directly, because
 * S = [(r - h)]ds_A.
 *
 * This needs no second signature at all — a leaked or predictable r on ONE
 * signature is already fatal. It is the reason r must be both secret and
 * unpredictable, not merely non-repeating.
 */
export function recoverFromKnownNonce(
  sig: Sm9Signature,
  nonce: bigint,
): RecoveryResult {
  // l = (r - h) mod N. If l == 0 the signer would have redrawn r (clause 6.1
  // step A6), so a genuine signature never has l == 0; a claimed one that does
  // is malformed.
  const l = sub(nonce, sig.h);
  if (l === 0n) {
    return {
      ok: false,
      reason: 'NONCE-OUT-OF-RANGE',
      detail:
        'r - h = 0 mod N, which a correct signer never emits (clause 6.1 step A6 ' +
        'redraws r). S carries no multiple of ds_A to invert.',
    };
  }

  // ds_A = [l^-1] S.
  const dsA = scalarMulG1(inv(l), sig.S);

  if (!point_is_on_curve(dsA)) {
    return {
      ok: false,
      reason: 'RECOVERED-POINT-OFF-CURVE',
      detail: 'The recovered point is not on the curve; r was not this signature’s nonce.',
    };
  }

  return { ok: true, method: 'single-signature-known-nonce', dsA };
}

/** S1 - S2 with both operands normalised to affine first and the result
 *  normalised after. See HAZARD 1 in the module header. */
function subtractG1(a: G1Point, b: G1Point): G1Point {
  const out = point_new();
  point_sub(out, a.Z === 1n ? a : toAffineG1(a), b.Z === 1n ? b : toAffineG1(b));
  return toAffineG1(out as G1Point);
}

/** Point equality in G1, both operands normalised. Exposed for the exhibit so it
 *  can confirm a recovered key equals the genuinely extracted one WITHOUT
 *  comparing raw Jacobian coordinates, which differ for equal points. */
export function sameG1Point(a: G1Point, b: G1Point): boolean {
  return point_equ(a.Z === 1n ? a : toAffineG1(a), b.Z === 1n ? b : toAffineG1(b));
}
