/**
 * The R-ate pairing e: G2 x G1 -> GT, wrapped so it cannot be called wrongly.
 *
 * WHY THIS WRAPPER EXISTS. The vendored engine's `sm9_pairing` requires BOTH
 * arguments in AFFINE form and returns a silently wrong Fp12 element otherwise:
 * `eval_g_tangent` reads Q.X/Q.Y as though Z were 1 and never divides through,
 * and the Miller loop's `twist_point_add` is the mixed routine that never reads
 * Q.Z. Meanwhile `point_mul` and `twist_point_mul` return PROJECTIVE points.
 * There is no throw and no check upstream, so passing a freshly multiplied point
 * straight in produces a wrong answer that looks like a real Fp12 element.
 *
 * That is a silent-wrong-answer edge, which is the worst kind, so the fix is a
 * chokepoint rather than a comment: every pairing in this lab goes through
 * `pairing()`, which normalises both arguments first. src/sm9/pairing.test.ts
 * pins the failure it prevents by calling the raw engine both ways.
 */
import {
  sm9_pairing,
  fp12_new,
  point_get_affine,
  twist_point_get_affine,
  point_new,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';

/** An Fp12 element as the engine represents it. Opaque outside this module. */
export type Gt = unknown;
/** A point of G1 as the engine represents it. */
export type G1Point = { X: bigint; Y: bigint; Z: bigint };
/** A point of G2 (on the twist) as the engine represents it. */
export type G2Point = { X: bigint[]; Y: bigint[]; Z: bigint[] };

/** Normalise a G1 point to affine (Z = 1). Safe to call on an already-affine point. */
export function toAffineG1(p: G1Point): G1Point {
  const out = point_new();
  point_get_affine(out, p);
  return out as G1Point;
}

/** Normalise a G2 point to affine. Safe to call on an already-affine point. */
export function toAffineG2(p: G2Point): G2Point {
  const out = twist_point_new();
  twist_point_get_affine(out, p);
  return out as G2Point;
}

/**
 * e(Q, P) for Q in G2 and P in G1, with both arguments normalised first.
 *
 * Argument order follows the engine and the standard: the G2 element comes
 * first. GM/T 0044.2 clause 6.1 step A1 writes g = e(P1, Ppub-s) with G1 first,
 * so call sites that mirror the standard's notation should read carefully —
 * `pairing(Ppubs, P1)` is that g.
 */
export function pairing(q: G2Point, p: G1Point): Gt {
  const out = fp12_new();
  sm9_pairing(out, toAffineG2(q), toAffineG1(p));
  return out;
}
