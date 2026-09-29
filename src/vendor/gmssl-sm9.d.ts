/**
 * Ambient types for the vendored GmSSL-JS SM9 engine.
 *
 * Hand-written because the upstream file is plain JavaScript with no types and is
 * vendored verbatim (see src/vendor/gmssl-sm9.js for why it is here at all).
 * Deliberately loose: the engine's own representations (Fp2 as bigint[2], Fp12 as
 * nested arrays, points as {X,Y,Z}) are not re-modelled here, because narrowing
 * them in a declaration file would be a claim about code this repo does not own.
 * src/sm9/pairing.ts is the typed chokepoint that the rest of the lab uses.
 */

/** Field characteristic q, GM/T 0044.5 clause 3.1. */
export const SM9_P: bigint;
/** Group order N, GM/T 0044.5 clause 3.1. */
export const SM9_N: bigint;

export const SM9_P1: unknown;
export const SM9_P2: unknown;
export const SM9_Ppubs: unknown;

export function eval_g_line(...args: any[]): any;
export function eval_g_tangent(...args: any[]): any;
export function final_exponent(...args: any[]): any;
export function final_exponent_hard_part(...args: any[]): any;
export function fp12_add(...args: any[]): any;
export function fp12_copy(...args: any[]): any;
export function fp12_dbl(...args: any[]): any;
export function fp12_equ(...args: any[]): any;
export function fp12_frobenius(...args: any[]): any;
export function fp12_frobenius2(...args: any[]): any;
export function fp12_frobenius3(...args: any[]): any;
export function fp12_frobenius6(...args: any[]): any;
export function fp12_from_hex(...args: any[]): any;
export function fp12_inv(...args: any[]): any;
export function fp12_is_one(...args: any[]): any;
export function fp12_is_zero(...args: any[]): any;
export function fp12_mul(...args: any[]): any;
export function fp12_neg(...args: any[]): any;
export function fp12_new(...args: any[]): any;
export function fp12_pow(...args: any[]): any;
export function fp12_set(...args: any[]): any;
export function fp12_set_bn(...args: any[]): any;
export function fp12_set_fp2(...args: any[]): any;
export function fp12_set_fp4(...args: any[]): any;
export function fp12_set_hex(...args: any[]): any;
export function fp12_set_one(...args: any[]): any;
export function fp12_set_u(...args: any[]): any;
export function fp12_set_v(...args: any[]): any;
export function fp12_set_w(...args: any[]): any;
export function fp12_set_w_sqr(...args: any[]): any;
export function fp12_set_zero(...args: any[]): any;
export function fp12_sqr(...args: any[]): any;
export function fp12_sub(...args: any[]): any;
export function fp12_tri(...args: any[]): any;
export function fp2_add(...args: any[]): any;
export function fp2_conjugate(...args: any[]): any;
export function fp2_copy(...args: any[]): any;
export function fp2_dbl(...args: any[]): any;
export function fp2_div(...args: any[]): any;
export function fp2_div2(...args: any[]): any;
export function fp2_equ(...args: any[]): any;
export function fp2_frobenius(...args: any[]): any;
export function fp2_from_hex(...args: any[]): any;
export function fp2_inv(...args: any[]): any;
export function fp2_is_one(...args: any[]): any;
export function fp2_is_zero(...args: any[]): any;
export function fp2_mul(...args: any[]): any;
export function fp2_mul_fp(...args: any[]): any;
export function fp2_mul_u(...args: any[]): any;
export function fp2_neg(...args: any[]): any;
export function fp2_new(...args: any[]): any;
export function fp2_set(...args: any[]): any;
export function fp2_set_5u(...args: any[]): any;
export function fp2_set_bn(...args: any[]): any;
export function fp2_set_hex(...args: any[]): any;
export function fp2_set_one(...args: any[]): any;
export function fp2_set_u(...args: any[]): any;
export function fp2_set_zero(...args: any[]): any;
export function fp2_sqr(...args: any[]): any;
export function fp2_sqr_u(...args: any[]): any;
export function fp2_sub(...args: any[]): any;
export function fp2_tri(...args: any[]): any;
export function fp4_add(...args: any[]): any;
export function fp4_conjugate(...args: any[]): any;
export function fp4_copy(...args: any[]): any;
export function fp4_dbl(...args: any[]): any;
export function fp4_equ(...args: any[]): any;
export function fp4_frobenius(...args: any[]): any;
export function fp4_frobenius2(...args: any[]): any;
export function fp4_frobenius3(...args: any[]): any;
export function fp4_from_hex(...args: any[]): any;
export function fp4_inv(...args: any[]): any;
export function fp4_is_one(...args: any[]): any;
export function fp4_is_zero(...args: any[]): any;
export function fp4_mul(...args: any[]): any;
export function fp4_mul_fp(...args: any[]): any;
export function fp4_mul_fp2(...args: any[]): any;
export function fp4_mul_v(...args: any[]): any;
export function fp4_neg(...args: any[]): any;
export function fp4_new(...args: any[]): any;
export function fp4_set(...args: any[]): any;
export function fp4_set_bn(...args: any[]): any;
export function fp4_set_fp2(...args: any[]): any;
export function fp4_set_hex(...args: any[]): any;
export function fp4_set_one(...args: any[]): any;
export function fp4_set_u(...args: any[]): any;
export function fp4_set_v(...args: any[]): any;
export function fp4_set_zero(...args: any[]): any;
export function fp4_sqr(...args: any[]): any;
export function fp4_sqr_v(...args: any[]): any;
export function fp4_sub(...args: any[]): any;
export function fp_add(...args: any[]): any;
export function fp_dbl(...args: any[]): any;
export function fp_div2(...args: any[]): any;
export function fp_equ(...args: any[]): any;
export function fp_from_hex(...args: any[]): any;
export function fp_inv(...args: any[]): any;
export function fp_is_one(...args: any[]): any;
export function fp_is_zero(...args: any[]): any;
export function fp_mul(...args: any[]): any;
export function fp_neg(...args: any[]): any;
export function fp_new(...args: any[]): any;
export function fp_one(...args: any[]): any;
export function fp_sqr(...args: any[]): any;
export function fp_sub(...args: any[]): any;
export function fp_tri(...args: any[]): any;
export function fp_zero(...args: any[]): any;
/** Upstream's own load-time check, exported instead of self-invoked. */
export function pairing_test(): void;
export function point_add(...args: any[]): any;
export function point_copy(...args: any[]): any;
export function point_double(...args: any[]): any;
export function point_equ(...args: any[]): any;
export function point_from_hex(...args: any[]): any;
export function point_get_affine(...args: any[]): any;
export function point_is_at_infinity(...args: any[]): any;
export function point_is_on_curve(...args: any[]): any;
export function point_mul(...args: any[]): any;
export function point_mul_G(...args: any[]): any;
export function point_neg(...args: any[]): any;
export function point_new(...args: any[]): any;
export function point_set_hex(...args: any[]): any;
export function point_set_infinity(...args: any[]): any;
export function point_sub(...args: any[]): any;
export function sm9_pairing(...args: any[]): any;
export function twist_point_add(...args: any[]): any;
export function twist_point_add_full(...args: any[]): any;
export function twist_point_copy(...args: any[]): any;
export function twist_point_double(...args: any[]): any;
export function twist_point_equ(...args: any[]): any;
export function twist_point_from_hex(...args: any[]): any;
export function twist_point_get_affine(...args: any[]): any;
export function twist_point_is_at_infinity(...args: any[]): any;
export function twist_point_is_on_curve(...args: any[]): any;
export function twist_point_mul(...args: any[]): any;
export function twist_point_mul_G(...args: any[]): any;
export function twist_point_neg(...args: any[]): any;
export function twist_point_neg_pi2(...args: any[]): any;
export function twist_point_new(...args: any[]): any;
export function twist_point_pi1(...args: any[]): any;
export function twist_point_pi2(...args: any[]): any;
export function twist_point_set_hex(...args: any[]): any;
export function twist_point_set_infinity(...args: any[]): any;
export function twist_point_sub(...args: any[]): any;
