/**
 * The R-ate pairing, tested for the properties that make it a pairing.
 *
 * These are structural tests, not vector tests: bilinearity, non-degeneracy and
 * the order of GT hold for every input, so they catch a class of error that a
 * single known-answer pair cannot. A pairing that is subtly wrong — the wrong
 * twist, a dropped Frobenius, a final exponentiation off by a factor — usually
 * still returns a deterministic Fp12 element, and usually still agrees with
 * itself; what it stops doing is respecting e([a]Q, [b]P) = e(Q, P)^(ab).
 *
 * Two of them come with a second reading, against GM/T 0044.5 Annex A:
 * Ppub-s = [ks]P2 is printed there with ks, so e(Ppub-s, P1) must be g^ks, and
 * the annex prints g itself. That ties the abstract properties to the standard.
 *
 * Every point here goes through pairing() rather than the raw engine, which is
 * the arrangement src/sm9/engine.test.ts justifies by breaking it.
 */
import { describe, it, expect } from 'vitest';
import {
  SM9_P1,
  SM9_P2,
  SM9_Ppubs,
  fp12_equ,
  fp12_is_one,
  fp12_mul,
  fp12_new,
  fp12_pow,
  point_mul,
  point_new,
  twist_point_mul,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';
import { N } from './params';
import { mod, mul } from './fn';
import { pairing, toAffineG1, toAffineG2, type G1Point, type G2Point } from './pairing';
import annexA from './fixtures/annexA-fixture.json';

const P1_E = SM9_P1 as G1Point;
const P2_E = SM9_P2 as G2Point;
const PPUBS_E = SM9_Ppubs as G2Point;

/** g = e(P2, P1), the generator of GT that every SM9 protocol starts from. */
const g = pairing(P2_E, P1_E);

/**
 * Two scalars with no special structure. Reused from GmSSL's own F_N vectors
 * (sm9test.c hex_x / hex_y) rather than invented, so they are pinned somewhere
 * a reader can check and are known to lie in [1, N-1].
 */
const A = 0x483f336f119053cba8c0e738cabc2bfdbf047caf7e1aaa92526fa48041ceea2bn;
const B = 0x3220b45276e3692a387faa7bf3cd46e390608f2f4298cce467bf2b7fda091edbn;

/** [k]P1, left projective — pairing() is expected to cope. */
function mulG1(k: bigint): G1Point {
  const out = point_new();
  point_mul(out, k, P1_E);
  return out as G1Point;
}

/** [k]P2, left projective. */
function mulG2(k: bigint): G2Point {
  const out = twist_point_new();
  twist_point_mul(out, k, P2_E);
  return out as G2Point;
}

/** g^e in GT. e must already be reduced: see engine.test.ts, HAZARD 3. */
function gPow(base: unknown, e: bigint): unknown {
  const out = fp12_new();
  fp12_pow(out, base, e);
  return out;
}

describe('bilinearity', () => {
  it('e([a]P2, [b]P1) = e(P2, P1)^(ab)', () => {
    const lhs = pairing(mulG2(A), mulG1(B));
    const rhs = gPow(g, mul(A, B));
    expect(fp12_equ(lhs, rhs)).toBe(true);
  });

  it('the exponent has to be reduced mod N for that to hold', () => {
    // a*b is 508 bits here, well past q, so an unreduced exponent would be
    // silently truncated mod q by fp12_pow. This states which reduction is the
    // right one rather than leaving it to luck.
    expect((A * B).toString(2).length).toBeGreaterThan(500);
    expect(mul(A, B)).toBe(mod(A * B));
    expect(mul(A, B)).toBeLessThan(N);
  });

  it('the scalar moves freely between the two arguments', () => {
    // e([a]P2, P1) = e(P2, [a]P1) = g^a. This is the property SM9 leans on
    // hardest: verification moves h from the signature into G2 and the signer
    // put it into G1.
    const inG2 = pairing(mulG2(A), P1_E);
    const inG1 = pairing(P2_E, mulG1(A));
    const direct = gPow(g, A);
    expect(fp12_equ(inG2, inG1)).toBe(true);
    expect(fp12_equ(inG2, direct)).toBe(true);
  });

  it('addition in G1 becomes multiplication in GT', () => {
    // e(P2, [a]P1) * e(P2, [b]P1) = e(P2, [a+b]P1).
    const ea = pairing(P2_E, mulG1(A));
    const eb = pairing(P2_E, mulG1(B));
    const product = fp12_new();
    fp12_mul(product, ea, eb);
    const sum = pairing(P2_E, mulG1(mod(A + B)));
    expect(fp12_equ(product, sum)).toBe(true);
  });

  it('[1]P is the identity case, so the multiplier path and the base case agree', () => {
    expect(fp12_equ(pairing(mulG2(1n), mulG1(1n)), g)).toBe(true);
  });
});

describe('non-degeneracy', () => {
  it('e(P2, P1) is not 1', () => {
    // A degenerate pairing returns 1 for everything and would still satisfy
    // bilinearity, so this is not implied by the tests above.
    expect(fp12_is_one(g)).toBe(false);
  });

  it('and neither is e(Q, P) for a multiplied pair', () => {
    expect(fp12_is_one(pairing(mulG2(A), mulG1(B)))).toBe(false);
    expect(fp12_is_one(pairing(mulG2(N - 1n), P1_E))).toBe(false);
  });
});

describe('the order of GT', () => {
  it('e(P2, P1)^N = 1', () => {
    expect(fp12_is_one(gPow(g, N))).toBe(true);
  });

  it('so g has order exactly N, N being prime and g not being 1', () => {
    // The only divisors of N are 1 and N. g^N = 1 puts the order among them,
    // and g != 1 rules out 1.
    expect(fp12_is_one(g)).toBe(false);
    expect(fp12_is_one(gPow(g, N))).toBe(true);
  });

  it('g^(N-1) is the inverse of g', () => {
    const inverse = gPow(g, N - 1n);
    const product = fp12_new();
    fp12_mul(product, g, inverse);
    expect(fp12_is_one(product)).toBe(true);
  });

  it('[N]P1 pairs to 1 as well, from the other side', () => {
    // [N]P1 is the point at infinity in exact arithmetic, but the engine's
    // pairing cannot read a Z = 0 point, so this goes the long way: N-1 then
    // one more step is equivalent to exponent N in GT.
    expect(fp12_equ(pairing(P2_E, mulG1(mod(N - 1n))), gPow(g, N - 1n))).toBe(true);
  });
});

describe('the wrapper normalises, so a caller cannot get this wrong', () => {
  it('a projective argument and its affine form pair to the same value', () => {
    const projective = mulG1(A);
    const affine = toAffineG1(projective);
    expect(affine.Z).toBe(1n);
    expect(projective.Z).not.toBe(1n);
    expect(fp12_equ(pairing(P2_E, projective), pairing(P2_E, affine))).toBe(true);
  });

  it('the same on the G2 side', () => {
    const projective = mulG2(A);
    const affine = toAffineG2(projective);
    expect(affine.Z).toEqual([1n, 0n]);
    expect(projective.Z).not.toEqual([1n, 0n]);
    expect(fp12_equ(pairing(projective, P1_E), pairing(affine, P1_E))).toBe(true);
  });

  it('normalising does not mutate its argument', () => {
    // toAffineG1 writes into a fresh point. If it aliased, the second pairing
    // in the tests above would be comparing a value with itself.
    const projective = mulG1(B);
    const before = { X: projective.X, Y: projective.Y, Z: projective.Z };
    toAffineG1(projective);
    expect(projective.X).toBe(before.X);
    expect(projective.Y).toBe(before.Y);
    expect(projective.Z).toBe(before.Z);
  });
});

describe('read against GM/T 0044.5 Annex A', () => {
  /**
   * The annex prints an Fp12 element as twelve components in the reverse of the
   * engine's flattened order — HAZARD 2 at full width. The flattening is
   * x[i][j][k] for i = 0..2, j = 0..1, k = 0..1, and the annex's printed order
   * is that list reversed.
   */
  function fp12ToAnnexHex(x: unknown): string[] {
    const t = x as bigint[][][];
    const flat = [
      t[0][0][0], t[0][0][1], t[0][1][0], t[0][1][1],
      t[1][0][0], t[1][0][1], t[1][1][0], t[1][1][1],
      t[2][0][0], t[2][0][1], t[2][1][0], t[2][1][1],
    ];
    return flat.map((v) => v.toString(16).padStart(64, '0')).reverse();
  }

  it("e(P1, Ppub-s) reproduces the annex's twelve printed components of g", () => {
    // The annex writes g = e(P1, Ppub-s) with G1 first; the engine and this
    // wrapper take G2 first, so the call is pairing(Ppubs, P1).
    const gAnnex = pairing(PPUBS_E, P1_E);
    expect(fp12ToAnnexHex(gAnnex)).toEqual(annexA.signature.g);
    expect(annexA.signature.g).toHaveLength(12);
  });

  it('Ppub-s = [ks]P2, so e(Ppub-s, P1) = g^ks — bilinearity, read off the standard', () => {
    const ks = BigInt('0x' + annexA.signature.ks);
    expect(ks).toBeGreaterThan(0n);
    expect(ks).toBeLessThan(N);

    // Ppub-s derived from the master secret, rather than taken from the engine.
    const derived = mulG2(ks);
    expect(fp12_equ(pairing(derived, P1_E), pairing(PPUBS_E, P1_E))).toBe(true);

    // And that same value is g^ks.
    expect(fp12_equ(pairing(PPUBS_E, P1_E), gPow(g, ks))).toBe(true);
  });
});
