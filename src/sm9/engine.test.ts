/**
 * The vendored GmSSL-JS engine, checked at the seam where this lab meets it.
 *
 * Three separate jobs, and they are separate on purpose:
 *
 *  1. The engine's own self-check passes. Upstream wrote `pairing_test()` to
 *     LOG its verdict, so a caller who trusts the return value gets `undefined`
 *     every time — pass and fail alike. This file reads the log.
 *  2. The engine's constants are the constants src/sm9/params.ts read out of
 *     GM/T 0044.5. Two independent transcriptions of the same standard; if they
 *     disagree, one of them is a typo and the pairing would still "work".
 *  3. The three engine hazards are pinned by EXECUTING them, not by comment.
 *     A hazard described in prose is a hazard until someone edits the prose out.
 *     A hazard with a failing test beside it is a hazard that cannot come back
 *     unnoticed.
 */
import { describe, it, expect, vi } from 'vitest';
import {
  SM9_N,
  SM9_P,
  SM9_P1,
  SM9_P2,
  SM9_Ppubs,
  fp12_equ,
  fp12_is_one,
  fp12_new,
  fp12_pow,
  pairing_test,
  point_get_affine,
  point_mul,
  point_new,
  sm9_pairing,
  twist_point_get_affine,
  twist_point_is_on_curve,
  twist_point_mul,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';
import { N, P1, P2, Q, TRACE } from './params';
import { pairing, toAffineG1, toAffineG2, type G1Point, type G2Point } from './pairing';
import annexA from './fixtures/annexA-fixture.json';

/** The engine's own generators, typed at the boundary. The .d.ts leaves these
 *  `unknown` deliberately, so every use states the shape it is assuming. */
const P1_E = SM9_P1 as G1Point;
const P2_E = SM9_P2 as G2Point;
const PPUBS_E = SM9_Ppubs as G2Point;

/** A scalar with no special structure, used as the multiplier throughout. */
const K = 0x1234567890abcdefn;

describe("the engine's own self-check", () => {
  /**
   * `pairing_test()` recomputes e(P1, Ppub-s) and compares it to twelve pinned
   * Fp12 components. It then prints the verdict with console.log and returns
   * nothing, which is how a self-check becomes decorative: `if (pairing_test())`
   * is false whether the pairing is right or wrong.
   */
  it('returns undefined, which is why the log is what has to be read', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    try {
      expect(pairing_test()).toBeUndefined();
    } finally {
      spy.mockRestore();
    }
  });

  it('reports true', () => {
    const spy = vi.spyOn(console, 'log').mockImplementation(() => {});
    let calls: unknown[][];
    try {
      pairing_test();
      calls = spy.mock.calls.map((c) => [...c]);
    } finally {
      spy.mockRestore();
    }
    expect(calls).toHaveLength(1);
    const verdict = calls[0][calls[0].length - 1];
    // Boolean true, not truthy: `fp12_equ` returns a boolean, and a string or an
    // object here would mean the self-check changed shape under us.
    expect(verdict).toBe(true);
  });
});

describe('the engine transcribed the same standard params.ts did', () => {
  it('SM9_P is params.Q', () => {
    expect(SM9_P).toBe(Q);
  });

  it('SM9_N is params.N', () => {
    expect(SM9_N).toBe(N);
  });

  it('q - N = tr - 1, so the two constants are consistent in the engine too', () => {
    expect(SM9_P - SM9_N).toBe(TRACE - 1n);
  });

  it('SM9_P1 is params.P1, in affine form', () => {
    expect(P1_E.X).toBe(P1.x);
    expect(P1_E.Y).toBe(P1.y);
    expect(P1_E.Z).toBe(1n);
  });

  it('SM9_P2 is params.P2 — and the Fp2 component order is pinned by the curve, not by a convention', () => {
    // HAZARD 2 at its smallest. GM/T 0044.5 prints x_P2 as a pair whose FIRST
    // printed component is 85ae...; the engine stores that component at index 1.
    // params.ts calls the components `hi` and `lo`, and `hi` is the one the
    // standard prints SECOND, i.e. engine index 0. Nothing about the names says
    // that, so the test establishes it by arithmetic instead: with the two
    // components in this order P2 lies on the twist, and swapped it does not.
    expect(P2_E.X[0]).toBe(P2.x.hi);
    expect(P2_E.X[1]).toBe(P2.x.lo);
    expect(P2_E.Y[0]).toBe(P2.y.hi);
    expect(P2_E.Y[1]).toBe(P2.y.lo);
    expect(P2_E.Z).toEqual([1n, 0n]);

    expect(twist_point_is_on_curve(P2_E)).toBe(true);
    const swapped: G2Point = {
      X: [P2_E.X[1], P2_E.X[0]],
      Y: [P2_E.Y[1], P2_E.Y[0]],
      Z: [1n, 0n],
    };
    expect(twist_point_is_on_curve(swapped)).toBe(false);
  });

  it("SM9_Ppubs is Annex A's master signature public key, same order", () => {
    // The fixture stores the annex's printed order; the engine stores the
    // reverse. Reading one off the other is the check.
    const x = annexA.signature.Ppubs.x;
    const y = annexA.signature.Ppubs.y;
    expect(PPUBS_E.X[0]).toBe(BigInt('0x' + x[1]));
    expect(PPUBS_E.X[1]).toBe(BigInt('0x' + x[0]));
    expect(PPUBS_E.Y[0]).toBe(BigInt('0x' + y[1]));
    expect(PPUBS_E.Y[1]).toBe(BigInt('0x' + y[0]));
    expect(twist_point_is_on_curve(PPUBS_E)).toBe(true);
  });
});

describe('HAZARD 1 — the affine precondition, executed', () => {
  /**
   * `point_mul` and `twist_point_mul` return Jacobian points. `sm9_pairing`
   * reads both of its arguments as though Z were 1 and never divides through.
   * Composing the two without normalising returns a well-formed Fp12 element
   * that is simply the wrong one: no throw, no NaN, nothing to notice.
   *
   * The reference value below is not the engine's own affine answer — that
   * would only prove the engine agrees with itself. It is g^k, computed from
   * g = e(P2, P1) by exponentiation, which is what bilinearity says
   * e(P2, [k]P1) must equal.
   */
  const g = fp12_new();
  sm9_pairing(g, P2_E, P1_E);

  it('point_mul really does return a point with Z != 1', () => {
    const kP = point_new();
    point_mul(kP, K, P1_E);
    expect((kP as G1Point).Z).not.toBe(1n);
    expect((kP as G1Point).Z).not.toBe(0n);
  });

  it('the raw engine gives a DIFFERENT answer for a projective G1 argument', () => {
    const kP = point_new();
    point_mul(kP, K, P1_E);
    const kPa = point_new();
    point_get_affine(kPa, kP);

    const fromProjective = fp12_new();
    sm9_pairing(fromProjective, P2_E, kP);
    const fromAffine = fp12_new();
    sm9_pairing(fromAffine, P2_E, kPa);

    expect(fp12_equ(fromProjective, fromAffine)).toBe(false);

    // And it is the affine one that is right, judged against bilinearity.
    const gk = fp12_new();
    fp12_pow(gk, g, K);
    expect(fp12_equ(fromAffine, gk)).toBe(true);
    expect(fp12_equ(fromProjective, gk)).toBe(false);
  });

  it('the same is true on the G2 side', () => {
    const kQ = twist_point_new();
    twist_point_mul(kQ, K, P2_E);
    expect((kQ as G2Point).Z).not.toEqual([1n, 0n]);

    const kQa = twist_point_new();
    twist_point_get_affine(kQa, kQ);

    const fromProjective = fp12_new();
    sm9_pairing(fromProjective, kQ, P1_E);
    const fromAffine = fp12_new();
    sm9_pairing(fromAffine, kQa, P1_E);

    expect(fp12_equ(fromProjective, fromAffine)).toBe(false);

    const gk = fp12_new();
    fp12_pow(gk, g, K);
    expect(fp12_equ(fromAffine, gk)).toBe(true);
    expect(fp12_equ(fromProjective, gk)).toBe(false);
  });

  it('pairing.ts gives the right answer either way — that is the whole point of the wrapper', () => {
    const gk = fp12_new();
    fp12_pow(gk, g, K);

    const kP = point_new();
    point_mul(kP, K, P1_E);
    const kPa = toAffineG1(kP as G1Point);

    expect(fp12_equ(pairing(P2_E, kP as G1Point), gk)).toBe(true);
    expect(fp12_equ(pairing(P2_E, kPa), gk)).toBe(true);

    const kQ = twist_point_new();
    twist_point_mul(kQ, K, P2_E);
    const kQa = toAffineG2(kQ as G2Point);

    expect(fp12_equ(pairing(kQ as G2Point, P1_E), gk)).toBe(true);
    expect(fp12_equ(pairing(kQa, P1_E), gk)).toBe(true);
  });

  it('normalising is idempotent, so the wrapper is safe on an already-affine point', () => {
    const once = toAffineG1(P1_E);
    const twice = toAffineG1(once);
    expect(twice.X).toBe(P1_E.X);
    expect(twice.Y).toBe(P1_E.Y);
    expect(twice.Z).toBe(1n);
  });
});

describe('HAZARD 3 — fp12_pow reduces its exponent mod q, not mod N', () => {
  /**
   * The engine opens `fp12_pow` with `k %= SM9_P`. GT has order N, so the
   * mathematically correct reduction is mod N, and q > N: the two differ by
   * tr - 1, a 128-bit number. Any exponent at or above N therefore risks a
   * wrong answer, and the failure is silent.
   *
   * Every exponent SM9 itself uses is a scalar already reduced into [1, N-1],
   * so the protocol layer is safe as long as it stays that way. This test is
   * what makes "as long as it stays that way" checkable.
   */
  const g = fp12_new();
  sm9_pairing(g, P2_E, P1_E);

  it('g has order N, so mod-N is the correct reduction for an exponent', () => {
    const gN = fp12_new();
    fp12_pow(gN, g, N);
    expect(fp12_is_one(gN)).toBe(true);
    expect(fp12_is_one(g)).toBe(false);
  });

  it('g^(q+3) comes back as g^3, which is wrong, and the correct value differs', () => {
    const viaEngine = fp12_new();
    fp12_pow(viaEngine, g, Q + 3n);

    const gCubed = fp12_new();
    fp12_pow(gCubed, g, 3n);

    // What the engine does: q + 3 reduced mod q is 3.
    expect(fp12_equ(viaEngine, gCubed)).toBe(true);

    // What it should do: q + 3 reduced mod N is q - N + 3 = tr + 2, and g to
    // that power is a different element.
    const correctExponent = (Q + 3n) % N;
    expect(correctExponent).toBe(TRACE + 2n);
    const correct = fp12_new();
    fp12_pow(correct, g, correctExponent);
    expect(fp12_equ(viaEngine, correct)).toBe(false);
  });

  it('an exponent already in [1, N-1] is untouched, which is why the protocol layer is safe', () => {
    const e = N - 1n;
    const a = fp12_new();
    fp12_pow(a, g, e);
    // g^(N-1) = g^-1, so multiplying back by g must give one. Checked through
    // the order relation rather than through fp12_inv, which is a second code
    // path that could share a bug with pow.
    const b = fp12_new();
    fp12_pow(b, a, N - 1n);
    // (g^(N-1))^(N-1) = g^((N-1)^2) = g^(N^2 - 2N + 1) = g^1.
    expect(fp12_equ(b, g)).toBe(true);
  });
});
