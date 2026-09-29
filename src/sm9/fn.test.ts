/**
 * Known-answer tests for F_N arithmetic, taken from GmSSL C's own test suite.
 *
 * SOURCE. `test_sm9_z256_fn()` in GmSSL's `tests/sm9test.c` — a local copy of
 * that file is the one these were read out of. The two operands are `hex_x` and
 * `hex_y` at lines 206-207 and the six expected results are `hex_fn_add`,
 * `hex_fn_sub`, `hex_fn_nsub`, `hex_fn_mul`, `hex_fn_pow` and `hex_fn_inv` at
 * lines 208-213; lines 225-230 are the calls that pair each expectation with
 * its operation, and the pairing below follows those lines rather than the
 * order the #defines happen to appear in.
 *
 * Using GmSSL's vectors rather than the standard's is deliberate. GM/T 0044.5's
 * annexes print scalar sub-values (t1, t2, l, h) but they are all products of
 * the protocol, so a bug in F_N and a bug in the protocol layer above it would
 * arrive together and could cancel. These six exercise mod-N addition,
 * subtraction in both directions, multiplication, exponentiation and inversion
 * with nothing else in the path.
 *
 * BYTE ORDER, derived rather than assumed. GmSSL's `sm9_z256_t` is an array of
 * four 64-bit limbs, so a 64-nibble string could plausibly be read
 * most-significant-limb-first or least-significant-limb-first, and the two
 * readings give different integers. Which one is right is settled below by
 * running both: the first reproduces all six vectors, the second reproduces
 * none. See "the hex convention is the plain big-endian one" at the end.
 */
import { describe, it, expect } from 'vitest';
import { N } from './params';
import { mod, add, sub, mul, pow, inv, isValidScalar } from './fn';

/** sm9test.c line 206 — the first operand of every vector below. */
const HEX_X = '483f336f119053cba8c0e738cabc2bfdbf047caf7e1aaa92526fa48041ceea2b';
/** sm9test.c line 207 — the second. */
const HEX_Y = '3220b45276e3692a387faa7bf3cd46e390608f2f4298cce467bf2b7fda091edb';

/** sm9test.c lines 208-213, paired with the calls at lines 225-230. */
const VECTORS = {
  add: '7a5fe7c18873bcf5e14091b4be8972e14f650bdec0b37776ba2ed0001bd80906',
  sub: '161e7f1c9aaceaa170413cbcd6eee51a2ea3ed803b81ddadeab0790067c5cb50',
  nsub: 'a02180e367f6bc5065c26e931e9fe22a1b4ea5cadd68ae40fabe689c6ed903d5',
  mul: '25c528484b65755b1ff57b47b77f2b32e20467be1dde566ede4264b2e092d223',
  pow: '445cb9b76f27e9d03a2c30fbabb59b0ea6d7b06259b0c8a1b30f21b9b274a055',
  inv: '3e3e849c2144c3596d9c79cb1f8ee7c60828787e298b06cc341a9a165191bc5e',
} as const;

const X = BigInt('0x' + HEX_X);
const Y = BigInt('0x' + HEX_Y);

/** Render a scalar the way GmSSL prints one: 64 nibbles, left-padded. */
function hex64(a: bigint): string {
  return a.toString(16).padStart(64, '0');
}

describe('GmSSL sm9test.c known-answer vectors for F_N', () => {
  it('the operands are in range, so every vector below is about F_N and not about reduction', () => {
    expect(isValidScalar(X)).toBe(true);
    expect(isValidScalar(Y)).toBe(true);
    // x > y, which is why sub and nsub are different vectors rather than
    // negations of one another: one wraps and the other does not.
    expect(X).toBeGreaterThan(Y);
  });

  it('hex_fn_add: x + y mod N', () => {
    expect(hex64(add(X, Y))).toBe(VECTORS.add);
  });

  it('hex_fn_sub: x - y mod N (no wrap, since x > y)', () => {
    expect(hex64(sub(X, Y))).toBe(VECTORS.sub);
    // The plain integer difference already lies in [0, N), so this vector says
    // nothing about the lift. hex_fn_nsub is the one that does.
    expect(X - Y).toBe(sub(X, Y));
  });

  it('hex_fn_nsub: y - x mod N, the wrapping direction', () => {
    expect(hex64(sub(Y, X))).toBe(VECTORS.nsub);
    // A negative intermediate is lifted into [0, N) rather than returned as a
    // negative bigint, which is what `mod` exists for.
    expect(Y - X).toBeLessThan(0n);
    expect(sub(Y, X)).toBeGreaterThan(0n);
    expect(sub(Y, X)).toBe(Y - X + N);
  });

  it('hex_fn_mul: x * y mod N', () => {
    expect(hex64(mul(X, Y))).toBe(VECTORS.mul);
  });

  it('hex_fn_pow: x^y mod N, with the full 256-bit y as the exponent', () => {
    expect(hex64(pow(X, Y))).toBe(VECTORS.pow);
    // Worth stating because the vendored engine's fp12_pow does NOT do this:
    // it reduces its exponent mod the field characteristic before it starts.
    // fn.pow takes the exponent as given, so the caller keeps the range check.
    // The exponent here is a full-width scalar (254 bits), not a small one, so
    // this vector really does exercise the whole square-and-multiply ladder.
    expect(Y.toString(2).length).toBe(254);
    expect(Y).toBeLessThan(N);
  });

  it('hex_fn_inv: x^-1 mod N', () => {
    expect(hex64(inv(X))).toBe(VECTORS.inv);
  });

  it('the inverse vector is consistent with the multiplication vector', () => {
    // Independent of both expectations: whatever inv returns, multiplying by it
    // must give 1. This catches an inv that agrees with a mistyped vector.
    expect(mul(X, inv(X))).toBe(1n);
    expect(mul(Y, inv(Y))).toBe(1n);
  });
});

describe('the hex convention is the plain big-endian one', () => {
  /**
   * GmSSL stores a scalar as four 64-bit limbs. Reading the 64-nibble string
   * limb-reversed is the plausible alternative, and it is wrong: it reproduces
   * none of the six. This test is the derivation, not a restatement of it.
   */
  function limbReversed(hex: string): bigint {
    const limbs = hex.match(/.{16}/g);
    if (!limbs) throw new Error('expected 64 nibbles');
    return BigInt('0x' + limbs.reverse().join(''));
  }

  it('the big-endian reading reproduces the add vector and the limb-reversed one does not', () => {
    expect(hex64(add(X, Y))).toBe(VECTORS.add);

    const xr = limbReversed(HEX_X);
    const yr = limbReversed(HEX_Y);
    expect(xr).not.toBe(X);
    expect(hex64(add(xr, yr))).not.toBe(VECTORS.add);
    expect(hex64(add(xr, yr))).not.toBe(limbReversed(VECTORS.add));
  });

  it('and does not reproduce the multiplication or inversion vectors either', () => {
    const xr = limbReversed(HEX_X);
    const yr = limbReversed(HEX_Y);
    expect(hex64(mul(xr, yr))).not.toBe(VECTORS.mul);
    expect(hex64(inv(xr))).not.toBe(VECTORS.inv);
  });
});

describe('inv refuses rather than returning a wrong value', () => {
  /**
   * The two places SM9 can reach a non-invertible scalar are both in the
   * standard: extraction must detect t1 = 0 and re-key (GM/T 0044.2 clause
   * 5.3), and the reused-nonce recovery in src/attack/nonce-reuse.ts has no
   * inverse when the two message hashes coincide. Returning 0, or N, or
   * anything at all in those cases would turn a detectable condition into a
   * wrong key.
   */
  it('inv(0) throws', () => {
    expect(() => inv(0n)).toThrow(RangeError);
  });

  it('inv(N) throws, because N reduces to 0', () => {
    expect(mod(N)).toBe(0n);
    expect(() => inv(N)).toThrow(RangeError);
  });

  it('inv(-N) and inv(2N) throw for the same reason', () => {
    expect(() => inv(-N)).toThrow(RangeError);
    expect(() => inv(2n * N)).toThrow(RangeError);
  });

  it('inv(1) and inv(N - 1) are the fixed points and do not throw', () => {
    expect(inv(1n)).toBe(1n);
    // N - 1 = -1 mod N, and (-1)^-1 = -1.
    expect(inv(N - 1n)).toBe(N - 1n);
  });
});

describe('reduction, and the boundaries isValidScalar draws', () => {
  it('mod lifts negatives into [0, N)', () => {
    expect(mod(-1n)).toBe(N - 1n);
    expect(mod(-N)).toBe(0n);
    expect(mod(-N - 1n)).toBe(N - 1n);
  });

  it('mod is idempotent', () => {
    const r = mod(X * Y);
    expect(mod(r)).toBe(r);
  });

  it('a valid secret scalar is in [1, N-1] — both ends excluded correctly', () => {
    expect(isValidScalar(0n)).toBe(false);
    expect(isValidScalar(1n)).toBe(true);
    expect(isValidScalar(N - 1n)).toBe(true);
    expect(isValidScalar(N)).toBe(false);
    expect(isValidScalar(-1n)).toBe(false);
  });

  it('pow(x, 0) = 1 and pow(x, 1) = x', () => {
    expect(pow(X, 0n)).toBe(1n);
    expect(pow(X, 1n)).toBe(mod(X));
  });

  it('pow refuses a negative exponent rather than guessing at an inverse', () => {
    expect(() => pow(X, -1n)).toThrow(RangeError);
  });

  it("Fermat holds for both operands, so N behaves as the prime order it is declared to be", () => {
    expect(pow(X, N - 1n)).toBe(1n);
    expect(pow(Y, N - 1n)).toBe(1n);
    // And inversion agrees with the Fermat route, though fn.inv uses extended
    // Euclid: two different algorithms, one answer.
    expect(pow(X, N - 2n)).toBe(inv(X));
  });
});
