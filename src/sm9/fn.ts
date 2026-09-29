/**
 * Arithmetic in F_N, the scalar field of SM9's group.
 *
 * The vendored GmSSL-JS engine has NO mod-N arithmetic anywhere in its 1580
 * lines — it is entirely Fp, Fp2, Fp4, Fp12 and the two curve groups. Every
 * scalar operation SM9's protocols need (the t1 = H1 + ks sum, the t1^-1 that
 * makes extraction an inversion, the l = r - h subtraction in signing, and the
 * (h2 - h1)^-1 in the reused-nonce recovery) lives here instead.
 *
 * GmSSL C's own hex_fn_* vectors are the known-answer tests for this file; see
 * src/sm9/fn.test.ts.
 */
import { N } from './params';

/** Reduce into [0, N). Negative inputs are lifted, so `mod(-1n)` is N-1. */
export function mod(a: bigint): bigint {
  const r = a % N;
  return r >= 0n ? r : r + N;
}

export function add(a: bigint, b: bigint): bigint {
  return mod(a + b);
}

export function sub(a: bigint, b: bigint): bigint {
  return mod(a - b);
}

export function mul(a: bigint, b: bigint): bigint {
  return mod(a * b);
}

export function pow(base: bigint, exp: bigint): bigint {
  if (exp < 0n) throw new RangeError('fn.pow: negative exponent');
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = mod(result * b);
    b = mod(b * b);
    e >>= 1n;
  }
  return result;
}

/**
 * Multiplicative inverse mod N.
 *
 * Throws on a non-invertible input rather than returning a wrong value. That
 * matters twice in SM9 and both times the standard has something to say about
 * it: extraction must detect t1 = 0 and re-key (GM/T 0044.2 clause 5.3), and the
 * reused-nonce recovery has no inverse when the two hashes coincide, because
 * then there are not two independent equations.
 */
export function inv(a: bigint): bigint {
  const x = mod(a);
  if (x === 0n) throw new RangeError('fn.inv: 0 has no inverse mod N');
  // Extended Euclid rather than Fermat: it is exact, and it is the algorithm the
  // standard's own description implies.
  let [oldR, r] = [x, N];
  let [oldS, s] = [1n, 0n];
  while (r !== 0n) {
    const q = oldR / r;
    [oldR, r] = [r, oldR - q * r];
    [oldS, s] = [s, oldS - q * s];
  }
  if (oldR !== 1n) throw new RangeError('fn.inv: not invertible mod N');
  return mod(oldS);
}

/** Is this a valid secret scalar, i.e. in [1, N-1]? */
export function isValidScalar(a: bigint): boolean {
  return a >= 1n && a <= N - 1n;
}
