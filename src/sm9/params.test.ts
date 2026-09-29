/**
 * The SM9 system parameters, RE-DERIVED rather than restated.
 *
 * A test that asserts `Q === Q` passes on a typo. GM/T 0044.5 clause 3.1 prints
 * the defining polynomials as well as the values, so this file recomputes q, N
 * and the trace from the single curve parameter t and compares. Every constant
 * below that can be derived is derived; the ones that cannot (b, cf, k, cid,
 * eid, the generators) are checked against the properties they must have
 * instead of against themselves.
 *
 * The arithmetic here is deliberately self-contained: no import from fn.ts,
 * which works mod N and would beg the question, and no import from the vendored
 * engine, which is a second implementation of the same numbers and belongs in
 * src/sm9/engine.test.ts.
 */
import { describe, it, expect } from 'vitest';
import {
  T,
  Q,
  N,
  TRACE,
  B,
  COFACTOR,
  EMBEDDING_DEGREE,
  BETA,
  CID,
  EID,
  P1,
  HID,
} from './params';

/** a^e mod m. Local to this file so the test does not lean on fn.ts. */
function modPow(a: bigint, e: bigint, m: bigint): bigint {
  let result = 1n;
  let base = ((a % m) + m) % m;
  let exp = e;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

/**
 * The Legendre symbol (a/q) for the odd prime q, as +1, -1 or 0.
 *
 * Euler's criterion: a^((q-1)/2) is 1 for a residue and q-1 for a non-residue.
 */
function legendre(a: bigint, q: bigint): number {
  const r = modPow(((a % q) + q) % q, (q - 1n) / 2n, q);
  if (r === 0n) return 0;
  return r === 1n ? 1 : -1;
}

describe('GM/T 0044.5 clause 3.1 — the curve is re-derived from t', () => {
  it('q = 36t^4 + 36t^3 + 24t^2 + 6t + 1', () => {
    const q = 36n * T ** 4n + 36n * T ** 3n + 24n * T ** 2n + 6n * T + 1n;
    expect(q).toBe(Q);
  });

  it('N = 36t^4 + 36t^3 + 18t^2 + 6t + 1', () => {
    const n = 36n * T ** 4n + 36n * T ** 3n + 18n * T ** 2n + 6n * T + 1n;
    expect(n).toBe(N);
  });

  it('tr(t) = 6t^2 + 1', () => {
    expect(6n * T ** 2n + 1n).toBe(TRACE);
  });

  it('the Hasse relation closes: #E(Fq) = q + 1 - tr(t) = N', () => {
    // This is the one identity that ties all three constants together. Get any
    // single one wrong and it fails, which is why it is worth stating separately
    // from the three polynomial checks above.
    expect(Q + 1n - TRACE).toBe(N);
  });

  it('N is the full curve order, so the cofactor is 1', () => {
    expect(COFACTOR).toBe(1n);
    expect((Q + 1n - TRACE) / COFACTOR).toBe(N);
  });
});

describe('size — what the parameters are worth', () => {
  it('N > 2^191, so the discrete log in G1/G2 is out of reach', () => {
    expect(N).toBeGreaterThan(2n ** 191n);
    // And it is a 256-bit number, not merely a large one.
    expect(N.toString(2).length).toBe(256);
  });

  it('q^12 > 2^1536, so the target group GT is a 3000-bit-class field', () => {
    // k = 12 is what makes the pairing usable AND what sets the cost of the
    // index calculus attack in GT.
    expect(Q ** BigInt(EMBEDDING_DEGREE)).toBeGreaterThan(2n ** 1536n);
    expect(EMBEDDING_DEGREE).toBe(12);
    // 3067, not 3072. q occupies 256 bits but sits well below 2^256 (it opens
    // 0xb64...), so log2(q) is about 255.6 and twelve of them fall five bits
    // short of a round 3072. The round number is the one a reader expects and
    // the one an implementation summary would print; it is not the derived one.
    expect((Q ** 12n).toString(2).length).toBe(3067);
    expect(Q.toString(2).length).toBe(256);
  });
});

describe('the base field — why no generic BN254 library will do', () => {
  /**
   * SM9 builds Fq2 as Fq[u]/(u^2 - beta) with beta = -2. Almost every BN254
   * implementation in circulation hardcodes u^2 = -1, because for THEIR q the
   * value -1 is a non-residue. For SM9's q it is not, and the two Legendre
   * symbols below are the whole reason:
   *
   *   (-1/q) = +1  -> Fq[u]/(u^2 + 1) is NOT a field here; u^2 = -1 has a root
   *                   in Fq, so that quotient ring has zero divisors.
   *   (-2/q) = -1  -> u^2 = -2 has no root, so beta = -2 does give a field.
   *
   * This is an arithmetic fact about q, not a style choice by the committee,
   * and it is why this lab vendors a GmSSL engine rather than adapting a BN254
   * library: swapping the non-residue is not a parameter change, it changes
   * every Fp2 multiplication in the tower.
   */
  it('(-1/q) = +1, so u^2 = -1 does not build a field over Fq', () => {
    expect(legendre(-1n, Q)).toBe(1);
    // Equivalently and more cheaply: q = 1 (mod 4).
    expect(Q % 4n).toBe(1n);
  });

  it('(-2/q) = -1, so beta = -2 does', () => {
    expect(legendre(-2n, Q)).toBe(-1);
    expect(BETA).toBe(-2n);
  });

  it('the two symbols together pin q = 5 (mod 8)', () => {
    // (-2/q) = (-1/q)(2/q). With (-1/q) = +1 the second factor must be -1, and
    // (2/q) = -1 exactly when q = 3 or 5 (mod 8). Only 5 is compatible with
    // q = 1 (mod 4).
    expect(Q % 8n).toBe(5n);
    expect(legendre(2n, Q)).toBe(-1);
  });

  it('q is odd and larger than N, as q + 1 - tr = N with tr > 1 requires', () => {
    expect(Q % 2n).toBe(1n);
    expect(Q).toBeGreaterThan(N);
    expect(TRACE).toBeGreaterThan(1n);
  });
});

describe('the generator P1 of G1', () => {
  it('satisfies y^2 = x^3 + 5 over Fq', () => {
    const lhs = (P1.y * P1.y) % Q;
    const rhs = (((P1.x * P1.x) % Q) * P1.x + B) % Q;
    expect(lhs).toBe(rhs);
    expect(B).toBe(5n);
  });

  it('has both coordinates reduced into [0, q)', () => {
    // A coordinate that happened to exceed q would still satisfy the curve
    // equation after reduction, so this is a separate claim from the one above.
    expect(P1.x).toBeGreaterThanOrEqual(0n);
    expect(P1.x).toBeLessThan(Q);
    expect(P1.y).toBeGreaterThanOrEqual(0n);
    expect(P1.y).toBeLessThan(Q);
  });

  it('is not the point at infinity or a 2-torsion point', () => {
    // y = 0 would mean [2]P1 = O, which cannot hold for a generator of a group
    // of odd prime order N.
    expect(P1.y).not.toBe(0n);
    expect(N % 2n).toBe(1n);
  });
});

describe('the identifier bytes GM/T 0044.1 clause 8.1 assigns', () => {
  it('cid = 0x12 — an ordinary curve (1) with its twist (2)', () => {
    expect(CID).toBe(0x12);
    // The low nibble is why beta is in the parameter set at all: a curve with
    // no twist would carry no beta.
    expect(CID & 0x0f).toBe(2);
    expect(CID >> 4).toBe(1);
  });

  it('eid = 0x04 — the R-ate pairing', () => {
    // 0x01 Tate, 0x02 Weil, 0x03 Ate, 0x04 R-ate.
    expect(EID).toBe(0x04);
  });
});

describe('hid — the one byte the normative text does not pin', () => {
  /**
   * GM/T 0044.2/.3/.4 clause 5.3 each say the KGC "selects" hid and publishes
   * it, so these three values come from GM/T 0044.5's annexes and from GmSSL,
   * not from a normative clause. The test states that provenance as structure:
   * SIGN and ENCRYPT are annex values, EXCHANGE_GMSSL is not in the standard.
   */
  it('each value is a single octet', () => {
    for (const v of Object.values(HID)) {
      expect(Number.isInteger(v)).toBe(true);
      expect(v).toBeGreaterThanOrEqual(0);
      expect(v).toBeLessThanOrEqual(0xff);
    }
  });

  it('Annex A signs with 0x01 and Annexes B/C/D use 0x03', () => {
    expect(HID.SIGN).toBe(0x01);
    expect(HID.ENCRYPT).toBe(0x03);
  });

  it('0x02 is GmSSL’s exchange value and is distinct from both', () => {
    expect(HID.EXCHANGE_GMSSL).toBe(0x02);
    expect(new Set(Object.values(HID)).size).toBe(3);
  });
});
