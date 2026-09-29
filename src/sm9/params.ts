/**
 * SM9 system parameters — GM/T 0044.5-2016 clause 3.1, "System parameters".
 *
 * PROVENANCE. Every value below was read out of the official English text of
 * GM/T 0044.5 fetched directly from the Cryptography Standardization Technical
 * Committee of China at
 *   http://www.gmbz.org.cn/upload/2025-01-23/1737625720708039809.pdf
 * (that host refuses HTTPS; plain HTTP answers 200). The fetched file is
 *   md5 40cee7ca9ab2b885dee2158b2d4a12cc, 1340159 bytes.
 * Nothing here was transcribed from an implementation, a paper, or a summary.
 *
 * The standard states the defining formulas as well as the values, so the
 * constants are re-derived rather than trusted: src/sm9/params.test.ts recomputes
 * q, N and the trace from t and fails if any disagrees.
 */

/** Curve parameter t. Clause 3.1, "the elliptic curve parameters: t". */
export const T = 0x600000000058f98an;

/** Characteristic of the base field, q = 36t^4 + 36t^3 + 24t^2 + 6t + 1. */
export const Q = 0xb640000002a3a6f1d603ab4ff58ec74521f2934b1a7aeedbe56f9b27e351457dn;

/** Order of the group, N = 36t^4 + 36t^3 + 18t^2 + 6t + 1. */
export const N = 0xb640000002a3a6f1d603ab4ff58ec74449f2934b18ea8beee56ee19cd69ecf25n;

/** Trace of Frobenius, tr(t) = 6t^2 + 1. */
export const TRACE = 0xd8000000019062ed0000b98b0cb27659n;

/** Curve equation y^2 = x^3 + b. Clause 3.1, "the equation parameter b: 05". */
export const B = 5n;

/** Cofactor. Clause 3.1, "the cofactor cf: 1" — so N is the full curve order. */
export const COFACTOR = 1n;

/** Embedding degree. Clause 3.1, "the embedding degree k: 12". */
export const EMBEDDING_DEGREE = 12;

/**
 * Twisted-curve parameter beta = -2, which is also the Fp2 non-residue.
 * This is the value that rules out every generic BN254 library: those hardcode
 * u^2 = -1, and q = 1 (mod 4) here, so -1 is a quadratic residue mod q and
 * Fp[u]/(u^2 + 1) is not a field. legendre(-2/q) = -1, so beta = -2 is.
 */
export const BETA = -2n;

/** Curve identifier. Clause 3.1, "the curve identifier cid: 0x12" — GM/T 0044.1
 *  clause 8.1 a)/c): 0x12 = an ordinary curve and its corresponding twist, and the
 *  low nibble 2 is precisely why beta appears in the parameter set at all. */
export const CID = 0x12;

/** Bilinear pairing identifier. Clause 3.1, "eid: 0x04". GM/T 0044.1 clause 8.1 h)
 *  assigns 0x01 Tate, 0x02 Weil, 0x03 Ate, 0x04 R-ate. SM9 is R-ate. */
export const EID = 0x04;

/** Generator P1 of G1, an affine point on E(Fq). */
export const P1 = {
  x: 0x93de051d62bf718ff5ed0704487d01d6e1e4086909dc3280e8c4e4817c66ddddn,
  y: 0x21fe8dda4f21e607631065125c395bbc1c1c00cbfa6024350c464cd70a3ea616n,
} as const;

/** Generator P2 of G2, an affine point on the twist E'(Fq2). Each coordinate is
 *  an Fq2 element, printed by the standard as (high, low). */
export const P2 = {
  x: {
    hi: 0x3722755292130b08d2aab97fd34ec120ee265948d19c17abf9b7213baf82d65bn,
    lo: 0x85aef3d078640c98597b6027b441a01ff1dd2c190f5e93c454806c11d8806141n,
  },
  y: {
    hi: 0xa7cf28d519be3da65f3170153d278ff247efba98a71a08116215bba5c999a7c7n,
    lo: 0x17509b092e845c1266ba0d262cbee6ed0736a96fa347c8bd856dc76b84ebeb96n,
  },
} as const;

/**
 * The private-key generating function identifier.
 *
 * GM/T 0044.2/.3/.4 clause 5.3 all say the KGC "selects a one-byte ... identifier
 * hid and makes it public" — the NORMATIVE text pins no value. What is pinned is
 * in GM/T 0044.5's informative annexes, which are the conformance vectors:
 * Annex A (signature) declares 0x01, and Annexes B, C and D (key exchange, KEM,
 * encryption) all declare 0x03.
 *
 * SIGN and ENCRYPT below are those annex values. EXCHANGE_GMSSL is NOT in the
 * standard at all: GmSSL, emmansun/gmsm and Bouncy Castle use 0x02 for key
 * exchange and reach a different session key from the same master key. Both are
 * shipped because the divergence is an exhibit, not a bug to pick a side in.
 * See src/sm9/exchange.ts and the "hid" panel.
 */
export const HID = {
  /** GM/T 0044.5 Annex A. */
  SIGN: 0x01,
  /** NOT in GM/T 0044 — GmSSL's SM9_HID_EXCH, used by GmSSL and emmansun/gmsm. */
  EXCHANGE_GMSSL: 0x02,
  /** GM/T 0044.5 Annexes B, C and D — including key exchange. */
  ENCRYPT: 0x03,
} as const;
