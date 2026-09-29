/**
 * Known-answer tests for SM9 key exchange — GM/T 0044.3-2016 clause 6.1.
 *
 * WHAT IS BEING COMPARED AGAINST WHAT. Every expected value in the first block comes
 * out of src/sm9/fixtures/sm9-keyexchange-vectors.json, whose `annex_b_published`
 * section was extracted from the official GM/T 0044.5-2016 text BY LINE NUMBER rather
 * than retyped — each entry carries the lines it was read from, and the test titles
 * print them. The hid = 0x02 block is compared against GmSSL C's own
 * `test_sm9_z256_exchange` hex macros, which are a different codebase's output and not
 * this lab's. Nothing here is compared against a value this lab generated.
 */
import { describe, expect, it } from 'vitest';
import { SM9_P1, SM9_P2, point_mul, point_new } from '../vendor/gmssl-sm9.js';
import vectors from './fixtures/sm9-keyexchange-vectors.json';
import { HID, N } from './params';
import { bytesToHex, hexToBytes } from './hash';
import { pairing, type G1Point, type G2Point } from './pairing';
import {
  confirmationTags,
  deriveSessionKey,
  encryptionMasterKey,
  extractEncryptionKey,
  g1ScalarMul,
  g1ToHex,
  g2ToHex,
  gtPow,
  gtToHex,
  hidConvention,
  isInG1,
  runKeyExchange,
  type SideValues,
} from './exchange';

const P1 = SM9_P1 as G1Point;
const P2 = SM9_P2 as G2Point;

const shared = vectors.shared_inputs;
const published = vectors.annex_b_published;

const ke = BigInt('0x' + shared.ke);
const idA = hexToBytes(shared.ID_A);
const idB = hexToBytes(shared.ID_B);
const rA = BigInt('0x' + shared.r_A);
const rB = BigInt('0x' + shared.r_B);
const klenBits = shared.klen_bits;

const base = { ke, idA, idB, rA, rB, klenBits };

/** The declared hid of GM/T 0044.5 Annex B. */
const run03 = runKeyExchange({ ...base, hid: HID.ENCRYPT });
/** GmSSL's SM9_HID_EXCH, which is not in the standard at all. */
const run02 = runKeyExchange({ ...base, hid: HID.EXCHANGE_GMSSL });
/**
 * The annex read LITERALLY: 0x03 in the clause 5.3 extraction steps, 0x02 in A1/B1,
 * exactly as the two misprinted lines say. This is not a convention anybody runs; it
 * is the third leg of the misprint diagnosis, and the only way to settle it is output.
 */
const literal = runKeyExchange({ ...base, hid: HID.ENCRYPT, protocolHid: HID.EXCHANGE_GMSSL });

const scalarHex = (x: bigint): string => x.toString(16).padStart(64, '0');

describe('what this test opened, before any of its logic is trusted', () => {
  it('names one subject beside the question it answers', () => {
    // question: "what hid does Annex B declare?"  opened: the standard, line 574.
    expect(shared.source_pdf_md5).toBe('40cee7ca9ab2b885dee2158b2d4a12cc');
    expect(shared.source_pdf_md5_verified).toBe(true);
    expect(vectors.sources['hid-0x03'].declared_at).toContain('line 574');
    expect(vectors.sources['hid-0x03'].kind).toBe('national standard, informative annex');
    // question: "what hid does GmSSL use for EXCHANGE?"  opened: gmssl-sm9.h line 31.
    expect(vectors.sources['hid-0x02'].declared_at).toContain('SM9_HID_EXCH 0x02');
    expect(vectors.sources['hid-0x02'].kind).toBe('implementation convention');
  });

  it('labels each hid by its source rather than by a verdict', () => {
    expect(hidConvention(HID.ENCRYPT)?.inTheStandard).toBe(true);
    expect(hidConvention(HID.EXCHANGE_GMSSL)?.inTheStandard).toBe(false);
    // A hid neither convention declares is reported as unknown, not defaulted.
    expect(hidConvention(0x01)).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The 37 intermediates
// ---------------------------------------------------------------------------

interface Row {
  name: string;
  lines: string;
  expected: string;
  actual: string;
}

const r = run03;
const INTERMEDIATES: Row[] = [
  // clause 5.3 — the master key and the two user private keys
  { name: 'Ppub-e', lines: `${published.Ppube_x.lines}/${published.Ppube_y.lines}`,
    expected: published.Ppube_x.hex + published.Ppube_y.hex, actual: g1ToHex(r.master.Ppube) },
  { name: 'ID_A || hid (extraction)', lines: published.kg_A_in.lines,
    expected: published.kg_A_in.hex, actual: bytesToHex(r.deA.hashInput) },
  { name: 'H1(ID_A || hid, N) (extraction)', lines: published.kg_A_h1.lines,
    expected: published.kg_A_h1.hex, actual: scalarHex(r.deA.h1) },
  { name: 't1', lines: published.t1.lines, expected: published.t1.hex, actual: scalarHex(r.deA.t1) },
  { name: 't2', lines: published.t2.lines, expected: published.t2.hex, actual: scalarHex(r.deA.t2) },
  { name: 'de_A', lines: `${published.deA_x.lines}/${published.deA_y.lines}`,
    expected: published.deA_x.hex + published.deA_y.hex, actual: g2ToHex(r.deA.de) },
  { name: 'ID_B || hid (extraction)', lines: published.kg_B_in.lines,
    expected: published.kg_B_in.hex, actual: bytesToHex(r.deB.hashInput) },
  { name: 'H1(ID_B || hid, N) (extraction)', lines: published.kg_B_h1.lines,
    expected: published.kg_B_h1.hex, actual: scalarHex(r.deB.h1) },
  { name: 't3', lines: published.t3.lines, expected: published.t3.hex, actual: scalarHex(r.deB.t1) },
  { name: 't4', lines: published.t4.lines, expected: published.t4.hex, actual: scalarHex(r.deB.t2) },
  { name: 'de_B', lines: `${published.deB_x.lines}/${published.deB_y.lines}`,
    expected: published.deB_x.hex + published.deB_y.hex, actual: g2ToHex(r.deB.de) },

  // A1-A4
  { name: 'H1(ID_B || hid, N) (A1)', lines: published.a1_h1.lines,
    expected: published.a1_h1.hex, actual: scalarHex(r.qB.h1) },
  { name: 'Q_B (A1)', lines: `${published.QB_x.lines}/${published.QB_y.lines}`,
    expected: published.QB_x.hex + published.QB_y.hex, actual: g1ToHex(r.qB.Q) },
  { name: 'R_A (A3)', lines: `${published.RA_x.lines}/${published.RA_y.lines}`,
    expected: published.RA_x.hex + published.RA_y.hex, actual: g1ToHex(r.RA) },

  // B1-B3
  { name: 'H1(ID_A || hid, N) (B1)', lines: published.b1_h1.lines,
    expected: published.b1_h1.hex, actual: scalarHex(r.qA.h1) },
  { name: 'Q_A (B1)', lines: `${published.QA_x.lines}/${published.QA_y.lines}`,
    expected: published.QA_x.hex + published.QA_y.hex, actual: g1ToHex(r.qA.Q) },
  { name: 'R_B (B3)', lines: `${published.RB_x.lines}/${published.RB_y.lines}`,
    expected: published.RB_x.hex + published.RB_y.hex, actual: g1ToHex(r.RB) },

  // B4-B6, the responder
  { name: 'g1 = e(R_A, de_B) (B4)', lines: published.B_g1.lines,
    expected: published.B_g1.hex, actual: gtToHex(r.responder.g1) },
  { name: 'g2 = e(Ppub-e, P2)^r_B (B4)', lines: published.B_g2.lines,
    expected: published.B_g2.hex, actual: gtToHex(r.responder.g2) },
  { name: 'g3 = g1^r_B (B4)', lines: published.B_g3.lines,
    expected: published.B_g3.hex, actual: gtToHex(r.responder.g3) },
  { name: 'KDF input, 1288 octets (B5)', lines: published.B_kdf_in.lines,
    expected: published.B_kdf_in.hex, actual: bytesToHex(r.responder.kdfInput) },
  { name: 'SK_B (B5)', lines: published.SKB.lines,
    expected: published.SKB.hex, actual: bytesToHex(r.responder.sk) },
  { name: 'inner hash input, 904 octets (B6)', lines: published.B_inner_in.lines,
    expected: published.B_inner_in.hex, actual: bytesToHex(r.responder.innerInput) },
  { name: 'Hv(g2 || g3 || ID_A || ID_B || R_A || R_B) (B6)', lines: published.B_inner.lines,
    expected: published.B_inner.hex, actual: bytesToHex(r.responder.inner) },
  { name: '0x82 || g1 || inner (B6)', lines: published.B_s82_in.lines,
    expected: published.B_s82_in.hex, actual: bytesToHex(r.responder.tag82Input) },
  { name: 'S_B (B6)', lines: published.SB.lines,
    expected: published.SB.hex, actual: bytesToHex(r.responder.tag82) },

  // A5-A8, the initiator
  { name: "g1' = e(Ppub-e, P2)^r_A (A5)", lines: published.A_g1.lines,
    expected: published.A_g1.hex, actual: gtToHex(r.initiator.g1) },
  { name: "g2' = e(R_B, de_A) (A5)", lines: published.A_g2.lines,
    expected: published.A_g2.hex, actual: gtToHex(r.initiator.g2) },
  { name: "g3' = (g2')^r_A (A5)", lines: published.A_g3.lines,
    expected: published.A_g3.hex, actual: gtToHex(r.initiator.g3) },
  { name: "Hv(g2' || g3' || ...) (A6)", lines: published.A_inner.lines,
    expected: published.A_inner.hex, actual: bytesToHex(r.initiator.inner) },
  { name: 'S1 (A6)', lines: published.S1.lines,
    expected: published.S1.hex, actual: bytesToHex(r.initiator.tag82) },
  { name: 'KDF input, 1288 octets (A7)', lines: published.A_kdf_in.lines,
    expected: published.A_kdf_in.hex, actual: bytesToHex(r.initiator.kdfInput) },
  { name: 'SK_A (A7)', lines: published.SKA.lines,
    expected: published.SKA.hex, actual: bytesToHex(r.initiator.sk) },
  { name: "Hv(g2' || g3' || ...) (A8)", lines: published.A_inner2.lines,
    expected: published.A_inner2.hex, actual: bytesToHex(r.initiator.inner) },
  { name: 'S_A (A8)', lines: published.SA.lines,
    expected: published.SA.hex, actual: bytesToHex(r.initiator.tag83) },
  { name: 'Hv(g2 || g3 || ...) (B8)', lines: published.B_inner2.lines,
    expected: published.B_inner2.hex, actual: bytesToHex(r.responder.inner) },
  { name: 'S2 (B8)', lines: published.S2.lines,
    expected: published.S2.hex, actual: bytesToHex(r.responder.tag83) },
];

describe('hid = 0x03, GM/T 0044.5 Annex B', () => {
  it.each(INTERMEDIATES)('$name, Annex B lines $lines', ({ expected, actual }) => {
    expect(actual).toBe(expected);
  });

  it('is 37 intermediates — every hex block Annex B prints except its two misprints', () => {
    expect(INTERMEDIATES).toHaveLength(37);
    // Both sides reach the annex's published SK, so neither side alone carries the run.
    expect(bytesToHex(run03.responder.sk)).toBe(vectors.sources['hid-0x03'].published_SK);
    expect(bytesToHex(run03.initiator.sk)).toBe(vectors.sources['hid-0x03'].published_SK);
  });
});

// ---------------------------------------------------------------------------
// The misprint, diagnosed in three legs
// ---------------------------------------------------------------------------

describe("Annex B's two misprinted hid bytes", () => {
  it('leg 1: the H1 VALUE printed beside each 02 input is the 0x03 image, and SM3 is not constant', () => {
    // The annex prints ID_B||hid as 426f6202 at step A1 while printing 426f6203 in
    // extraction — but the H1 value it prints beside the 02 input is byte-identical to
    // the one it printed beside the 03 input. One of the two printed things is wrong,
    // and the value agrees with 0x03.
    expect(published.a1_in.hex).toBe('426f6202');
    expect(published.b1_in.hex).toBe('416c69636502');
    expect(published.a1_h1.hex).toBe(published.kg_B_h1.hex);
    expect(published.b1_h1.hex).toBe(published.kg_A_h1.hex);
    // Which image is it? Compute both and look.
    expect(scalarHex(run03.qB.h1)).toBe(published.a1_h1.hex);
    expect(scalarHex(run02.qB.h1)).not.toBe(published.a1_h1.hex);
    // The inputs differ in exactly their last octet, which is the hid.
    expect(bytesToHex(run03.qB.hashInput)).toBe('426f6203');
    expect(bytesToHex(run03.qB.hashInput).slice(0, -2)).toBe(published.a1_in.hex.slice(0, -2));
    expect(bytesToHex(run03.qA.hashInput)).toBe('416c69636503');
    expect(bytesToHex(run03.qA.hashInput).slice(0, -2)).toBe(published.b1_in.hex.slice(0, -2));
  });

  it('leg 2: read literally, the protocol does not complete — which the annex itself forbids', () => {
    // 0x03 in extraction, 0x02 in A1/B1, exactly as the two lines say. de_B is then
    // [ke/t3]P2 with t3 from H1(ID_B||03) while R_A is [r_A t3']P1 with t3' from
    // H1(ID_B||02), so t3 stops cancelling inside e(R_A, de_B) and the two sides land
    // on different elements of G_T.
    expect(bytesToHex(literal.responder.sk)).toBe(vectors.literal_reading_of_the_misprint.SK_B);
    expect(bytesToHex(literal.initiator.sk)).toBe(vectors.literal_reading_of_the_misprint.SK_A);
    expect(literal.agree).toBe(false);
    expect(literal.confirmBtoA).toBe(false);
    expect(literal.confirmAtoB).toBe(false);
    // The annex prints SK_A == SK_B. Its own output rules the literal reading out, so
    // this is not a third convention — it is a misprint.
    expect(published.SKA.hex).toBe(published.SKB.hex);
    expect(vectors.literal_reading_of_the_misprint.sides_agree).toBe(false);
  });

  it('leg 3: the misprint is in the source, not in the translation', () => {
    expect(vectors.misprint_diagnosis.holds).toBe(true);
    expect(vectors.misprint_diagnosis.leg_3).toContain('Chinese original');
  });
});

// ---------------------------------------------------------------------------
// The central exhibit: the same master key at both hid values
// ---------------------------------------------------------------------------

describe('hid = 0x02, the GmSSL convention', () => {
  const c = vectors.sources['hid-0x02'].corroborated_by;

  it("reproduces GmSSL C's own de_A, de_B and R_A from test_sm9_z256_exchange", () => {
    // These three come from a different codebase's test file, not from this lab.
    expect(g2ToHex(run02.deA.de)).toBe(c.hex_deA);
    expect(g2ToHex(run02.deB.de)).toBe(c.hex_deB);
    expect(g1ToHex(run02.RA)).toBe(c.hex_RA);
  });

  it('reaches the session key GmSSL and emmansun/gmsm publish', () => {
    expect(bytesToHex(run02.responder.sk)).toBe(vectors.sources['hid-0x02'].published_SK);
    expect(bytesToHex(run02.initiator.sk)).toBe(vectors.sources['hid-0x02'].published_SK);
    expect(bytesToHex(run02.responder.tag82)).toBe(vectors.sources['hid-0x02'].published_S_B);
    expect(bytesToHex(run02.initiator.tag83)).toBe(vectors.sources['hid-0x02'].published_S_A);
  });

  it("does not reproduce GmSSL C's key material at hid = 0x03", () => {
    // The pinned values belong to 0x02 and to nothing else; if they matched at both,
    // they would be evidence of nothing.
    expect(g2ToHex(run03.deA.de)).not.toBe(c.hex_deA);
    expect(g1ToHex(run03.RA)).not.toBe(c.hex_RA);
  });
});

describe('the exhibit: one master key, two hid conventions, two session keys', () => {
  it('the two session keys differ', () => {
    expect(bytesToHex(run03.responder.sk)).toBe('68b20d3077ea6e2b825315836fdbc633');
    expect(bytesToHex(run02.responder.sk)).toBe('c5c13a8f59a97cdeae64f16a2272a9e7');
    expect(bytesToHex(run03.responder.sk)).not.toBe(bytesToHex(run02.responder.sk));
  });

  it('neither run fails — that is what makes the divergence expensive', () => {
    for (const run of [run03, run02]) {
      expect(run.agree).toBe(true); // both sides hold the same SK
      expect(run.confirmBtoA).toBe(true); // A6: S1 = S_B
      expect(run.confirmAtoB).toBe(true); // B8: S2 = S_A
    }
    // Two conforming deployments, each internally consistent, each convinced the key
    // confirmed — and no shared key between them. There is no error to report.
  });

  it('g1, g2 and g3 are byte-identical at both hid values', () => {
    // hid enters only through t1/t3, and t1/t3 cancel inside the pairings. So the hid
    // reaches SK only through R_A and R_B in the KDF input, never through G_T.
    expect(gtToHex(run02.responder.g1)).toBe(gtToHex(run03.responder.g1));
    expect(gtToHex(run02.responder.g2)).toBe(gtToHex(run03.responder.g2));
    expect(gtToHex(run02.responder.g3)).toBe(gtToHex(run03.responder.g3));
    // ...while the two points that carry hid into the KDF input do differ.
    expect(g1ToHex(run02.RA)).not.toBe(g1ToHex(run03.RA));
    expect(g1ToHex(run02.RB)).not.toBe(g1ToHex(run03.RB));
    // And the KDF inputs differ in exactly those 128 octets: the first 8 (ID_A||ID_B)
    // and the last 1152 (g1||g2||g3) are the same bytes.
    const a = bytesToHex(run03.responder.kdfInput);
    const b = bytesToHex(run02.responder.kdfInput);
    expect(a.slice(0, 16)).toBe(b.slice(0, 16));
    expect(a.slice(16 + 256)).toBe(b.slice(16 + 256));
    expect(a.slice(16, 16 + 256)).not.toBe(b.slice(16, 16 + 256));
  });
});

// ---------------------------------------------------------------------------
// The cancellation, run rather than argued
// ---------------------------------------------------------------------------

describe('why hid cancels: the algebra, checked by computing both halves', () => {
  it('Q_B = [t3]P1, so R_A = [r_A t3]P1', () => {
    // A1 computes [H1(ID_B||hid,N)]P1 + Ppub-e without knowing t3; clause 5.3 computes
    // t3 = H1(ID_B||hid,N) + ke knowing ke. They are the same point.
    expect(g1ToHex(run03.qB.Q)).toBe(g1ToHex(g1ScalarMul(run03.deB.t1, P1)));
    expect(g1ToHex(run03.RA)).toBe(g1ToHex(g1ScalarMul((rA * run03.deB.t1) % N, P1)));
  });

  it('e(R_A, de_B) = e(Ppub-e, P2)^r_A — the t3 cancels', () => {
    // B computes the left side and A computes the right side. They never exchange a
    // G_T element, and they agree.
    expect(gtToHex(run03.responder.g1)).toBe(gtToHex(run03.initiator.g1));
    expect(gtToHex(run03.responder.g2)).toBe(gtToHex(run03.initiator.g2));
    expect(gtToHex(run03.responder.g3)).toBe(gtToHex(run03.initiator.g3));
  });
});

// ---------------------------------------------------------------------------
// The swap, tested as a negative control
// ---------------------------------------------------------------------------

describe('the g1/g2 swap between the two sides', () => {
  // The error this catches: A implemented with B4's formulas instead of A5's. Built
  // here out of the module's own exported primitives, so the control exercises the
  // real pairing and serialisation path rather than a copy of it.
  const master = encryptionMasterKey(ke);
  const deA = extractEncryptionKey(master, idA, HID.ENCRYPT);
  const swappedA: SideValues = (() => {
    const g1 = pairing(deA.de, run03.RB); // B4's shape: pair the received point
    const g2 = gtPow(pairing(P2, master.Ppube), rA); // B4's shape: exponentiate
    const g3 = gtPow(g1, rA); // B4 raises g3 from g1, A5 raises it from g2
    return { g1, g2, g3 };
  })();
  // The mirror of the same mistake on B's side: B implemented with A5's formulas.
  const deB = extractEncryptionKey(master, idB, HID.ENCRYPT);
  const swappedB: SideValues = (() => {
    const g1 = gtPow(pairing(P2, master.Ppube), rB); // A5's shape
    const g2 = pairing(deB.de, run03.RA); // A5's shape
    const g3 = gtPow(g2, rB); // A5 raises g3 from g2
    return { g1, g2, g3 };
  })();
  const swappedKey = deriveSessionKey(idA, idB, run03.RA, run03.RB, swappedA, klenBits);
  const swappedTags = confirmationTags(idA, idB, run03.RA, run03.RB, swappedA);
  const swappedKeyB = deriveSessionKey(idA, idB, run03.RA, run03.RB, swappedB, klenBits);
  const swappedTagsB = confirmationTags(idA, idB, run03.RA, run03.RB, swappedB);

  it('produces the same three values with two of them transposed', () => {
    // This is why the mistake is quiet: nothing is malformed, nothing is off-curve,
    // and g3 is not even changed. Only the order of g1 and g2 in the two hash inputs.
    expect(gtToHex(swappedA.g1)).toBe(gtToHex(run03.initiator.g2));
    expect(gtToHex(swappedA.g2)).toBe(gtToHex(run03.initiator.g1));
    expect(gtToHex(swappedA.g3)).toBe(gtToHex(run03.initiator.g3));
  });

  it('disagrees with a correct B, and the key confirmation is what catches it', () => {
    expect(bytesToHex(swappedKey.sk)).not.toBe(bytesToHex(run03.responder.sk));
    expect(bytesToHex(swappedKey.sk)).not.toBe(published.SKA.hex);
    // A6 compares S1 with S_B. That comparison is the only thing standing between a
    // swapped initiator and a silently wrong session key, which is the argument for
    // running the OPTIONAL key confirmation.
    expect(bytesToHex(swappedTags.tag82)).not.toBe(bytesToHex(run03.responder.tag82));
  });

  it('agrees with a B that made the MIRROR mistake, which is why one side proves nothing', () => {
    // Swap B4 for A5 on the responder and the transposition is the same one, so two
    // wrong implementations interoperate perfectly and derive a key the standard does
    // not. A test that only checks "both sides agree" would pass on this fleet.
    expect(gtToHex(swappedB.g1)).toBe(gtToHex(swappedA.g1));
    expect(gtToHex(swappedB.g2)).toBe(gtToHex(swappedA.g2));
    expect(gtToHex(swappedB.g3)).toBe(gtToHex(swappedA.g3));
    expect(bytesToHex(swappedKeyB.sk)).toBe(bytesToHex(swappedKey.sk));
    expect(bytesToHex(swappedTagsB.tag82)).toBe(bytesToHex(swappedTags.tag82));
    expect(bytesToHex(swappedKeyB.sk)).not.toBe(published.SKB.hex);
  });
});

// ---------------------------------------------------------------------------
// The preconditions the engine will not check for you
// ---------------------------------------------------------------------------

describe('guards', () => {
  it('B4/A5 membership: rejects the identity and an off-curve point, accepts R_A', () => {
    expect(isInG1(run03.RA)).toBe(true);
    expect(isInG1(run03.RB)).toBe(true);
    expect(isInG1({ X: 1n, Y: 1n, Z: 0n })).toBe(false); // the identity
    expect(isInG1({ X: 1n, Y: 1n, Z: 1n })).toBe(false); // y^2 = 1, x^3 + 5 = 6
  });

  it('gtPow refuses an exponent the engine would reduce against the wrong modulus', () => {
    // fp12_pow opens with k %= SM9_P, the field characteristic, not N.
    expect(() => gtPow(run03.responder.g1, 0n)).toThrow(RangeError);
    expect(() => gtPow(run03.responder.g1, N)).toThrow(RangeError);
    expect(() => gtPow(run03.responder.g1, -1n)).toThrow(RangeError);
  });

  it('scalars and ke are range-checked against [1, N-1]', () => {
    expect(() => encryptionMasterKey(0n)).toThrow(RangeError);
    expect(() => encryptionMasterKey(N)).toThrow(RangeError);
    expect(() => g1ScalarMul(0n, P1)).toThrow(RangeError);
  });

  it('g1ScalarMul normalises the point it is given, because point_mul reads it as affine', () => {
    // HAZARD 1, pinned rather than asserted in a comment. point_mul's inner loop is
    // point_add(Q, Q, P), and point_add ignores its second operand's Z — so a Jacobian
    // P produces an off-curve answer with no throw. Build a Jacobian point the way the
    // engine hands them back, and check that multiplying it still lands on [6]P1.
    const jacobian = point_new();
    point_mul(jacobian, 2n, P1); // raw engine call, deliberately not normalised
    expect((jacobian as G1Point).Z).not.toBe(1n);
    expect(g1ToHex(g1ScalarMul(3n, jacobian as G1Point))).toBe(g1ToHex(g1ScalarMul(6n, P1)));
  });

  it('hid is one octet', () => {
    const master = encryptionMasterKey(ke);
    expect(() => extractEncryptionKey(master, idA, 0x100)).toThrow(RangeError);
    expect(() => extractEncryptionKey(master, idA, -1)).toThrow(RangeError);
  });
});
