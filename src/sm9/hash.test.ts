/**
 * Every vector in src/sm9/fixtures/sm9-hash-vectors.json, driven.
 *
 * The fixture holds 30 vectors: 20 published sub-values read out of GM/T
 * 0044.5's Annexes A-D, and 10 generated here. The published ones are the
 * conformance evidence. The generated ones exist for one reason, and it is the
 * reason this file states it out loud rather than leaving it to a filename:
 *
 *   EVERY H1 INPUT THE STANDARD PRINTS IS 4 OR 6 BYTES LONG.
 *
 * With the 0x01 prefix and the 4-byte counter that is a 9- or 11-byte SM3
 * message, so all 20 annex vectors compress exactly one 64-byte block. An H1
 * that mishandled a second block — a length field written in the wrong
 * endianness, a counter appended before the identity, a buffer reused across
 * compressions — would reproduce all twenty and still be broken for any
 * identity longer than 49 bytes. Identities are email addresses and domain
 * names; 49 bytes is not an exotic case.
 *
 * So the multi-block coverage is asserted explicitly below, not merely present.
 * If someone prunes the fixture to "just the standard's vectors", that
 * assertion fails, which is the only thing that stops this coverage
 * disappearing quietly.
 */
import { describe, it, expect } from 'vitest';
import { H1, H2, KDF, V_BITS, bytesToHex, hexToBytes, identityWithHid } from './hash';
import { N } from './params';
import fixture from './fixtures/sm9-hash-vectors.json';

interface HashVector {
  id: string;
  fn: string;
  annex: string;
  description: string;
  n_hex?: string;
  klen_bits?: number;
  input_hex: string;
  input_bytes: number;
  sm3_blocks_compressed: number;
  expected_hex: string;
  verified: boolean;
  standard_correction?: string;
  identity_utf8?: string;
  identity_hex?: string;
}

const VECTORS = fixture.vectors as unknown as HashVector[];
const H1_VECTORS = VECTORS.filter((v) => v.fn === 'H1');
const H2_VECTORS = VECTORS.filter((v) => v.fn === 'H2');
const KDF_VECTORS = VECTORS.filter((v) => v.fn === 'KDF');

/** How many 64-byte blocks SM3 compresses for a message of `n` bytes: the
 *  message plus the 1-byte 0x80, 8-byte length field, rounded up. */
function sm3BlocksFor(messageBytes: number): number {
  return Math.ceil((messageBytes + 9) / 64);
}

describe('the fixture itself', () => {
  it('holds every vector it says it holds', () => {
    // A count lint. The failure this prevents is a vector being dropped during
    // an edit and the suite still passing on the ones that remain.
    expect(VECTORS).toHaveLength(30);
    expect(VECTORS.filter((v) => v.annex !== 'GENERATED')).toHaveLength(fixture.counts.published);
    expect(VECTORS.filter((v) => v.annex === 'GENERATED')).toHaveLength(fixture.counts.generated);
    expect(H1_VECTORS.length + H2_VECTORS.length + KDF_VECTORS.length).toBe(VECTORS.length);
  });

  it('declares the same N the params module does', () => {
    expect(BigInt('0x' + fixture.n_hex)).toBe(N);
    expect(fixture.v_bits).toBe(V_BITS);
  });

  it('carries the two vectors whose annex input is a misprint, still flagged as such', () => {
    // GM/T 0044.5 Annex B prints two H1 inputs ending ...02 whose printed
    // digests are the ...03 digests. The fixture corrects the input and records
    // that it did. Folding a correction in silently is how a reader ends up
    // believing the standard says something it does not.
    const corrected = VECTORS.filter((v) => v.standard_correction);
    expect(corrected).toHaveLength(2);
    for (const v of corrected) {
      expect(v.standard_correction).toMatch(/typo/);
      expect(v.input_hex.endsWith('03')).toBe(true);
    }
  });
});

describe('H1 — GM/T 0044.4 clause 5.4.2.2', () => {
  it.each(H1_VECTORS.map((v) => [v.id, v] as const))('%s', (_id, v) => {
    const n = BigInt('0x' + (v.n_hex ?? fixture.n_hex));
    const result = H1(hexToBytes(v.input_hex), n);

    expect(result.h.toString(16).padStart(64, '0')).toBe(v.expected_hex);

    // Every H1 output is a usable scalar, which is the point of step 6's
    // (Ha mod (n-1)) + 1 rather than a bare reduction.
    expect(result.h).toBeGreaterThanOrEqual(1n);
    expect(result.h).toBeLessThanOrEqual(n - 1n);

    // The intermediate shape, for SM9's 256-bit n: hlen = 320 bits, so two SM3
    // calls and a 40-byte Ha whose last block is truncated to 8 bytes.
    expect(result.hlen).toBe(fixture.hlen_bits);
    expect(result.blocks).toBe(2);
    expect(result.Ha).toHaveLength(40);

    // And the message length the module reports agrees with the fixture's own
    // block count: 0x01 || Z || ct.
    expect(result.sm3InputBytes).toBe(1 + v.input_bytes + 4);
    expect(result.sm3Blocks).toBe(v.sm3_blocks_compressed);
  });
});

describe('H2 — GM/T 0044.4 clause 5.4.2.3', () => {
  it.each(H2_VECTORS.map((v) => [v.id, v] as const))('%s', (_id, v) => {
    const n = BigInt('0x' + (v.n_hex ?? fixture.n_hex));
    const result = H2(hexToBytes(v.input_hex), n);
    expect(result.h.toString(16).padStart(64, '0')).toBe(v.expected_hex);
    expect(result.hlen).toBe(fixture.hlen_bits);
    expect(result.sm3Blocks).toBe(v.sm3_blocks_compressed);
  });

  it('H1 and H2 differ only in the prefix byte, and that is enough to separate them', () => {
    // Same Z, same n, different function: the two must not collide. This is the
    // whole of the domain separation SM9 relies on between key extraction and
    // message binding.
    const Z = hexToBytes('416c69636501');
    expect(H1(Z).h).not.toBe(H2(Z).h);
  });

  it('the annex H2 inputs are 404 bytes — message plus a 384-byte Fp12', () => {
    for (const v of H2_VECTORS) {
      expect(v.input_bytes).toBe(404);
      expect(v.input_bytes - 384).toBe(20); // "Chinese IBS standard"
    }
  });
});

describe('KDF — GM/T 0044.3 clause 5.4.3', () => {
  it.each(KDF_VECTORS.map((v) => [v.id, v] as const))('%s', (_id, v) => {
    expect(v.klen_bits).toBeDefined();
    const klen = v.klen_bits as number;
    const out = KDF(hexToBytes(v.input_hex), klen);
    expect(bytesToHex(out)).toBe(v.expected_hex);
    expect(out.length * 8).toBeGreaterThanOrEqual(klen);
    expect(sm3BlocksFor(v.input_bytes + 4)).toBe(v.sm3_blocks_compressed);
  });

  it('at least one vector asks for a klen that is not a whole number of SM3 blocks', () => {
    // 416 and 384 bits both leave a partial final block, which is the only path
    // through step 3's truncation. Without one of these the truncation branch
    // is never executed by any published vector.
    const partial = KDF_VECTORS.filter((v) => (v.klen_bits as number) % V_BITS !== 0);
    expect(partial.length).toBeGreaterThanOrEqual(1);
  });

  it('klen is in BITS — passing bytes gives a shorter output, not an error', () => {
    // The easiest wrong answer in this file. Stated as a test because the type
    // system cannot say it: both are numbers.
    const Z = hexToBytes('416c696365');
    expect(KDF(Z, 128)).toHaveLength(16);
    expect(KDF(Z, 16)).toHaveLength(2);
  });
});

describe('multi-block H1 — the coverage the annexes do not provide', () => {
  /**
   * This block is the reason the generated vectors exist. It is written as an
   * assertion about the fixture rather than as a comment so that pruning the
   * fixture back to "the standard's own vectors" turns something red.
   */
  it('every H1 input the STANDARD publishes is one SM3 block, which is the gap', () => {
    const published = H1_VECTORS.filter((v) => v.annex !== 'GENERATED');
    expect(published.length).toBeGreaterThan(0);
    for (const v of published) {
      expect(v.input_bytes).toBeLessThanOrEqual(6);
      expect(H1(hexToBytes(v.input_hex)).sm3Blocks).toBe(1);
    }
  });

  it('at least one H1 vector hashes an SM3 message longer than one 64-byte block', () => {
    const multi = H1_VECTORS.filter((v) => H1(hexToBytes(v.input_hex)).sm3Blocks > 1);
    expect(multi.length).toBeGreaterThanOrEqual(1);
    // Nine of them today. Stated as a floor rather than an equality so adding
    // more is not a failure, but losing them all is.
    expect(multi.length).toBeGreaterThanOrEqual(9);

    // And the longest genuinely crosses several blocks, not just two.
    const widest = Math.max(...multi.map((v) => H1(hexToBytes(v.input_hex)).sm3Blocks));
    expect(widest).toBeGreaterThanOrEqual(4);
  });

  it('the pair either side of the one-block boundary is covered, and they differ', () => {
    // An SM3 message of exactly 55 bytes still fits one block once 0x80 and the
    // 8-byte length are appended; 56 does not. The fixture has an identity on
    // each side of that line, which is where an off-by-one in the padding lives.
    const at = H1_VECTORS.find((v) => H1(hexToBytes(v.input_hex)).sm3InputBytes === 55);
    const over = H1_VECTORS.find((v) => H1(hexToBytes(v.input_hex)).sm3InputBytes === 56);
    expect(at).toBeDefined();
    expect(over).toBeDefined();
    expect(H1(hexToBytes((at as HashVector).input_hex)).sm3Blocks).toBe(1);
    expect(H1(hexToBytes((over as HashVector).input_hex)).sm3Blocks).toBe(2);
  });

  it('the generated vectors span all three hid values, so hid is not accidentally fixed', () => {
    const generated = H1_VECTORS.filter((v) => v.annex === 'GENERATED');
    const hids = new Set(generated.map((v) => v.input_hex.slice(-2)));
    expect(hids).toEqual(new Set(['01', '02', '03']));
  });
});

describe('identityWithHid', () => {
  it('rebuilds every generated vector’s input from its identity and hid byte', () => {
    const generated = H1_VECTORS.filter((v) => v.annex === 'GENERATED' && v.identity_utf8);
    expect(generated.length).toBeGreaterThanOrEqual(9);
    for (const v of generated) {
      const hid = parseInt(v.input_hex.slice(-2), 16);
      const built = identityWithHid(v.identity_utf8 as string, hid);
      expect(bytesToHex(built)).toBe(v.input_hex);
      // And the round trip through H1 lands on the published digest.
      expect(H1(built).h.toString(16).padStart(64, '0')).toBe(v.expected_hex);
    }
  });

  it('appends the hid byte last, not first', () => {
    expect(bytesToHex(identityWithHid('Alice', 0x01))).toBe('416c69636501');
    expect(bytesToHex(identityWithHid('Alice', 0x03))).toBe('416c69636503');
  });

  it('refuses a hid that is not one octet', () => {
    expect(() => identityWithHid('Alice', -1)).toThrow(RangeError);
    expect(() => identityWithHid('Alice', 0x100)).toThrow(RangeError);
    expect(() => identityWithHid('Alice', 1.5)).toThrow(RangeError);
  });
});

describe('hex helpers', () => {
  it('round-trip', () => {
    const hex = '00ff10abcdef';
    expect(bytesToHex(hexToBytes(hex))).toBe(hex);
  });

  it('hexToBytes refuses an odd-length string rather than dropping a nibble', () => {
    expect(() => hexToBytes('abc')).toThrow(RangeError);
  });

  it('bytesToHex pads each byte to two nibbles', () => {
    // Without the pad, [0x0a, 0xbc] and [0xab, 0xc0] both render "abc".
    expect(bytesToHex(Uint8Array.from([0x0a, 0xbc]))).toBe('0abc');
  });
});
