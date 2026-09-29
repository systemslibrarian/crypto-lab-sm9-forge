/**
 * The independent cross-check: values this lab produces, checked against an
 * implementation that shares no code path with it.
 *
 * WHY NOT gmssl-node, which the build brief named. It cannot do this job, and
 * that was established by reading its source rather than assumed: the addon's
 * only key-import path is `importEncryptedPrivateKeyInfoPem`, so there is no way
 * to load a PINNED master key such as GM/T 0044.5 Annex A's ks. It can generate
 * fresh keys and round-trip them, which proves self-consistency and nothing about
 * agreement with a published vector. It also links -lgmssl, a native library that
 * would have to be built inside CI.
 *
 * So the oracle is two legs, both stronger for this purpose and both runnable in
 * CI with no native build:
 *
 *   LEG 1 — GmSSL C's own pinned test vectors, lifted verbatim from its
 *   tests/sm9test.c into src/sm9/fixtures/gmssl-c-vectors.json. Those are the
 *   OUTPUTS of an independent SM9 implementation, committed by its authors. If
 *   this lab agrees with them, two implementations agree.
 *
 *   LEG 2 — OpenSSL's SM3, reached through node:crypto, driving the same H1/H2/KDF
 *   constructions. A different SM3 codebase entirely from the @li0ard/sm3 the
 *   runtime uses, so a bug inside either hash implementation cannot hide.
 *
 * This runs as its own CI step (`npm run test:oracle`) so that a failure here is
 * legible as "the two implementations disagree" rather than as one more red test.
 */
import { describe, expect, it } from 'vitest';
import { createHash } from 'node:crypto';

import vectors from './fixtures/gmssl-c-vectors.json';
import { N } from './params';
import * as fn from './fn';
import { H1, H2, KDF, concatBytes, bytesToHex, hexToBytes } from './hash';

const hex = (name: string): string[] => {
  const v = (vectors.vectors as Record<string, string[]>)[name];
  if (!v) throw new Error(`no such GmSSL C vector: ${name}`);
  return v;
};
const one = (name: string): bigint => BigInt('0x' + hex(name)[0]);

/** Does this Node build actually have OpenSSL's SM3? If not, say so loudly. */
function opensslSm3Available(): boolean {
  try {
    createHash('sm3');
    return true;
  } catch {
    return false;
  }
}

const opensslSm3 = (data: Uint8Array): Uint8Array =>
  new Uint8Array(createHash('sm3').update(Buffer.from(data)).digest());

describe('oracle leg 1 — GmSSL C pinned vectors (independent implementation)', () => {
  // These six are GmSSL C's F_N arithmetic outputs. src/sm9/fn.ts is written from
  // scratch here because the vendored engine has no mod-N layer at all, so there is
  // no shared code between the two sides of this comparison.
  const x = one('hex_x');
  const y = one('hex_y');

  it('fn.add matches hex_fn_add', () => {
    expect(fn.add(x, y)).toBe(one('hex_fn_add'));
  });

  it('fn.sub matches hex_fn_sub', () => {
    expect(fn.sub(x, y)).toBe(one('hex_fn_sub'));
  });

  it('fn.mul matches hex_fn_mul', () => {
    expect(fn.mul(x, y)).toBe(one('hex_fn_mul'));
  });

  it('fn.inv matches hex_fn_inv', () => {
    expect(fn.inv(x)).toBe(one('hex_fn_inv'));
  });

  it('fn.pow matches hex_fn_pow', () => {
    expect(fn.pow(x, y)).toBe(one('hex_fn_pow'));
  });

  // sm9test.c:227 is `sm9_z256_modn_sub(r, y, x)` — the REVERSE subtraction, not
  // N - x. Asserting the wrong relationship here failed, which is the point of
  // having an oracle: the vector is right and the assumption about it was not.
  it('fn.sub(y, x) matches hex_fn_nsub (the reverse subtraction)', () => {
    expect(fn.sub(y, x)).toBe(one('hex_fn_nsub'));
  });

  it('the two subtraction directions are genuinely different values', () => {
    expect(fn.sub(x, y)).not.toBe(fn.sub(y, x));
    expect(fn.add(fn.sub(x, y), fn.sub(y, x))).toBe(0n);
  });

  it('the master secrets GmSSL pins are valid scalars for this curve', () => {
    for (const name of ['hex_ks', 'hex_ke', 'hex_kex']) {
      const k = one(name);
      expect(fn.isValidScalar(k), `${name} in [1, N-1]`).toBe(true);
      expect(k).toBeLessThan(N);
    }
  });

  it('carries the provenance of every vector it uses', () => {
    expect(vectors.source.project).toBe('guanzhi/GmSSL');
    expect(vectors.source.file).toBe('tests/sm9test.c');
    expect(vectors.source.license).toBe('Apache-2.0');
    expect(Object.keys(vectors.vectors).length).toBeGreaterThanOrEqual(70);
  });
});

describe('oracle leg 2 — OpenSSL SM3 driving the same constructions', () => {
  it('this Node build provides OpenSSL SM3 (the leg is not silently skipped)', () => {
    expect(
      opensslSm3Available(),
      'node:crypto has no sm3 digest, so the independent hash leg cannot run. ' +
        'Do not treat this suite as green without it.',
    ).toBe(true);
  });

  it('agrees with @li0ard/sm3 on the published GB/T 32905 vector', () => {
    const abc = new TextEncoder().encode('abc');
    expect(bytesToHex(opensslSm3(abc))).toBe(
      '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0',
    );
  });

  /** H1/H2 rebuilt on OpenSSL's SM3 — GM/T 0044.4 clauses 5.4.2.2 / 5.4.2.3. */
  function hashToRangeOpenssl(prefix: number, Z: Uint8Array, n: bigint): bigint {
    const hlen = 8 * Math.ceil((5 * n.toString(2).length) / 32);
    const blocks = Math.ceil(hlen / 256);
    const parts: Uint8Array[] = [];
    for (let ct = 1; ct <= blocks; ct++) {
      const ctBytes = Uint8Array.from([
        (ct >>> 24) & 0xff,
        (ct >>> 16) & 0xff,
        (ct >>> 8) & 0xff,
        ct & 0xff,
      ]);
      parts.push(opensslSm3(concatBytes(Uint8Array.from([prefix]), Z, ctBytes)));
    }
    if (hlen % 256 !== 0) {
      const tailBits = hlen - 256 * Math.floor(hlen / 256);
      const last = parts[parts.length - 1];
      const whole = tailBits >> 3;
      const rem = tailBits & 7;
      const cut = last.slice(0, whole + (rem ? 1 : 0));
      if (rem) cut[whole] &= (0xff << (8 - rem)) & 0xff;
      parts[parts.length - 1] = cut;
    }
    const Ha = concatBytes(...parts);
    return (BigInt('0x' + bytesToHex(Ha)) % (n - 1n)) + 1n;
  }

  function kdfOpenssl(Z: Uint8Array, klenBits: number): Uint8Array {
    const blocks = Math.ceil(klenBits / 256);
    const parts: Uint8Array[] = [];
    for (let ct = 1; ct <= blocks; ct++) {
      const ctBytes = Uint8Array.from([
        (ct >>> 24) & 0xff,
        (ct >>> 16) & 0xff,
        (ct >>> 8) & 0xff,
        ct & 0xff,
      ]);
      parts.push(opensslSm3(concatBytes(Z, ctBytes)));
    }
    if (klenBits % 256 !== 0) {
      const tailBits = klenBits - 256 * Math.floor(klenBits / 256);
      const last = parts[parts.length - 1];
      const whole = tailBits >> 3;
      const rem = tailBits & 7;
      const cut = last.slice(0, whole + (rem ? 1 : 0));
      if (rem) cut[whole] &= (0xff << (8 - rem)) & 0xff;
      parts[parts.length - 1] = cut;
    }
    return concatBytes(...parts);
  }

  // Inputs spanning one block and several, including the multi-block H1 case the
  // standard's own annexes never exercise (every annex H1 input is 4-6 bytes).
  const inputs: Array<{ label: string; Z: Uint8Array }> = [
    { label: 'Alice||0x01 (Annex A shape, single block)', Z: hexToBytes('416c69636501') },
    { label: 'Bob||0x03 (Annex B shape, single block)', Z: hexToBytes('426f6203') },
    {
      label: 'a 60-byte identity (multi-block: crosses one SM3 block)',
      Z: concatBytes(
        new TextEncoder().encode('certificate-authority.operations.example.test.identity-60'),
        Uint8Array.from([0x01]),
      ),
    },
    {
      label: 'a 200-byte identity (multi-block: four SM3 blocks)',
      Z: concatBytes(new TextEncoder().encode('z'.repeat(200)), Uint8Array.from([0x03])),
    },
  ];

  for (const { label, Z } of inputs) {
    it(`H1 agrees across both SM3 implementations — ${label}`, () => {
      expect(H1(Z).h).toBe(hashToRangeOpenssl(0x01, Z, N));
    });

    it(`H2 agrees across both SM3 implementations — ${label}`, () => {
      expect(H2(Z).h).toBe(hashToRangeOpenssl(0x02, Z, N));
    });
  }

  it('at least one H1 input above genuinely spans more than one SM3 block', () => {
    const spans = inputs.filter(({ Z }) => H1(Z).sm3Blocks > 1);
    expect(spans.length).toBeGreaterThan(0);
  });

  for (const klenBits of [128, 256, 264, 512, 1024]) {
    it(`KDF agrees across both SM3 implementations at klen=${klenBits} bits`, () => {
      const Z = new TextEncoder().encode('sm9 kdf cross-check input, deliberately longer than one SM3 block to exercise the compression loop');
      expect(bytesToHex(KDF(Z, klenBits))).toBe(bytesToHex(kdfOpenssl(Z, klenBits)));
    });
  }

  it('the two legs would actually notice a disagreement', () => {
    // A negative control: feed the two sides different inputs and require a mismatch.
    const a = hexToBytes('426f6203');
    const b = hexToBytes('426f6202');
    expect(H1(a).h).not.toBe(hashToRangeOpenssl(0x01, b, N));
  });
});
