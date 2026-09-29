/**
 * src/sm9/encrypt.ts against GM/T 0044.5 Annex C (key encapsulation) and
 * Annex D (public key encryption, both modes), value by value.
 *
 * WHAT IS BEING CHECKED AGAINST WHAT. Every expected value in this file comes
 * from src/sm9/fixtures/sm9-annex-cd-fixtures.json, whose fields were read out
 * of the standard's own text BY LINE NUMBER rather than retyped — each carries
 * the line range it came from. Nothing here is compared against this module's
 * own earlier output, which would measure nothing.
 *
 * It asserts the INTERMEDIATES, not just K and the ciphertext. A wrong Fp12
 * coefficient order, a swapped MAC argument or a missing affine normalisation
 * all still produce a self-consistent encrypt/decrypt round trip; only the
 * standard's printed w, C3 and Q_B can tell them apart, so those are what is
 * pinned.
 *
 * SM4 IS VERIFIED FIRST, in the first describe block, against GB/T 32907-2016
 * Appendix A.1 — both the single-block vector and the 1,000,000-round one.
 * Annex D mode b) reproduces nothing if the block cipher under it is wrong, and
 * an unverified SM4 would turn that into a claim about SM9.
 *
 * TWO CLAUSE 5 STEPS ARE REPRODUCED LOCALLY, at the top of this file: Ppub-e =
 * [ke]P1 (clause 5.2) and the user key extraction that yields de_B (clause 5.3).
 * They belong to the KGC, not to this module, and are here only to turn the
 * annex's master private key into the inputs clauses 6 and 7 take. They are not
 * a claim on any other module's interface.
 */
import { describe, expect, it } from 'vitest';
import { SM4, decryptCBC, encryptCBC } from '@li0ard/sm4';
import { sm3 } from '@li0ard/sm3';
import fixtures from './fixtures/sm9-annex-cd-fixtures.json';
import { HID, N, Q } from './params';
import { add, inv, mul } from './fn';
import { H1, bytesToHex, concatBytes, hexToBytes } from './hash';
import { toAffineG1, toAffineG2, type G1Point, type G2Point } from './pairing';
import {
  SM9_P,
  SM9_P1,
  SM9_P2,
  fp12_new,
  fp12_pow,
  point_add,
  point_is_on_curve,
  point_mul,
  point_new,
  twist_point_mul,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';
import {
  admitG1,
  compareKemKeys,
  pairingBase,
  decrypt,
  encrypt,
  fp12ToBytes,
  g1ToBytes,
  isInG1,
  kemDecapsulate,
  kemEncapsulate,
  mac,
  padForBlockCipher,
  receiverPublicPoint,
  stripBlockCipherPadding,
  type CipherMode,
} from './encrypt';

// ---------------------------------------------------------------------------
// fixture access
// ---------------------------------------------------------------------------

const FX = fixtures as unknown as Record<string, unknown>;

function at(path: string): unknown {
  let cur: unknown = FX;
  for (const key of path.split('.')) {
    if (cur === null || typeof cur !== 'object') throw new Error(`fixture: nothing at ${path}`);
    cur = (cur as Record<string, unknown>)[key];
  }
  if (cur === undefined) throw new Error(`fixture: nothing at ${path}`);
  return cur;
}

/** A plain string value printed in the annex (an input, an identity, a message). */
function str(path: string): string {
  const v = at(path);
  if (typeof v !== 'string') throw new Error(`fixture: ${path} is not a string`);
  return v;
}

/** The same, lowercased, for the fields whose value is hex. */
const hexOf = (path: string): string => str(path).toLowerCase();

/**
 * The expected value of a fixture node.
 *
 * Three shapes appear: a bare string (an input the annex prints, such as ID_B or
 * the master private key), a `value`/`source_lines` node (a value read out of the
 * standard by line number), and a `value_hex`/`value` node (a scalar
 * configuration line such as klen, where the number is what a caller passes).
 */
function expected(path: string): string | number {
  const node = at(path);
  if (typeof node === 'string') return node;
  const rec = node as Record<string, unknown>;
  if (typeof rec.value === 'number') return rec.value;
  if (typeof rec.value === 'string') return rec.value;
  if (typeof rec.value_hex === 'string') return rec.value_hex;
  throw new Error(`fixture: ${path} carries no value`);
}

/** Hex is compared without regard to case; the annexes print it in both. */
const norm = (v: string | number): string | number => (typeof v === 'string' ? v.toLowerCase() : v);

/**
 * Assert one computed value against the fixture.
 *
 * A bigint on the computed side is compared NUMERICALLY rather than as text,
 * and that is not a convenience. The annex prints its two secret scalars — the
 * master private key ke and the ephemeral r — with their leading zero bytes
 * stripped, 62 hex characters rather than 64. The claim being made about them is
 * "this module used the scalar the standard printed", which is a claim about the
 * number; padding it to 32 bytes to make the strings line up would be asserting
 * a transcription instead.
 */
function assertMatches(computed: string | number | bigint, want: string | number): void {
  if (typeof computed === 'bigint') {
    expect(computed).toBe(BigInt('0x' + String(want)));
    return;
  }
  expect(norm(computed)).toBe(norm(want));
}

/** Every node in the fixture that states a value, so none can be left unasserted. */
function valueNodePaths(root: string): string[] {
  const found: string[] = [];
  const walk = (node: unknown, path: string): void => {
    if (node === null || typeof node !== 'object' || Array.isArray(node)) return;
    const rec = node as Record<string, unknown>;
    if ('value' in rec || 'value_hex' in rec) {
      found.push(path);
      return;
    }
    for (const key of Object.keys(rec)) walk(rec[key], `${path}.${key}`);
  };
  walk(at(root), root);
  return found.sort();
}

// ---------------------------------------------------------------------------
// local helpers: serialisation in the annex's print order, and clause 5
// ---------------------------------------------------------------------------

const hex32 = (a: bigint): string => a.toString(16).padStart(64, '0');

/** An Fp2 as the annex prints it: (a1 || a0). The engine array is [a0, a1]. */
const fp2AnnexHex = (a: bigint[]): string => hex32(a[1]) + hex32(a[0]);

/** A G2 point in the annex's order, x then y, each an Fp2. */
function twistAnnex(p: G2Point): { x: string; y: string } {
  const a = toAffineG2(p);
  return { x: fp2AnnexHex(a.X), y: fp2AnnexHex(a.Y) };
}

function mulG1(k: bigint, p: G1Point): G1Point {
  const out = point_new();
  point_mul(out, k, toAffineG1(p));
  return toAffineG1(out as G1Point);
}

function mulG2(k: bigint, p: G2Point): G2Point {
  const out = twist_point_new();
  twist_point_mul(out, k, toAffineG2(p));
  return toAffineG2(out as G2Point);
}

/** Ppub-e = [ke]P1 — GM/T 0044.4 clause 5.2, the KGC's setup. */
const masterPublicPoint = (ke: bigint): G1Point => mulG1(ke, SM9_P1 as G1Point);

/**
 * de_B = [ke * (H1(ID||hid, N) + ke)^-1]P2 — GM/T 0044.4 clause 5.3, the KGC's
 * extraction. `inv` throws rather than returning a wrong value when t1 = 0,
 * which is the case the clause tells the KGC to re-key on.
 */
function extractEncryptionKey(ke: bigint, id: Uint8Array, hid: number) {
  const h1 = H1(concatBytes(id, Uint8Array.of(hid)), N).h;
  const t1 = add(h1, ke);
  const t2 = mul(ke, inv(t1));
  return { h1, t1, t2, deB: mulG2(t2, SM9_P2 as G2Point) };
}

// ---------------------------------------------------------------------------
// Annex C: key encapsulation, reproduced once
// ---------------------------------------------------------------------------

const cHid = parseInt(hexOf('annex_C_kem.hid'), 16);
const cId = hexToBytes(hexOf('annex_C_kem.ID_B'));
const cKe = BigInt('0x' + hexOf('annex_C_kem.master_encryption_private_key_ke'));
const cKlen = expected('annex_C_kem.klen_bits') as number;
const cR = BigInt('0x' + hexOf('annex_C_kem.encapsulate.A2_r'));

const cPpube = masterPublicPoint(cKe);
const cKey = extractEncryptionKey(cKe, cId, cHid);
const cQ = receiverPublicPoint(cId, cHid, cPpube);
const cEncap = kemEncapsulate(cId, cHid, cPpube, cKlen, { r: cR });
const cDecap = kemDecapsulate(cEncap.CBytes, cId, cKey.deB, cKlen);
if (!cDecap.ok) throw new Error(`Annex C decapsulation failed at ${cDecap.step}: ${cDecap.cause}`);

const cPpubeAff = toAffineG1(cPpube);
const cQbAff = toAffineG1(cEncap.Qb);
const cCAff = toAffineG1(cEncap.C);
const cDeB = twistAnnex(cKey.deB);

const ANNEX_C_COMPUTED: Record<string, string | number | bigint> = {
  'annex_C_kem.hid': cHid.toString(16).padStart(2, '0'),
  'annex_C_kem.ID_B_ascii': new TextDecoder().decode(cId),
  'annex_C_kem.ID_B': bytesToHex(cId),
  'annex_C_kem.ID_B_with_hid': bytesToHex(concatBytes(cId, Uint8Array.of(cHid))),
  'annex_C_kem.klen_bits': cEncap.K.length * 8,
  'annex_C_kem.master_encryption_private_key_ke': cKe,
  'annex_C_kem.Ppub_e.x': hex32(cPpubeAff.X),
  'annex_C_kem.Ppub_e.y': hex32(cPpubeAff.Y),
  'annex_C_kem.key_extraction.H1_ID_hid': hex32(cKey.h1),
  'annex_C_kem.key_extraction.t1': hex32(cKey.t1),
  'annex_C_kem.key_extraction.t2': hex32(cKey.t2),
  'annex_C_kem.key_extraction.de_B_x': cDeB.x,
  'annex_C_kem.key_extraction.de_B_y': cDeB.y,
  'annex_C_kem.encapsulate.A1_H1': hex32(cQ.h1),
  'annex_C_kem.encapsulate.A1_Q_B_x': hex32(cQbAff.X),
  'annex_C_kem.encapsulate.A1_Q_B_y': hex32(cQbAff.Y),
  'annex_C_kem.encapsulate.A2_r': cEncap.r,
  'annex_C_kem.encapsulate.A3_C_x': hex32(cCAff.X),
  'annex_C_kem.encapsulate.A3_C_y': hex32(cCAff.Y),
  'annex_C_kem.encapsulate.A4_g': bytesToHex(fp12ToBytes(cEncap.g)),
  'annex_C_kem.encapsulate.A5_w': bytesToHex(cEncap.wBytes),
  'annex_C_kem.encapsulate.A6_kdf_input': bytesToHex(cEncap.kdfInput),
  'annex_C_kem.encapsulate.A6_K': bytesToHex(cEncap.K),
  'annex_C_kem.decapsulate.B2_w': bytesToHex(cDecap.wBytes),
  'annex_C_kem.decapsulate.B3_kdf_input': bytesToHex(cDecap.kdfInput),
  'annex_C_kem.decapsulate.B3_K': bytesToHex(cDecap.K),
};

// ---------------------------------------------------------------------------
// Annex D: public key encryption, both modes, reproduced once
// ---------------------------------------------------------------------------

const dHid = parseInt(hexOf('annex_D_encryption.hid'), 16);
const dId = hexToBytes(hexOf('annex_D_encryption.ID_B'));
const dKe = BigInt('0x' + hexOf('annex_D_encryption.master_encryption_private_key_ke'));
const dMessage = hexToBytes(hexOf('annex_D_encryption.message_hex'));
const dR = BigInt('0x' + hexOf('annex_D_encryption.common.A2_r'));
const dK1Len = expected('annex_D_encryption.K1_len_bits') as number;
const dK2Len = expected('annex_D_encryption.K2_len_bits') as number;

const dPpube = masterPublicPoint(dKe);
const dKey = extractEncryptionKey(dKe, dId, dHid);
const dQ = receiverPublicPoint(dId, dHid, dPpube);
const pin = { r: dR, k1LenBits: dK1Len, k2LenBits: dK2Len } as const;

const encA = encrypt(dMessage, dId, dHid, dPpube, { ...pin, mode: 'a' });
const encB = encrypt(dMessage, dId, dHid, dPpube, { ...pin, mode: 'b' });
const decA = decrypt(encA.bytes, dId, dKey.deB, { mode: 'a', k1LenBits: dK1Len, k2LenBits: dK2Len });
const decB = decrypt(encB.bytes, dId, dKey.deB, { mode: 'b', k1LenBits: dK1Len, k2LenBits: dK2Len });
if (!decA.ok) throw new Error(`Annex D mode a decryption failed at ${decA.step}: ${decA.cause}`);
if (!decB.ok) throw new Error(`Annex D mode b decryption failed at ${decB.step}: ${decB.cause}`);

const dPpubeAff = toAffineG1(dPpube);
const dQbAff = toAffineG1(encA.Qb);
const dC1Aff = toAffineG1(encA.C1);
const dDeB = twistAnnex(dKey.deB);

const ANNEX_D_COMPUTED: Record<string, string | number | bigint> = {
  'annex_D_encryption.hid': dHid.toString(16).padStart(2, '0'),
  'annex_D_encryption.ID_B': bytesToHex(dId),
  'annex_D_encryption.message_ascii': new TextDecoder().decode(dMessage),
  'annex_D_encryption.message_hex': bytesToHex(dMessage),
  'annex_D_encryption.mlen_bits': dMessage.length * 8,
  'annex_D_encryption.K1_len_bits': encB.K1.length * 8,
  'annex_D_encryption.K2_len_bits': encA.K2.length * 8,
  'annex_D_encryption.master_encryption_private_key_ke': dKe,
  'annex_D_encryption.Ppub_e.x': hex32(dPpubeAff.X),
  'annex_D_encryption.Ppub_e.y': hex32(dPpubeAff.Y),
  'annex_D_encryption.key_extraction.H1_ID_hid': hex32(dKey.h1),
  'annex_D_encryption.key_extraction.t1': hex32(dKey.t1),
  'annex_D_encryption.key_extraction.t2': hex32(dKey.t2),
  'annex_D_encryption.key_extraction.de_B_x': dDeB.x,
  'annex_D_encryption.key_extraction.de_B_y': dDeB.y,
  'annex_D_encryption.common.A1_Q_B_x': hex32(dQbAff.X),
  'annex_D_encryption.common.A1_Q_B_y': hex32(dQbAff.Y),
  'annex_D_encryption.common.A2_r': encA.r,
  'annex_D_encryption.common.A3_C1_x': hex32(dC1Aff.X),
  'annex_D_encryption.common.A3_C1_y': hex32(dC1Aff.Y),
  'annex_D_encryption.common.A4_g': bytesToHex(fp12ToBytes(encA.g)),
  'annex_D_encryption.common.A5_w': bytesToHex(encA.wBytes),
  'annex_D_encryption.common.B2_w_decrypt': bytesToHex(decA.wBytes),

  'annex_D_encryption.mode_a_kdf_stream_cipher.klen_bits': encA.klenBits,
  'annex_D_encryption.mode_a_kdf_stream_cipher.kdf_input': bytesToHex(encA.kdfInput),
  'annex_D_encryption.mode_a_kdf_stream_cipher.K': bytesToHex(encA.K),
  'annex_D_encryption.mode_a_kdf_stream_cipher.K1': bytesToHex(encA.K1),
  'annex_D_encryption.mode_a_kdf_stream_cipher.C2': bytesToHex(encA.C2),
  'annex_D_encryption.mode_a_kdf_stream_cipher.K2': bytesToHex(encA.K2),
  'annex_D_encryption.mode_a_kdf_stream_cipher.C3': bytesToHex(encA.C3),
  'annex_D_encryption.mode_a_kdf_stream_cipher.ciphertext_C1_C3_C2': bytesToHex(encA.bytes),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.kdf_input': bytesToHex(decA.kdfInput),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.K': bytesToHex(decA.K),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.K1': bytesToHex(decA.K1),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.M': bytesToHex(decA.message),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.K2': bytesToHex(decA.K2),
  'annex_D_encryption.mode_a_kdf_stream_cipher.decrypt.u': bytesToHex(decA.u),

  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.klen_bits': encB.klenBits,
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.kdf_input': bytesToHex(encB.kdfInput),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.K': bytesToHex(encB.K),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.K1_sm4_key': bytesToHex(encB.K1),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.M_padded': bytesToHex(encB.paddedMessage!),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.C2': bytesToHex(encB.C2),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.K2': bytesToHex(encB.K2),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.C3': bytesToHex(encB.C3),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.ciphertext_C1_C3_C2': bytesToHex(encB.bytes),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.kdf_input': bytesToHex(decB.kdfInput),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.K': bytesToHex(decB.K),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.K1': bytesToHex(decB.K1),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.M_padded': bytesToHex(decB.paddedMessage!),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.K2': bytesToHex(decB.K2),
  'annex_D_encryption.mode_b_sm4_cbc_block_cipher.decrypt.u': bytesToHex(decB.u),
};

// ---------------------------------------------------------------------------
// SM4, verified before Annex D mode b) leans on it
// ---------------------------------------------------------------------------

describe('SM4 (GB/T 32907-2016 Appendix A.1), verified before Annex D mode b) uses it', () => {
  const key = hexToBytes(hexOf('sm4_known_answer.key'));
  const plaintext = hexToBytes(hexOf('sm4_known_answer.plaintext'));
  const zeroIv = new Uint8Array(16);

  it('reproduces the single-block known answer', () => {
    expect(bytesToHex(new SM4(key).encrypt(plaintext))).toBe(hexOf('sm4_known_answer.ciphertext_1_round'));
  });

  it('inverts the single-block known answer', () => {
    const ct = hexToBytes(hexOf('sm4_known_answer.ciphertext_1_round'));
    expect(bytesToHex(new SM4(key).decrypt(ct))).toBe(bytesToHex(plaintext));
  });

  it('reproduces the 1,000,000-round known answer', () => {
    const cipher = new SM4(key);
    let block: Uint8Array = plaintext;
    for (let i = 0; i < 1_000_000; i++) block = Uint8Array.from(cipher.encrypt(block));
    expect(bytesToHex(block)).toBe(hexOf('sm4_known_answer.ciphertext_1000000_rounds'));
  }, 600_000);

  it('CBC with an all-zero IV agrees with the raw cipher on the first block', () => {
    const out = encryptCBC(key, plaintext, zeroIv);
    expect(bytesToHex(Uint8Array.from(out).subarray(0, 16))).toBe(hexOf('sm4_known_answer.ciphertext_1_round'));
  });

  it('CBC round-trips two blocks', () => {
    const two = concatBytes(plaintext, plaintext);
    const back = decryptCBC(key, encryptCBC(key, two, zeroIv), zeroIv);
    expect(bytesToHex(Uint8Array.from(back))).toBe(bytesToHex(two));
  });

  it('NEGATIVE CONTROL: one flipped key bit changes the ciphertext', () => {
    const otherKey = Uint8Array.from(key);
    otherKey[15] ^= 1;
    expect(bytesToHex(new SM4(otherKey).encrypt(plaintext)))
      .not.toBe(hexOf('sm4_known_answer.ciphertext_1_round'));
  });
});

// ---------------------------------------------------------------------------
// the annexes, value by value
// ---------------------------------------------------------------------------

describe('GM/T 0044.5 Annex C — key encapsulation, clause 6', () => {
  it.each(Object.keys(ANNEX_C_COMPUTED))('reproduces %s', (path) => {
    assertMatches(ANNEX_C_COMPUTED[path], expected(path));
  });

  it("decapsulation reaches the key that was encapsulated", () => {
    expect(compareKemKeys(cEncap.K, cDecap)).toEqual({
      agreed: true,
      silentDivergence: false,
      note: 'the decapsulated key matches',
    });
  });
});

describe('GM/T 0044.5 Annex D — public key encryption, clause 7, both modes', () => {
  it.each(Object.keys(ANNEX_D_COMPUTED))('reproduces %s', (path) => {
    assertMatches(ANNEX_D_COMPUTED[path], expected(path));
  });

  it('mode a) recovers the annex message', () => {
    expect(new TextDecoder().decode(decA.message)).toBe(str('annex_D_encryption.message_ascii'));
  });

  it('mode b) recovers the annex message once the padding is removed', () => {
    expect(new TextDecoder().decode(decB.message)).toBe(str('annex_D_encryption.message_ascii'));
  });

  it("mode b) pads a 20-byte message with 12 bytes of 0x0c, as the annex's own padding note says", () => {
    const padded = padForBlockCipher(dMessage, 16);
    expect(padded.length).toBe(32);
    expect(bytesToHex(padded.subarray(20))).toBe('0c'.repeat(12));
    const stripped = stripBlockCipherPadding(padded, 16);
    expect(stripped.ok && bytesToHex(stripped.message)).toBe(bytesToHex(dMessage));
  });
});

describe('fixture coverage — no value in the annexes is left unasserted', () => {
  it('every value node under annex_C_kem is asserted above', () => {
    const missing = valueNodePaths('annex_C_kem').filter((p) => !(p in ANNEX_C_COMPUTED));
    expect(missing).toEqual([]);
  });

  it('every value node under annex_D_encryption is asserted above', () => {
    const missing = valueNodePaths('annex_D_encryption').filter((p) => !(p in ANNEX_D_COMPUTED));
    expect(missing).toEqual([]);
  });

  it('reports how many annex values were reproduced', () => {
    const total = Object.keys(ANNEX_C_COMPUTED).length + Object.keys(ANNEX_D_COMPUTED).length;
    // eslint-disable-next-line no-console
    console.log(
      `annex values reproduced: ${Object.keys(ANNEX_C_COMPUTED).length} (Annex C) `
      + `+ ${Object.keys(ANNEX_D_COMPUTED).length} (Annex D) = ${total}`,
    );
    expect(total).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// the failure direction — the two mechanisms fail differently, on purpose
// ---------------------------------------------------------------------------

describe('failure direction: the KEM fails silently, public key encryption fails closed', () => {
  // A second legitimate user, so the "wrong key" is a real key rather than junk.
  const alice = extractEncryptionKey(cKe, new TextEncoder().encode('Alice'), cHid);

  it('KEM: decapsulating with a DIFFERENT user private key reports success', () => {
    const wrong = kemDecapsulate(cEncap.CBytes, cId, alice.deB, cKlen);
    expect(wrong.ok).toBe(true);
  });

  it('KEM: and the key it produces is a different key', () => {
    const wrong = kemDecapsulate(cEncap.CBytes, cId, alice.deB, cKlen);
    expect(wrong.ok && bytesToHex(wrong.K)).not.toBe(bytesToHex(cEncap.K));
  });

  it('KEM: compareKemKeys is what names that as a silent divergence', () => {
    const wrong = kemDecapsulate(cEncap.CBytes, cId, alice.deB, cKlen);
    const verdict = compareKemKeys(cEncap.K, wrong);
    expect(verdict.agreed).toBe(false);
    expect(verdict.silentDivergence).toBe(true);
  });

  it("KEM: w' under the wrong key differs from w, so nothing downstream can agree", () => {
    const wrong = kemDecapsulate(cEncap.CBytes, cId, alice.deB, cKlen);
    expect(wrong.ok && bytesToHex(wrong.wBytes)).not.toBe(bytesToHex(cEncap.wBytes));
  });

  it('KEM: a successful decapsulation still reports integrityChecked false', () => {
    expect(cDecap.ok && cDecap.integrityChecked).toBe(false);
  });

  it('KEM B1: a C moved off the curve is rejected as C_NOT_ON_CURVE', () => {
    const tampered = Uint8Array.from(cEncap.CBytes);
    tampered[63] ^= 1;
    const out = kemDecapsulate(tampered, cId, cKey.deB, cKlen);
    expect(out.ok).toBe(false);
    expect(!out.ok && [out.step, out.cause]).toEqual(['B1', 'C_NOT_ON_CURVE']);
  });

  it('KEM B1: a C of the wrong length is rejected as C_MALFORMED, not decoded anyway', () => {
    const out = kemDecapsulate(cEncap.CBytes.subarray(0, 63), cId, cKey.deB, cKlen);
    expect(!out.ok && [out.step, out.cause]).toEqual(['B1', 'C_MALFORMED']);
  });

  it('KEM B1: a non-canonical coordinate (x >= q) is rejected rather than reduced', () => {
    const out = kemDecapsulate(new Uint8Array(64).fill(0xff), cId, cKey.deB, cKlen);
    expect(!out.ok && [out.step, out.cause]).toEqual(['B1', 'C_COORDINATE_OUT_OF_RANGE']);
  });

  it('G1 membership: the identity is excluded, though the engine calls it on-curve', () => {
    const identity = point_new() as G1Point;
    expect(identity.Z).toBe(0n);
    expect(isInG1(identity)).toBe(false);
    expect(isInG1(toAffineG1(cEncap.C))).toBe(true);
  });

  // The annex fixture's own negative cases, driven from the fixture rather than
  // restated here, so the expected step is the one that file records.
  const negatives = at('annex_D_encryption.negative_fixtures') as { name: string; expect_reject_at: string }[];
  const bitFlips = negatives.filter((n) => /bit flipped/.test(n.name));

  it.each(bitFlips)('$name is rejected at $expect_reject_at', ({ name, expect_reject_at }) => {
    const mode: CipherMode = name.startsWith('mode-a') ? 'a' : 'b';
    const source = mode === 'a' ? encA : encB;
    const byte = Number(/byte (\d+)/.exec(name)![1]);
    const tampered = Uint8Array.from(source.bytes);
    tampered[byte] ^= 1;
    const out = decrypt(tampered, dId, dKey.deB, { mode, k1LenBits: dK1Len, k2LenBits: dK2Len });
    expect(out.ok).toBe(false);
    expect(!out.ok && out.step).toBe(expect_reject_at);
    // The two rejections are DIFFERENT events and are reported as such.
    expect(!out.ok && out.cause).toBe(expect_reject_at === 'B1' ? 'C1_NOT_ON_CURVE' : 'MAC_MISMATCH');
  });

  it('a C1 replaced by a VALID point from a different r passes B1 and is caught only at B4', () => {
    // The case a bit flip cannot reach: this C1 really is on the curve, so the
    // membership test has nothing to object to and the MAC is the only check left.
    const otherR = (dR + 12345n) % N;
    const forgedC1 = mulG1(otherR, dQ.Qb);
    expect(isInG1(forgedC1)).toBe(true);
    const forged = concatBytes(g1ToBytes(forgedC1), encA.C3, encA.C2);
    expect(admitG1(forged.subarray(0, 64)).ok).toBe(true);
    const out = decrypt(forged, dId, dKey.deB, { mode: 'a', k1LenBits: dK1Len, k2LenBits: dK2Len });
    expect(!out.ok && [out.step, out.cause]).toEqual(['B4', 'MAC_MISMATCH']);
  });

  it('decrypting under a different user private key is rejected at B4', () => {
    const out = decrypt(encA.bytes, dId, alice.deB, { mode: 'a', k1LenBits: dK1Len, k2LenBits: dK2Len });
    expect(!out.ok && [out.step, out.cause]).toEqual(['B4', 'MAC_MISMATCH']);
  });

  it('THE DISTINCTION: the same wrong key is silent for the KEM and fatal for encryption', () => {
    const kem = kemDecapsulate(cEncap.CBytes, cId, alice.deB, cKlen);
    const pke = decrypt(encA.bytes, dId, alice.deB, { mode: 'a', k1LenBits: dK1Len, k2LenBits: dK2Len });
    expect(kem.ok).toBe(true);
    expect(pke.ok).toBe(false);
    expect(!pke.ok && pke.cause).toBe('MAC_MISMATCH');
  });

  it('a truncated ciphertext is rejected as CIPHERTEXT_TRUNCATED, before any pairing', () => {
    const out = decrypt(encA.bytes.subarray(0, 90), dId, dKey.deB, { mode: 'a' });
    expect(!out.ok && [out.step, out.cause]).toEqual(['B1', 'CIPHERTEXT_TRUNCATED']);
  });

  it('mode b) rejects a C2 that is not a whole number of SM4 blocks', () => {
    const short = encB.bytes.subarray(0, encB.bytes.length - 1);
    const out = decrypt(short, dId, dKey.deB, { mode: 'b', k1LenBits: dK1Len, k2LenBits: dK2Len });
    expect(!out.ok && [out.step, out.cause]).toEqual(['B3', 'C2_NOT_BLOCK_ALIGNED']);
  });

  it('MAC(K2, Z) is SM3(Z || K2): the swapped order does not reproduce the annex C3', () => {
    expect(bytesToHex(mac(encA.K2, encA.C2)))
      .toBe(norm(expected('annex_D_encryption.mode_a_kdf_stream_cipher.C3')));
    expect(bytesToHex(sm3(concatBytes(encA.K2, encA.C2))))
      .not.toBe(norm(expected('annex_D_encryption.mode_a_kdf_stream_cipher.C3')));
  });

  it('a wrong MAC argument order would still round-trip, which is why the annex is the test', () => {
    // Both orders are a 32-byte digest of the same two strings, so an
    // implementation that swaps them verifies its own ciphertexts perfectly.
    const swapped = sm3(concatBytes(encA.K2, encA.C2));
    expect(swapped.length).toBe(32);
    expect(bytesToHex(swapped)).not.toBe(bytesToHex(encA.C3));
  });
});

// ---------------------------------------------------------------------------
// the engine hazards, pinned on the raw engine rather than asserted in prose
// ---------------------------------------------------------------------------

describe('engine hazards: what this module is containing', () => {
  /** The same point in Jacobian coordinates: (X*l^2, Y*l^3, l). */
  function rescale(p: G1Point, lambda: bigint): G1Point {
    const a = toAffineG1(p);
    const l2 = (lambda * lambda) % Q;
    const l3 = (l2 * lambda) % Q;
    return { X: (a.X * l2) % Q, Y: (a.Y * l3) % Q, Z: lambda };
  }

  it('HAZARD 1a: point_mul returns a Jacobian point, and serialising it raw gives an off-curve x||y', () => {
    const raw = point_new();
    point_mul(raw, cR, toAffineG1(cEncap.Qb)); // exactly step A3, with no normalisation after it
    expect((raw as G1Point).Z).not.toBe(1n);
    expect(point_is_on_curve(raw)).toBe(true); // the POINT is fine; its X and Y are not its x and y

    const rawBytes = hexToBytes(hex32((raw as G1Point).X) + hex32((raw as G1Point).Y));
    const admitted = admitG1(rawBytes);
    expect(!admitted.ok && admitted.cause).toBe('NOT_ON_CURVE');

    // Normalised, the same computation is the annex's C.
    expect(bytesToHex(g1ToBytes(raw as G1Point)))
      .toBe(norm(expected('annex_C_kem.encapsulate.A3_C_x')) as string
        + (norm(expected('annex_C_kem.encapsulate.A3_C_y')) as string));
  });

  it('HAZARD 1b: point_add ignores its second operand\'s Z, so a Jacobian Ppub-e gives a wrong Q_B', () => {
    const jacobianPpube = rescale(cPpube, 7n);
    expect(point_is_on_curve(jacobianPpube)).toBe(true); // a legitimate representation of the same point

    const h1P1 = point_new();
    point_mul(h1P1, cQ.h1, toAffineG1(SM9_P1 as G1Point));
    const wrong = point_new();
    point_add(wrong, h1P1, jacobianPpube); // the composition the engine silently mishandles
    const right = point_new();
    point_add(right, h1P1, toAffineG1(jacobianPpube));

    expect(bytesToHex(g1ToBytes(right as G1Point))).toBe(bytesToHex(g1ToBytes(cEncap.Qb)));
    expect(bytesToHex(g1ToBytes(wrong as G1Point))).not.toBe(bytesToHex(g1ToBytes(cEncap.Qb)));
  });

  it('HAZARD 2: the annex prints the Fp12 tower descending, the engine stores it ascending', () => {
    const f = cEncap.g as unknown as bigint[][][];
    const ascending: string[] = [];
    for (let i = 0; i < 3; i++) for (let j = 0; j < 2; j++) for (let k = 0; k < 2; k++) ascending.push(hex32(f[i][j][k]));

    expect(bytesToHex(fp12ToBytes(cEncap.g))).toBe(norm(expected('annex_C_kem.encapsulate.A4_g')));
    expect(ascending.join('')).not.toBe(norm(expected('annex_C_kem.encapsulate.A4_g')));
    // Both are 384 bytes of the same twelve coefficients, so only the annex can tell them apart.
    expect(ascending.join('').length).toBe(bytesToHex(fp12ToBytes(cEncap.g)).length);
  });

  it('HAZARD 3: fp12_pow reduces its exponent mod q, the field characteristic, not mod N', () => {
    const g = pairingBase(cPpube);
    const base = fp12_new();
    fp12_pow(base, g, cR);
    const plusQ = fp12_new();
    fp12_pow(plusQ, g, cR + (SM9_P as bigint));
    const plusN = fp12_new();
    fp12_pow(plusN, g, cR + N);

    // g has order N, so mathematically g^(r+N) = g^r. The engine disagrees,
    // because it reduces by q instead — which is why every r is range-checked
    // before it gets here rather than trusted to wrap.
    expect(bytesToHex(fp12ToBytes(plusQ))).toBe(bytesToHex(fp12ToBytes(base)));
    expect(bytesToHex(fp12ToBytes(plusN))).not.toBe(bytesToHex(fp12ToBytes(base)));
  });

  it('HAZARD 3: an out-of-range r is refused rather than silently reduced', () => {
    expect(() => kemEncapsulate(cId, cHid, cPpube, cKlen, { r: N })).toThrow(/\[1, N-1\]/);
    expect(() => kemEncapsulate(cId, cHid, cPpube, cKlen, { r: 0n })).toThrow(/\[1, N-1\]/);
    expect(() => encrypt(dMessage, dId, dHid, dPpube, { r: N + 1n })).toThrow(/\[1, N-1\]/);
  });
});

// ---------------------------------------------------------------------------
// round trips with a drawn r, so nothing above depends on the pinned one
// ---------------------------------------------------------------------------

describe('round trips with a freshly drawn r', () => {
  it('KEM: encapsulate then decapsulate agrees on K', () => {
    const encapsulated = kemEncapsulate(cId, cHid, cPpube, 256);
    expect(encapsulated.r).not.toBe(cR);
    const decapsulated = kemDecapsulate(encapsulated.CBytes, cId, cKey.deB, 256);
    expect(compareKemKeys(encapsulated.K, decapsulated).agreed).toBe(true);
  });

  it.each<CipherMode>(['a', 'b'])('mode %s: encrypt then decrypt returns the message', (mode) => {
    const message = new TextEncoder().encode('one concept per demo, and this is the KEM/DEM split');
    const ct = encrypt(message, dId, dHid, dPpube, { mode });
    const out = decrypt(ct.bytes, dId, dKey.deB, { mode });
    expect(out.ok && bytesToHex(out.message)).toBe(bytesToHex(message));
  });

  it('mode b) handles a message that is already a whole number of blocks', () => {
    // The padding is a full extra block here, which is the case that makes the
    // scheme unambiguous and the case a naive "pad only if needed" gets wrong.
    const message = new TextEncoder().encode('sixteen bytes!!!');
    expect(message.length % 16).toBe(0);
    const ct = encrypt(message, dId, dHid, dPpube, { mode: 'b' });
    expect(ct.paddedMessage!.length).toBe(32);
    const out = decrypt(ct.bytes, dId, dKey.deB, { mode: 'b' });
    expect(out.ok && bytesToHex(out.message)).toBe(bytesToHex(message));
  });

  it('the encryption hid is the annexes\' 0x03', () => {
    expect(cHid).toBe(HID.ENCRYPT);
    expect(dHid).toBe(HID.ENCRYPT);
  });
});
