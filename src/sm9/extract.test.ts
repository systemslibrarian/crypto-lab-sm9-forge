/**
 * Key extraction against the standard's own worked examples.
 *
 * Both sides are pinned, because they are mirror images and a mirror image is
 * exactly the kind of thing that can be built backwards without anything
 * complaining:
 *   GM/T 0044.5 Annex A  signature  Ppub-s in G2, ds_A in G1
 *   GM/T 0044.5 Annex C  encryption Ppub-e in G1, de_B in G2
 *
 * Every intermediate the annexes print is checked, not just the final key. That
 * is not thoroughness for its own sake: sign.test.ts demonstrates that a wrong
 * H1 produces a signature which verifies perfectly, so these pinned h1/t1/t2
 * values are the ONLY thing in the lab that can catch one.
 */
import { describe, expect, it } from 'vitest';
import {
  SM9_P1,
  SM9_P2,
  point_is_on_curve,
  twist_point_is_on_curve,
} from '../vendor/gmssl-sm9.js';
import { HID, N, Q } from './params';
import { mod, mul } from './fn';
import { bytesToHex } from './hash';
import {
  encodeIdentity,
  mulG1,
  mulG2,
  encryptMasterKeyPair,
  extractEncryptKey,
  extractSignKey,
  fp2Components,
  generatorP1,
  generatorP2,
  identityHashH1,
  masterKeyForcingT1Zero,
  signMasterKeyPair,
  toFieldHex,
} from './extract';
import annexA from './fixtures/annexA-fixture.json';
import annexCD from './fixtures/sm9-annex-cd-fixtures.json';

const A = annexA.signature;
const C = annexCD.annex_C_kem;

/**
 * The annexes strip leading zeros from scalars, so scalar text is parsed as an
 * INTEGER and never length-compared. annexA-fixture.json records the caveat as
 * `annex-strips-leading-zeros`; annex C's ke is a live instance of it.
 */
const asScalar = (hex: string): bigint => BigInt('0x' + hex);

describe('component-order conventions, pinned against the engine and the annex', () => {
  const engineP1 = SM9_P1 as { X: bigint; Y: bigint; Z: bigint };
  const engineP2 = SM9_P2 as { X: bigint[]; Y: bigint[]; Z: bigint[] };

  it('generatorP1() built from params.ts is the engine\'s own P1', () => {
    expect(generatorP1()).toEqual({ X: engineP1.X, Y: engineP1.Y, Z: 1n });
  });

  it('generatorP2() maps params.ts hi/lo onto the engine\'s [c0, c1] correctly', () => {
    // params.ts names the components hi/lo and the engine indexes them 0/1.
    // That is a mapping between two other people's naming choices, so it is
    // pinned here rather than reasoned about.
    const built = generatorP2();
    expect(built.X).toEqual(engineP2.X);
    expect(built.Y).toEqual(engineP2.Y);
    expect(built.Z).toEqual([1n, 0n]);
  });

  it('fp2Components() reproduces the annex\'s printed (c1, c0) order for P2', () => {
    expect(fp2Components(generatorP2().X)).toEqual(annexA.curve.P2.x);
    expect(fp2Components(generatorP2().Y)).toEqual(annexA.curve.P2.y);
  });

  it('NEGATIVE CONTROL: without the Fp2 swap the same comparison must fail', () => {
    // Engine hazard (2). If this ever passes, the swap has become a no-op and
    // every Fp2 check above is passing vacuously.
    const unswapped = generatorP2().X.map(toFieldHex);
    expect(unswapped).not.toEqual(annexA.curve.P2.x);
  });

  it('generatorP1 matches the annex\'s printed P1 coordinates', () => {
    expect(toFieldHex(generatorP1().X)).toBe(annexA.curve.P1.x);
    expect(toFieldHex(generatorP1().Y)).toBe(annexA.curve.P1.y);
  });
});

describe('GM/T 0044.5 Annex A: signature master key and ds_A, every intermediate', () => {
  const ks = asScalar(A.ks);
  const master = signMasterKeyPair(ks);
  const outcome = extractSignKey(master, A.identity.ascii, { hid: Number('0x' + A.hid) });

  it('the annex declares hid = 0x01 for signature keys, matching params.HID.SIGN', () => {
    expect(Number('0x' + A.hid)).toBe(HID.SIGN);
  });

  it('Ppub-s = [ks]P2, both Fp2 coordinates', () => {
    expect(fp2Components(master.Ppubs.X)).toEqual(A.Ppubs.x);
    expect(fp2Components(master.Ppubs.Y)).toEqual(A.Ppubs.y);
  });

  it('Ppub-s lies on the twist', () => {
    expect(twist_point_is_on_curve(master.Ppubs)).toBe(true);
  });

  it('ID_A || hid is the octet string the annex prints', () => {
    expect(bytesToHex(encodeIdentity(A.identity.ascii, HID.SIGN))).toBe(A.id_bar_hid);
    expect(bytesToHex(new TextEncoder().encode(A.identity.ascii))).toBe(A.identity.hex);
  });

  it('extraction succeeds, so the union discriminates to the ok branch', () => {
    expect(outcome.ok).toBe(true);
  });

  it('h1 = H1(ID_A || hid, N)', () => {
    expect(toFieldHex(outcome.h1)).toBe(A.H1);
  });

  it('t1 = h1 + ks mod N', () => {
    expect(toFieldHex(outcome.t1)).toBe(A.t1);
  });

  it('t2 = ks * t1^-1 mod N', () => {
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(toFieldHex(outcome.t2)).toBe(A.t2);
  });

  it('ds_A = [t2]P1, both coordinates, and the point is on the curve', () => {
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(toFieldHex(outcome.dsA.X)).toBe(A.dsA.x);
    expect(toFieldHex(outcome.dsA.Y)).toBe(A.dsA.y);
    expect(point_is_on_curve(outcome.dsA)).toBe(true);
    expect(outcome.dsA.Z).toBe(1n);
  });

  it('t1 * t2 == ks — the identity that makes H1 cancel in verification', () => {
    // Not a restatement of t2's definition for its own sake: this product is
    // what sign.test.ts's cancellation demonstration turns on, and it holds for
    // EVERY value of h1, which is precisely the problem.
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(mul(outcome.t1, outcome.t2)).toBe(mod(ks));
  });

  it('the annex\'s ks is compared as an integer, never as padded hex', () => {
    // annexA-fixture.json's caveat `annex-strips-leading-zeros`: the standard
    // prints ks with leading zeros stripped. The fixture stores it padded; the
    // integer is what both agree on.
    expect(asScalar(A.ks)).toBe(ks);
    expect(toFieldHex(ks)).toBe(A.ks);
    expect(toFieldHex(ks).length).toBe(64);
  });
});

describe('GM/T 0044.5 Annex C: encryption master key and de_B, the mirror image', () => {
  const keHex = C.master_encryption_private_key_ke;
  const ke = asScalar(keHex);
  const master = encryptMasterKeyPair(ke);
  const outcome = extractEncryptKey(master, C.ID_B_ascii, { hid: Number('0x' + C.hid) });

  it('the annex prints ke with leading zeros stripped: 62 nibbles, not 64', () => {
    // The live instance of the caveat. A byte-for-byte string comparison here
    // fails while the value is perfectly correct, which is why every scalar in
    // this suite is parsed with asScalar().
    expect(keHex.length).toBe(62);
    expect(toFieldHex(ke).length).toBe(64);
    expect(toFieldHex(ke).endsWith(keHex)).toBe(true);
  });

  it('the annex declares hid = 0x03 for encryption keys, matching params.HID.ENCRYPT', () => {
    expect(Number('0x' + C.hid)).toBe(HID.ENCRYPT);
    expect(bytesToHex(encodeIdentity(C.ID_B_ascii, HID.ENCRYPT))).toBe(C.ID_B_with_hid);
  });

  it('Ppub-e = [ke]P1 lands in G1 — the OTHER group from the signature side', () => {
    expect(toFieldHex(master.Ppube.X)).toBe(C.Ppub_e.x.value);
    expect(toFieldHex(master.Ppube.Y)).toBe(C.Ppub_e.y.value);
    expect(point_is_on_curve(master.Ppube)).toBe(true);
  });

  it('h1, t1 and t2 use the identical scalar arithmetic as the signature side', () => {
    expect(toFieldHex(outcome.h1)).toBe(C.key_extraction.H1_ID_hid.value);
    expect(toFieldHex(outcome.t1)).toBe(C.key_extraction.t1.value);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(toFieldHex(outcome.t2)).toBe(C.key_extraction.t2.value);
  });

  it('de_B = [t2]P2 lands in G2, both Fp2 coordinates, on the twist', () => {
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(fp2Components(outcome.deB.X).join('')).toBe(C.key_extraction.de_B_x.value);
    expect(fp2Components(outcome.deB.Y).join('')).toBe(C.key_extraction.de_B_y.value);
    expect(twist_point_is_on_curve(outcome.deB)).toBe(true);
  });
});

describe('the t1 == 0 branch of clause 5.3 step A3, actually entered', () => {
  // GM/T 0044.2 clause 5.3: "if t1 = 0, regenerate the master key pair, ...
  // update the master public key and re-issue every user's private key". A real
  // KGC meets this with probability about 2^-256, so the branch is only
  // reachable by solving for the master key that triggers it: ks = -H1(ID||hid).
  const identity = 'Alice';

  it('the signature side returns the typed outcome instead of throwing', () => {
    const ks = masterKeyForcingT1Zero(identity, HID.SIGN);
    const outcome = extractSignKey(signMasterKeyPair(ks), identity);

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.outcome).toBe('MASTER-KEY-REGENERATION-REQUIRED');
    expect(outcome.t1).toBe(0n);
    expect(outcome.t2).toBeNull();
    expect(outcome.reason).toContain('regenerate the master key pair');
    // The intermediates still come back: the page can show WHY it collapsed.
    expect(outcome.h1).toBe(identityHashH1(encodeIdentity(identity, HID.SIGN)));
    expect(mod(outcome.h1 + ks)).toBe(0n);
  });

  it('the encryption side returns the same typed outcome', () => {
    const ke = masterKeyForcingT1Zero(identity, HID.ENCRYPT);
    const outcome = extractEncryptKey(encryptMasterKeyPair(ke), identity);

    expect(outcome.ok).toBe(false);
    if (outcome.ok) return;
    expect(outcome.outcome).toBe('MASTER-KEY-REGENERATION-REQUIRED');
    expect(outcome.t1).toBe(0n);
    expect(outcome.t2).toBeNull();
  });

  it('the forcing master key is itself a legal master key, so nothing is special-cased', () => {
    const ks = masterKeyForcingT1Zero(identity, HID.SIGN);
    expect(ks >= 1n && ks <= N - 1n).toBe(true);
    // It only collapses for THIS identity; every other identity extracts fine.
    const other = extractSignKey(signMasterKeyPair(ks), 'Bob');
    expect(other.ok).toBe(true);
  });

  it('the collapse follows the hid, not just the identity string', () => {
    // ks solved for hid 0x01 does not collapse the same identity under hid 0x03,
    // because hid is inside the hashed octet string.
    const ks = masterKeyForcingT1Zero(identity, HID.SIGN);
    const under3 = extractSignKey(signMasterKeyPair(ks), identity, { hid: HID.ENCRYPT });
    expect(under3.ok).toBe(true);
  });
});

describe('engine hazard (1): a Jacobian base must not silently corrupt the result', () => {
  // point_mul feeds its base to point_add as the SECOND operand, which reads it
  // as affine and ignores Z. A caller handing in a Jacobian point therefore gets
  // an off-curve answer with nothing thrown. MEASURED, against the raw engine
  // with the guard bypassed: the same point in Jacobian form produced a
  // DIFFERENT x and point_is_on_curve() returned false. mulG1/mulG2 normalise
  // the base, and this is the test that says so rather than the comment that
  // claims it.
  //
  // A Jacobian representation of the SAME point, with lambda = 2:
  //   (X, Y, Z) -> (X*lambda^2, Y*lambda^3, Z*lambda)
  // lambda is taken from the base field, so on the twist it scales each Fp2
  // component independently and needs no Fp2 multiplication here.
  const modQ = (x: bigint): bigint => ((x % Q) + Q) % Q;
  const k = 0x1234_5678_9abc_def0n;

  it('G1: the same point in Jacobian form gives the same [k]P', () => {
    const affine = generatorP1();
    const jacobian = {
      X: modQ(affine.X * 4n),
      Y: modQ(affine.Y * 8n),
      Z: 2n,
    };
    expect(jacobian.Z).not.toBe(1n);
    expect(mulG1(k, jacobian)).toEqual(mulG1(k, affine));
  });

  it('G2: the same twist point in Jacobian form gives the same [k]P', () => {
    const affine = generatorP2();
    const jacobian = {
      X: affine.X.map((c) => modQ(c * 4n)),
      Y: affine.Y.map((c) => modQ(c * 8n)),
      Z: [2n, 0n],
    };
    expect(jacobian.Z).not.toEqual([1n, 0n]);
    expect(mulG2(k, jacobian)).toEqual(mulG2(k, affine));
  });

  it('every point this module returns is already affine, so the guard costs nothing', () => {
    const master = signMasterKeyPair(asScalar(A.ks));
    const outcome = extractSignKey(master, A.identity.ascii);
    expect(master.Ppubs.Z).toEqual([1n, 0n]);
    expect(outcome.ok).toBe(true);
    if (!outcome.ok) return;
    expect(outcome.dsA.Z).toBe(1n);
  });
});

describe('input validation the engine does not do for us', () => {
  it('a master key outside [1, N-1] is refused on both sides', () => {
    expect(() => signMasterKeyPair(0n)).toThrow(RangeError);
    expect(() => signMasterKeyPair(N)).toThrow(RangeError);
    expect(() => encryptMasterKeyPair(0n)).toThrow(RangeError);
    expect(() => encryptMasterKeyPair(N + 1n)).toThrow(RangeError);
  });

  it('encodeIdentity accepts bytes and strings identically', () => {
    const asString = encodeIdentity('Alice', HID.SIGN);
    const asBytes = encodeIdentity(new TextEncoder().encode('Alice'), HID.SIGN);
    expect(bytesToHex(asBytes)).toBe(bytesToHex(asString));
  });

  it('encodeIdentity refuses an hid that is not one byte', () => {
    expect(() => encodeIdentity('Alice', 256)).toThrow(RangeError);
    expect(() => encodeIdentity(new TextEncoder().encode('Alice'), -1)).toThrow(RangeError);
  });
});
