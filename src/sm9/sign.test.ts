/**
 * The SM9 signature algorithm against GM/T 0044.5 Annex A, plus the lab's
 * headline negative claim.
 *
 * EVERY printed intermediate is checked, not the final (h, S) pair alone, and
 * the last describe block in this file is the reason why: a signature produced
 * under a WRONG H1 verifies perfectly. A suite that only round-tripped would be
 * green on an implementation whose identity hash is wrong in every bit.
 */
import { describe, expect, it } from 'vitest';
import { N, Q, HID } from './params';
import { mod, mul } from './fn';
import { H2, bytesToHex, concatBytes, hexToBytes } from './hash';
import {
  encodeIdentity,
  extractSignKey,
  fp2Components,
  identityHashH1,
  signMasterKeyPair,
  toFieldHex,
} from './extract';
import type { IdentityHash, SignKeyExtraction } from './extract';
import type { G1Point, Gt } from './pairing';
import { fp12Components, sign, signatureToHex, verify } from './sign';
import type { Sm9Signature } from './sign';
import annexA from './fixtures/annexA-fixture.json';

const A = annexA.signature;
const V = A.verify;

const asScalar = (hex: string): bigint => BigInt('0x' + hex);
const utf8 = (s: string): Uint8Array => new TextEncoder().encode(s);

/** A step that must have been reached. Reads better than `!` and checks more. */
function reached<T>(value: T | undefined, name: string): T {
  if (value === undefined) throw new Error(`verification never reached ${name}`);
  return value;
}

// ------------------------------------------------------------ the annex's run
const ks = asScalar(A.ks);
const master = signMasterKeyPair(ks);
const identity = A.identity.ascii;
const message = utf8(A.message.ascii);
const pinnedR = asScalar(A.r);

const extraction = extractSignKey(master, identity, { hid: HID.SIGN });
if (!extraction.ok) throw new Error('Annex A extraction collapsed; extract.test.ts covers why');
const annexKey: SignKeyExtraction = extraction;

/** The annex pins r, so this run is deterministic and reproducible line by line. */
const signed = sign(message, annexKey.dsA, master.Ppubs, { nonce: () => pinnedR });

describe('GM/T 0044.2 clause 6.1: signature generation, every printed intermediate', () => {
  it('the message is the annex\'s "Chinese IBS standard"', () => {
    expect(bytesToHex(message)).toBe(A.message.hex);
  });

  it('A2: the pinned r is in [1, N-1] and is what the signer used', () => {
    // The engine's fp12_pow reduces its exponent mod p, not mod N, so an
    // out-of-range r would be accepted silently. sign() range-checks it first.
    expect(pinnedR > 0n && pinnedR < N).toBe(true);
    expect(signed.r).toBe(pinnedR);
    expect(signed.attempts).toBe(1);
  });

  it('A1: g = e(P1, Ppub-s), all twelve Fp12 components', () => {
    expect(fp12Components(signed.g)).toEqual(A.g);
  });

  it('A4: w = g^r, all twelve Fp12 components', () => {
    expect(fp12Components(signed.w)).toEqual(A.w);
  });

  it('A5: the octet string M || w, 20 message bytes + 384 pairing bytes', () => {
    expect(signed.messageWithW.length).toBe(20 + 384);
    expect(bytesToHex(signed.messageWithW)).toBe(A.M_bar_w);
  });

  it('A5: h = H2(M || w, N)', () => {
    expect(toFieldHex(signed.h)).toBe(A.h);
  });

  it('A6: l = (r - h) mod N', () => {
    expect(toFieldHex(signed.l)).toBe(A.l);
    expect(signed.l).not.toBe(0n);
  });

  it('A7: S = [l]ds_A, both coordinates', () => {
    expect(toFieldHex(signed.S.X)).toBe(A.S.x);
    expect(toFieldHex(signed.S.Y)).toBe(A.S.y);
  });

  it('the signature (h, S) serialises as the annex prints it', () => {
    const hex = signatureToHex(signed.signature);
    expect(hex.h).toBe(A.h);
    expect(hex.S).toBe(A.sig_S_uncompressed);
  });

  it('NEGATIVE CONTROL: hashing w in the engine\'s storage order gives a different h', () => {
    // Engine hazard (2). The annex prints the 1-2-4-12 tower DESCENDING and the
    // engine stores it ascending. Hashing the engine's order yields a perfectly
    // well-formed h that both halves of a round trip would agree on, and that
    // no annex in the standard contains. If this assertion ever fails,
    // fp12Components() has stopped reversing and every Fp12 check above is
    // comparing the same order to itself.
    const engineOrder = [...fp12Components(signed.w)].reverse().join('');
    const wrongH = H2(concatBytes(message, hexToBytes(engineOrder)), N).h;
    expect(toFieldHex(wrongH)).not.toBe(A.h);
    expect(engineOrder).not.toBe(fp12Components(signed.w).join(''));
  });
});

describe('GM/T 0044.2 clause 7.1: verification, every printed intermediate', () => {
  const result = verify(message, identity, signed.signature, master.Ppubs, { hid: HID.SIGN });

  it('S3: the verifier recomputes the same g the signer used', () => {
    // The annex reprints g in its verification section; the fixture records the
    // signing copy, and the two are the same element by construction.
    expect(fp12Components(reached(result.steps.g, 'g'))).toEqual(A.g);
    expect(fp12Components(reached(result.steps.g, 'g'))).toEqual(fp12Components(signed.g));
  });

  it('S4: t = g^h\', all twelve components', () => {
    expect(fp12Components(reached(result.steps.t, 't'))).toEqual(V.t);
  });

  it('S5: h1 = H1(ID_A || hid, N), reprinted in the verification section', () => {
    expect(toFieldHex(reached(result.steps.h1, 'h1'))).toBe(V.h1);
    // The annex prints the same value in both sections; they must agree.
    expect(V.h1).toBe(A.H1);
  });

  it('S5: P = [h1]P2 + Ppub-s, both Fp2 coordinates', () => {
    const P = reached(result.steps.P, 'P');
    expect(fp2Components(P.X)).toEqual(V.P.x);
    expect(fp2Components(P.Y)).toEqual(V.P.y);
  });

  it('S5: u = e(S\', P), all twelve components', () => {
    expect(fp12Components(reached(result.steps.u, 'u'))).toEqual(V.u);
  });

  it('S5: w\' = u * t recovers the signer\'s w exactly', () => {
    expect(fp12Components(reached(result.steps.wPrime, "w'"))).toEqual(V.w_prime);
    expect(V.w_prime).toEqual(A.w);
  });

  it('S6: the octet string M\' || w\'', () => {
    expect(bytesToHex(reached(result.steps.messageWithWPrime, "M'||w'"))).toBe(V.M_bar_w_prime);
  });

  it('S6: h2 = H2(M\' || w\', N) equals h, so the annex\'s signature VERIFIES', () => {
    expect(toFieldHex(reached(result.steps.h2, 'h2'))).toBe(V.h2);
    expect(result.accepted).toBe(true);
    expect(result.failure).toBeNull();
  });
});

describe('the failure direction: all eight must_reject cases from the annex fixture', () => {
  // Built from the fixture by id, so a case added there and not handled here is
  // a failing test rather than a silent gap.
  const negative: Record<string, () => ReturnType<typeof verify>> = {
    N1: () => {
      const m = Uint8Array.from(message);
      m[m.length - 1] ^= 0x01;
      return verify(m, identity, signed.signature, master.Ppubs);
    },
    N2: () => {
      const m = Uint8Array.from(message);
      m[0] ^= 0x80;
      return verify(m, identity, signed.signature, master.Ppubs);
    },
    N3: () => verify(message, 'Bob', signed.signature, master.Ppubs),
    N4: () => verify(message, 'alice', signed.signature, master.Ppubs),
    N5: () =>
      verify(message, identity, { h: signed.h ^ 1n, S: signed.S }, master.Ppubs),
    N6: () => {
      // x + 1 mod q takes S off the curve without changing its shape.
      const off: G1Point = { X: mod0Q(signed.S.X + 1n), Y: signed.S.Y, Z: 1n };
      return verify(message, identity, { h: signed.h, S: off }, master.Ppubs);
    },
    N7: () => {
      // -S is ON the curve and is the wrong point: only the hash check catches it.
      const neg: G1Point = { X: signed.S.X, Y: mod0Q(Q - signed.S.Y), Z: 1n };
      return verify(message, identity, { h: signed.h, S: neg }, master.Ppubs);
    },
    N8: () => verify(message, identity, { h: 0n, S: signed.S }, master.Ppubs),
  };

  const whyToFailure: Record<string, string> = {
    'h2 != h': 'HASH-MISMATCH',
    'S not on the curve': 'S-NOT-ON-CURVE',
    'h out of [1, N-1]': 'H-OUT-OF-RANGE',
  };

  it('the fixture still declares exactly eight cases', () => {
    expect(annexA.must_reject).toHaveLength(8);
    expect(Object.keys(negative).sort()).toEqual(annexA.must_reject.map((c) => c.id).sort());
  });

  for (const entry of annexA.must_reject) {
    it(`${entry.id}: ${entry.case}`, () => {
      const result = negative[entry.id]();
      expect(result.accepted).toBe(false);
      expect(entry.rejected).toBe(true);
      // Bind the failure taxonomy to the reason the fixture recorded, so a
      // rejection for the WRONG reason is also a failure.
      expect(result.failure).toBe(whyToFailure[entry.why]);
    });
  }

  it('CONTROL: the untampered inputs still ACCEPT on the same code path', () => {
    // Without this every rejection above could be passing vacuously.
    expect(verify(message, identity, signed.signature, master.Ppubs).accepted).toBe(true);
  });

  it('N7\'s -S really is on the curve, so N7 is not N6 in disguise', () => {
    const neg: G1Point = { X: signed.S.X, Y: mod0Q(Q - signed.S.Y), Z: 1n };
    const result = verify(message, identity, { h: signed.h, S: neg }, master.Ppubs);
    expect(result.failure).toBe('HASH-MISMATCH');
  });
});

describe('signing with real randomness, and the nonce seam', () => {
  it('a default-nonce signature verifies, and differs from the annex\'s', () => {
    const fresh = sign(message, annexKey.dsA, master.Ppubs);
    expect(fresh.r).not.toBe(pinnedR);
    expect(verify(message, identity, fresh.signature, master.Ppubs).accepted).toBe(true);
  });

  it('two default-nonce signatures over the same message differ', () => {
    const a = sign(message, annexKey.dsA, master.Ppubs);
    const b = sign(message, annexKey.dsA, master.Ppubs);
    expect(a.signature.h).not.toBe(b.signature.h);
  });

  it('a nonce source returning a scalar outside [1, N-1] is refused', () => {
    expect(() => sign(message, annexKey.dsA, master.Ppubs, { nonce: () => 0n })).toThrow(RangeError);
    expect(() => sign(message, annexKey.dsA, master.Ppubs, { nonce: () => N })).toThrow(RangeError);
  });

  it('the clause 6.1 step A6 restart guard has a reachable failure path', () => {
    // HONEST LIMIT: l == 0 cannot be constructed, because it needs r such that
    // r == H2(M || g^r) -- a fixed point of a hash. The restart itself is
    // therefore unexercised; what is exercised is the guard that stops a
    // deterministic nonce source turning that restart into an infinite loop.
    expect(() =>
      sign(message, annexKey.dsA, master.Ppubs, { nonce: () => pinnedR, maxAttempts: 0 }),
    ).toThrow(/l == 0 on all 0 attempts/);
  });
});

/* ===================================================================== *
 * THE LAB'S HEADLINE NEGATIVE CLAIM (section 4.1d).
 *
 * An SM9 sign -> verify round trip does NOT establish that H1, the identity
 * encoding, or hid is correct.
 *
 * Extraction sets t1 = H1(ID||hid) + ks and t2 = ks * t1^-1, so t1 * t2 == ks
 * for ANY H1. Verification forms P = [H1]P2 + Ppub-s = [t1]P2 and
 * S = [l]ds_A = [l * t2]P1, so
 *       u = e(S, P) = e(P1, P2)^(l * t2 * t1) = e(P1, P2)^(l * ks)
 * and H1 CANCELS. The verification equation never learns which identity was
 * used -- only that extraction and verification used the SAME one.
 *
 * This is not an argument. Each case below runs a complete extraction, signing
 * and verification with a deliberately wrong identity hash and asserts the
 * observable consequences: a DIFFERENT ds_A, the SAME u, the SAME h, and an
 * ACCEPTED signature.
 * ===================================================================== */
describe('a wrong H1 used consistently still verifies — H1 cancels in the equation', () => {
  /**
   * The same hash-to-range construction with the wrong domain prefix. GM/T
   * 0044.4 clauses 5.4.2.2 and 5.4.2.3 define H1 and H2 as ONE function
   * separated by a single leading byte -- 0x01 for H1, 0x02 for H2 -- so using
   * H2 here is exactly "H1 with a wrong domain prefix", not a random number.
   */
  const wrongDomainPrefix: IdentityHash = (idWithHid) => H2(idWithHid, N).h;

  /**
   * The blunt form, to show the cancellation is total rather than approximate:
   * an identity hash that does not read the identity at all.
   */
  const ignoresTheIdentity: IdentityHash = () => 0x2aan;

  const cases: Array<{ name: string; identityHash: IdentityHash }> = [
    { name: 'H1 with a wrong domain prefix (0x02 instead of 0x01)', identityHash: wrongDomainPrefix },
    { name: 'an identity hash that ignores the identity entirely', identityHash: ignoresTheIdentity },
  ];

  /** One complete run of the protocol under a given identity hash. */
  function runUnder(identityHash: IdentityHash): {
    h1: bigint;
    t1: bigint;
    t2: bigint;
    dsA: G1Point;
    signature: Sm9Signature;
    u: Gt;
    accepted: boolean;
  } {
    const extracted = extractSignKey(master, identity, { hid: HID.SIGN, identityHash });
    if (!extracted.ok) throw new Error('extraction collapsed under the injected hash');
    // Signing never touches H1 at all -- that is the structural reason this works.
    const s = sign(message, extracted.dsA, master.Ppubs, { nonce: () => pinnedR });
    const v = verify(message, identity, s.signature, master.Ppubs, { hid: HID.SIGN, identityHash });
    return {
      h1: extracted.h1,
      t1: extracted.t1,
      t2: extracted.t2,
      dsA: extracted.dsA,
      signature: s.signature,
      u: reached(v.steps.u, 'u'),
      accepted: v.accepted,
    };
  }

  const good = runUnder(identityHashH1);

  it('CONTROL: the correct H1 reproduces the annex and accepts', () => {
    // Everything below is a comparison against this run, so it must be the
    // annex's own run and not merely self-consistent.
    expect(toFieldHex(good.h1)).toBe(A.H1);
    expect(toFieldHex(good.dsA.X)).toBe(A.dsA.x);
    expect(fp12Components(good.u)).toEqual(V.u);
    expect(good.accepted).toBe(true);
  });

  for (const { name, identityHash } of cases) {
    describe(name, () => {
      const bad = runUnder(identityHash);

      it('produces a DIFFERENT user private key ds_A', () => {
        expect(bad.h1).not.toBe(good.h1);
        expect(bad.t1).not.toBe(good.t1);
        expect(bad.t2).not.toBe(good.t2);
        expect(toFieldHex(bad.dsA.X)).not.toBe(toFieldHex(good.dsA.X));
      });

      it('produces the SAME pairing value u — this is the cancellation itself', () => {
        expect(fp12Components(bad.u)).toEqual(fp12Components(good.u));
        // And therefore the annex's own pinned u, from a key the annex never issued.
        expect(fp12Components(bad.u)).toEqual(V.u);
      });

      it('produces the SAME signature component h', () => {
        expect(bad.signature.h).toBe(good.signature.h);
        expect(toFieldHex(bad.signature.h)).toBe(A.h);
      });

      it('AND VERIFIES — the round trip reports success on a wrong H1', () => {
        expect(bad.accepted).toBe(true);
      });

      it('t1 * t2 == ks holds here too, which is WHY it cancels', () => {
        expect(mul(bad.t1, bad.t2)).toBe(mod(ks));
        expect(mul(good.t1, good.t2)).toBe(mod(ks));
      });

      it('only the annex\'s PINNED intermediates catch it', () => {
        // The whole consequence for the lab, stated as an assertion: the pinned
        // values disagree while the round trip does not.
        expect(toFieldHex(bad.h1)).not.toBe(A.H1);
        expect(toFieldHex(bad.t1)).not.toBe(A.t1);
        expect(toFieldHex(bad.t2)).not.toBe(A.t2);
        expect(toFieldHex(bad.dsA.X)).not.toBe(A.dsA.x);
        expect(bad.accepted).toBe(true);
      });
    });
  }

  it('the same freedom applies to hid: a wrong hid used on both sides verifies', () => {
    // hid is inside the octet string H1 consumes, so a wrong hid is a wrong H1
    // value by another route, and cancels identically.
    const wrongHid = 0x7f;
    const extracted = extractSignKey(master, identity, { hid: wrongHid });
    if (!extracted.ok) throw new Error('extraction collapsed');
    expect(bytesToHex(encodeIdentity(identity, wrongHid))).not.toBe(A.id_bar_hid);
    const s = sign(message, extracted.dsA, master.Ppubs, { nonce: () => pinnedR });
    expect(verify(message, identity, s.signature, master.Ppubs, { hid: wrongHid }).accepted).toBe(true);
    expect(toFieldHex(extracted.h1)).not.toBe(A.H1);
  });

  it('the two sides must still AGREE: a mismatch between them is rejected', () => {
    // The claim is that H1\'s VALUE is unconstrained, not that the two sides are
    // independent. Extract under the wrong hash, verify under the right one.
    const extracted = extractSignKey(master, identity, {
      hid: HID.SIGN,
      identityHash: wrongDomainPrefix,
    });
    if (!extracted.ok) throw new Error('extraction collapsed');
    const s = sign(message, extracted.dsA, master.Ppubs, { nonce: () => pinnedR });
    const v = verify(message, identity, s.signature, master.Ppubs, { hid: HID.SIGN });
    expect(v.accepted).toBe(false);
    expect(v.failure).toBe('HASH-MISMATCH');
  });
});

/** x mod q, for the two G1 points this suite constructs by hand. */
function mod0Q(x: bigint): bigint {
  const r = x % Q;
  return r >= 0n ? r : r + Q;
}
