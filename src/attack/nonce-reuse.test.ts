/**
 * The reused-nonce exhibit, run against this lab's OWN real verifier.
 *
 * The test is the demonstration: it does not assert the algebra, it performs the
 * attack and shows the forged signature clearing the same verify() that PANE 3
 * uses on genuine ones. Every signature accepted below is accepted by the
 * unmodified verifier — there is no weakened check anywhere in the path.
 *
 * The load-bearing assertion is the last one in each success block: the recovery
 * result carries NO scalar. That is the difference from crypto-lab-sm2-forge,
 * where the same mistake hands the attacker a scalar private key d. Here the key
 * is a group element, so the result is a point and there is nothing else to have.
 */
import { describe, it, expect } from 'vitest';
import {
  recoverFromKnownNonce,
  recoverFromReusedNonce,
  sameG1Point,
} from './nonce-reuse';
import { sign, verify, type NonceSource } from '../sm9/sign';
import { extractSignKey, signMasterKeyPair } from '../sm9/extract';
import { HID } from '../sm9/params';
import annexA from '../sm9/fixtures/annexA-fixture.json';

/** GM/T 0044.5 Annex A's master signature secret and signer identity, so the
 *  genuine key the attack must reproduce is the standard's own ds_A. */
const KS = BigInt('0x' + annexA.signature.ks);
const MASTER = signMasterKeyPair(KS);
const IDENTITY = annexA.signature.identity.ascii; // "Alice"

/** The genuinely extracted signing key, as the KGC would issue it. */
const extraction = extractSignKey(MASTER, IDENTITY, { hid: HID.SIGN });
if (!extraction.ok) throw new Error('Annex A key extraction should not require re-keying');
const GENUINE_DSA = extraction.dsA;

const enc = (s: string) => new TextEncoder().encode(s);

/** A nonce source that hands back the same fixed r every time — the mistake. */
function fixedNonce(r: bigint): NonceSource {
  return () => r;
}

/** Annex A's pinned nonce, a value known to give a valid signature. */
const REUSED_R = BigInt('0x' + annexA.signature.r);

describe('two signatures under one reused nonce', () => {
  const m1 = enc('transfer 100 to Bob');
  const m2 = enc('transfer 100 to Carol');

  // Both signed under the SAME r. This is the defect being exhibited.
  const s1 = sign(m1, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
  const s2 = sign(m2, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });

  it('the real verifier accepts both signatures first', () => {
    expect(verify(m1, IDENTITY, s1.signature, MASTER.Ppubs).accepted).toBe(true);
    expect(verify(m2, IDENTITY, s2.signature, MASTER.Ppubs).accepted).toBe(true);
  });

  it('the messages differ, so h1 and h2 differ — the attack precondition', () => {
    expect(s1.signature.h).not.toBe(s2.signature.h);
    // And the nonce really was reused: same r, same S only if h were equal.
    expect(s1.r).toBe(s2.r);
    expect(s1.r).toBe(REUSED_R);
  });

  it('recovers ds_A equal to the genuinely extracted key', () => {
    const result = recoverFromReusedNonce(s1.signature, s2.signature);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(sameG1Point(result.dsA, GENUINE_DSA)).toBe(true);
  });

  it('the recovered key FORGES a signature on a fresh message that the real verifier accepts', () => {
    const result = recoverFromReusedNonce(s1.signature, s2.signature);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // A message neither genuine signature covered, signed with the RECOVERED key
    // under a fresh random nonce (the forger is not obliged to reuse one).
    const forgedMessage = enc('transfer 1000000 to Attacker');
    const forgery = sign(forgedMessage, result.dsA, MASTER.Ppubs);

    const verdict = verify(forgedMessage, IDENTITY, forgery.signature, MASTER.Ppubs);
    expect(verdict.accepted).toBe(true);
    expect(verdict.failure).toBeNull();
  });

  it('the forgery is indistinguishable from a genuine signature to the verifier', () => {
    const result = recoverFromReusedNonce(s1.signature, s2.signature);
    if (!result.ok) return;
    // Sign the SAME message with the genuine key and with the recovered key; the
    // verifier accepts both, and neither carries a marker of its origin.
    const m = enc('a neutral statement');
    const genuine = sign(m, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
    const forged = sign(m, result.dsA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
    // Same key, same nonce, same message => byte-identical signature.
    expect(forged.signature.h).toBe(genuine.signature.h);
    expect(forged.signature.S.X).toBe(genuine.signature.S.X);
    expect(forged.signature.S.Y).toBe(genuine.signature.S.Y);
  });

  it('exposes the intermediate S1 - S2 = [h2 - h1]ds_A', () => {
    const result = recoverFromReusedNonce(s1.signature, s2.signature);
    if (!result.ok) return;
    expect(result.sDifference).toBeDefined();
    // S1 - S2 is on the curve and not the recovered key itself (they differ by
    // the (h2 - h1) factor).
    expect(sameG1Point(result.sDifference!, result.dsA)).toBe(false);
  });

  it('RETURNS NO SCALAR anywhere in the result — the whole point of the exhibit', () => {
    const result = recoverFromReusedNonce(s1.signature, s2.signature);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    // No top-level value is a bigint. dsA and sDifference are POINTS (objects);
    // their coordinates are field elements nested inside, not a private scalar
    // the result hands back. Contrast sm2-forge, whose result has `d: bigint`.
    for (const [key, value] of Object.entries(result)) {
      expect(typeof value, `field ${key} must not be a scalar`).not.toBe('bigint');
    }
    // And there is no field named for a scalar private key.
    expect('d' in result).toBe(false);
    expect('privateKey' in result).toBe(false);
    // What IS there is a point: an object with X, Y, Z field coordinates.
    expect(typeof result.dsA).toBe('object');
    expect(typeof result.dsA.X).toBe('bigint');
    expect(typeof result.dsA.Y).toBe('bigint');
  });
});

describe('the degenerate case: identical message hashes', () => {
  it('refuses rather than fabricating a key when h1 == h2', () => {
    // Same message under the same nonce gives the same h. Two such signatures
    // are one equation written twice.
    const m = enc('the same message twice');
    const a = sign(m, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
    const b = sign(m, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
    expect(a.signature.h).toBe(b.signature.h);

    const result = recoverFromReusedNonce(a.signature, b.signature);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('IDENTICAL-HASHES-NO-SECOND-EQUATION');
    // A refusal carries no key and no scalar.
    expect('dsA' in result).toBe(false);
  });

  it('also refuses two genuinely distinct signatures that happen to share h', () => {
    // Construct the singular input directly: two signatures with equal h. The
    // refusal is about the equation being singular, not about the messages.
    const s = sign(enc('m'), GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });
    const result = recoverFromReusedNonce(s.signature, { h: s.signature.h, S: s.signature.S });
    expect(result.ok).toBe(false);
  });
});

describe('the single-signature variant: a known nonce is fatal on its own', () => {
  const m = enc('one message, one leaked nonce');
  const s = sign(m, GENUINE_DSA, MASTER.Ppubs, { nonce: fixedNonce(REUSED_R) });

  it('recovers ds_A from ONE signature when its nonce r is known', () => {
    const result = recoverFromKnownNonce(s.signature, REUSED_R);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(sameG1Point(result.dsA, GENUINE_DSA)).toBe(true);
    expect(result.method).toBe('single-signature-known-nonce');
  });

  it('the key recovered from one signature also forges an accepted signature', () => {
    const result = recoverFromKnownNonce(s.signature, REUSED_R);
    if (!result.ok) return;
    const forged = sign(enc('forged via a single leaked nonce'), result.dsA, MASTER.Ppubs);
    expect(verify(enc('forged via a single leaked nonce'), IDENTITY, forged.signature, MASTER.Ppubs).accepted).toBe(true);
  });

  it('returns no scalar here either, and no S1 - S2 (there is only one signature)', () => {
    const result = recoverFromKnownNonce(s.signature, REUSED_R);
    if (!result.ok) return;
    for (const [key, value] of Object.entries(result)) {
      expect(typeof value, `field ${key} must not be a scalar`).not.toBe('bigint');
    }
    expect(result.sDifference).toBeUndefined();
  });

  it('refuses a claimed nonce that gives r - h == 0', () => {
    // A genuine signer never emits l == 0 (clause 6.1 step A6 redraws), so a
    // nonce equal to h means the caller supplied the wrong r or a malformed sig.
    const result = recoverFromKnownNonce({ h: s.signature.h, S: s.signature.S }, s.signature.h);
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe('NONCE-OUT-OF-RANGE');
  });

  it('a WRONG nonce yields a point that is not the genuine key', () => {
    // The recovery is only correct when r is truly this signature's nonce. A
    // wrong r still lands on the curve (it is [wrong-scalar^-1]S, a group
    // element) but it is not ds_A — recovery on bad input is silently wrong,
    // which is why this path is quarantined to the exhibit.
    const result = recoverFromKnownNonce(s.signature, REUSED_R + 1n);
    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(sameG1Point(result.dsA, GENUINE_DSA)).toBe(false);
  });
});
