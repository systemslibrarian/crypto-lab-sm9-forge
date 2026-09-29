/**
 * SM9 key generation and key extraction — GM/T 0044.2 clause 5.3 (signature
 * master key and user signature key) and GM/T 0044.3 clause 5.3 (encryption
 * master key and user encryption key).
 *
 * Extraction is the whole point of identity-based cryptography and it is one
 * modular inversion wearing a hat, so this module returns the inversion STEP BY
 * STEP rather than only its result. `h1`, `t1` and `t2` come back beside the key
 * because the page renders them; a function that returned only ds_A would make
 * the lab's headline act invisible.
 *
 * The two sides are mirror images across G1 and G2, and that mirroring is the
 * one thing worth holding onto:
 *
 *   signature   (0044.2 clause 5.3)   Ppub-s = [ks]P2 in G2 ... ds_A = [t2]P1 in G1
 *   encryption  (0044.3 clause 5.3)   Ppub-e = [ke]P1 in G1 ... de_B = [t2]P2 in G2
 *
 * The scalar arithmetic — t1 = H1 + ks, t2 = ks * t1^-1 — is identical on both
 * sides. Only the groups swap. Getting the groups the wrong way round produces a
 * key that is a perfectly good curve point and is useless, with nothing thrown.
 *
 * THE t1 == 0 CASE IS A TYPED OUTCOME, NOT AN EXCEPTION. GM/T 0044.2 clause 5.3
 * step A3 says that if t1 = 0 the KGC must regenerate the master key pair,
 * publish the new public key and RE-ISSUE EVERY USER KEY ALREADY EXTRACTED —
 * the remedy is an operational event affecting every user, not a retry, so the
 * caller is made to handle it rather than catch it. `masterKeyForcingT1Zero()`
 * below makes the branch reachable, because an outcome no test can enter is an
 * outcome nobody has checked.
 */
import {
  point_mul,
  point_new,
  twist_point_mul,
  twist_point_new,
} from '../vendor/gmssl-sm9.js';
import { HID, N, P1, P2 } from './params';
import { add, inv, isValidScalar, mul, sub } from './fn';
import { H1, concatBytes, identityWithHid } from './hash';
import { toAffineG1, toAffineG2 } from './pairing';
import type { G1Point, G2Point } from './pairing';

/** A field element as the standard prints it: 64 nibbles, leading zeros kept. */
export function toFieldHex(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

/**
 * The two components of an Fp2 element, in the order GM/T 0044.5's annexes
 * PRINT them, which is the reverse of the order the engine stores them in.
 *
 * Engine hazard (2): the annexes print the 1-2-4-12 tower in descending order
 * and the engine stores it ascending. The engine holds an Fp2 element as
 * [c0, c1]; the annex prints (c1, c0). This is asserted against the engine's own
 * P2 constant in extract.test.ts rather than assumed — a swapped Fp2 convention
 * produces comparisons that fail in a way that looks cryptographic.
 */
export function fp2Components(element: readonly bigint[]): string[] {
  return [toFieldHex(element[1]), toFieldHex(element[0])];
}

/** Generator P1 of G1, in the engine's affine representation. */
export function generatorP1(): G1Point {
  return { X: P1.x, Y: P1.y, Z: 1n };
}

/**
 * Generator P2 of G2, in the engine's affine representation.
 *
 * params.ts names the components `hi`/`lo`; the engine's index 0 is `hi` and its
 * index 1 is `lo`. That is a mapping between two other people's naming choices,
 * so extract.test.ts pins it against the engine's own SM9_P2 constant.
 */
export function generatorP2(): G2Point {
  return { X: [P2.x.hi, P2.x.lo], Y: [P2.y.hi, P2.y.lo], Z: [1n, 0n] };
}

/**
 * [k]P in G1, with BOTH ends of engine hazard (1) closed.
 *
 * The base is normalised on the way in, because point_mul's inner loop feeds it
 * to point_add as the SECOND operand, which reads it as affine and ignores its
 * Z. The result is normalised on the way out, because point_mul returns a
 * Jacobian point and every consumer downstream — another point_add, or
 * sm9_pairing — reads affine. Neither end throws when it is wrong; it returns an
 * off-curve point that looks like a key.
 *
 * The Z check keeps the guard free in the common case: generatorP1() and every
 * point this module returns are already affine, so no inversion is done.
 */
export function mulG1(k: bigint, base: G1Point = generatorP1()): G1Point {
  const affineBase = base.Z === 1n ? base : toAffineG1(base);
  const out = point_new();
  point_mul(out, k, affineBase);
  return toAffineG1(out as G1Point);
}

/** [k]P in G2. Same hazard, same guard, on the twist. */
export function mulG2(k: bigint, base: G2Point = generatorP2()): G2Point {
  const affineBase = base.Z[0] === 1n && base.Z[1] === 0n ? base : toAffineG2(base);
  const out = twist_point_new();
  twist_point_mul(out, k, affineBase);
  return toAffineG2(out as G2Point);
}

/** Encode ID || hid, the argument H1 takes throughout SM9. */
export function encodeIdentity(identity: string | Uint8Array, hid: number): Uint8Array {
  if (typeof identity === 'string') return identityWithHid(identity, hid);
  if (!Number.isInteger(hid) || hid < 0 || hid > 0xff) {
    throw new RangeError(`encodeIdentity: hid must be one byte, got ${hid}`);
  }
  return concatBytes(identity, Uint8Array.of(hid));
}

/**
 * The identity-to-scalar map extraction and verification must agree on.
 *
 * It is a parameter rather than a hard-wired call to H1 for one reason, and the
 * reason is this lab's headline negative claim: H1 CANCELS in the verification
 * equation, so an implementation can use a wrong one consistently and still pass
 * every round trip. Making it injectable is what lets sign.test.ts DEMONSTRATE
 * that rather than assert it. See the `h1CancelsInVerification` block there.
 */
export type IdentityHash = (idWithHid: Uint8Array) => bigint;

/** The real thing: H1(ID || hid, N), GM/T 0044.4 clause 5.4.2.2. */
export const identityHashH1: IdentityHash = (idWithHid) => H1(idWithHid, N).h;

/** Signature master key pair — GM/T 0044.2 clause 5.3. */
export interface SignMasterKey {
  /** Master signature private key ks, held only by the KGC. */
  ks: bigint;
  /** Master signature public key Ppub-s = [ks]P2, in G2, affine. */
  Ppubs: G2Point;
}

/** Encryption master key pair — GM/T 0044.3 clause 5.3. */
export interface EncryptMasterKey {
  /** Master encryption private key ke, held only by the KGC. */
  ke: bigint;
  /** Master encryption public key Ppub-e = [ke]P1, in G1, affine. */
  Ppube: G1Point;
}

/** The intermediates of clause 5.3, shared by both sides and by both outcomes. */
export interface ExtractionSteps {
  /** The hid byte this extraction used. */
  hid: number;
  /** The octet string ID || hid that was hashed. */
  idWithHid: Uint8Array;
  /** h1 = H1(ID || hid, N), or whatever identity hash was injected. */
  h1: bigint;
  /** t1 = h1 + master mod N. Zero here is the re-key outcome. */
  t1: bigint;
}

/** Clause 5.3 succeeded: the user's signature private key, with its workings. */
export interface SignKeyExtraction extends ExtractionSteps {
  ok: true;
  /** t2 = master * t1^-1 mod N. */
  t2: bigint;
  /** ds_A = [t2]P1, in G1, affine. */
  dsA: G1Point;
}

/** Clause 5.3 succeeded: the user's encryption private key, with its workings. */
export interface EncryptKeyExtraction extends ExtractionSteps {
  ok: true;
  t2: bigint;
  /** de_B = [t2]P2, in G2, affine. */
  deB: G2Point;
}

/**
 * Clause 5.3 step A3: t1 = 0, so t1^-1 does not exist and no key can be issued.
 *
 * Returned, never thrown, because the standard's remedy is not local to this
 * call: the KGC regenerates the master key pair, republishes the master public
 * key, and re-issues every user key it has already handed out. A caller that
 * merely retried would loop, since t1 is a deterministic function of the
 * identity and the unchanged master key.
 */
export interface MasterKeyRegenerationRequired extends ExtractionSteps {
  ok: false;
  outcome: 'MASTER-KEY-REGENERATION-REQUIRED';
  /** Always zero here; named so the union discriminates on `ok` alone. */
  t1: bigint;
  /** There is no t2: t1 has no inverse mod N. */
  t2: null;
  reason: string;
}

export type SignKeyOutcome = SignKeyExtraction | MasterKeyRegenerationRequired;
export type EncryptKeyOutcome = EncryptKeyExtraction | MasterKeyRegenerationRequired;

export interface ExtractOptions {
  /** Defaults to HID.SIGN (0x01) for signature keys, HID.ENCRYPT (0x03) for encryption keys. */
  hid?: number;
  /** Defaults to the real H1. See IdentityHash for why this is a parameter. */
  identityHash?: IdentityHash;
}

const REKEY_REASON =
  't1 = H1(ID||hid) + master == 0 mod N, so t1 has no inverse. GM/T 0044.2 ' +
  'clause 5.3 step A3: the KGC must regenerate the master key pair and ' +
  're-issue every user key already extracted.';

function requireMasterScalar(name: string, value: bigint): void {
  if (!isValidScalar(value)) {
    throw new RangeError(`${name} must be in [1, N-1]; got ${value}`);
  }
}

/**
 * Derive the signature master public key. GM/T 0044.2 clause 5.3:
 * "the KGC produces a random number ks in [1, N-1] ... and computes
 * Ppub-s = [ks]P2 in G2".
 */
export function signMasterKeyPair(ks: bigint): SignMasterKey {
  requireMasterScalar('ks', ks);
  return { ks, Ppubs: mulG2(ks) };
}

/**
 * Derive the encryption master public key. GM/T 0044.3 clause 5.3:
 * Ppub-e = [ke]P1 in G1 — the OTHER group from the signature side.
 */
export function encryptMasterKeyPair(ke: bigint): EncryptMasterKey {
  requireMasterScalar('ke', ke);
  return { ke, Ppube: mulG1(ke) };
}

/** The half of clause 5.3 that is identical on both sides: h1, t1, t2. */
function inversionSteps(
  master: bigint,
  identity: string | Uint8Array,
  hid: number,
  identityHash: IdentityHash,
): { steps: ExtractionSteps; t2: bigint | null } {
  const idWithHid = encodeIdentity(identity, hid);
  // Step A1: h1 = H1(ID_A || hid, N).
  const h1 = identityHash(idWithHid);
  // Step A2: t1 = h1 + master, in Fn.
  const t1 = add(h1, master);
  const steps: ExtractionSteps = { hid, idWithHid, h1, t1 };
  // Step A3: if t1 == 0 the master key must be regenerated; otherwise
  // t2 = master * t1^-1. fn.inv throws on 0 rather than returning a wrong
  // value, so the zero case is caught here and never reaches it.
  if (t1 === 0n) return { steps, t2: null };
  return { steps, t2: mul(master, inv(t1)) };
}

function rekeyRequired(steps: ExtractionSteps): MasterKeyRegenerationRequired {
  return {
    ...steps,
    ok: false,
    outcome: 'MASTER-KEY-REGENERATION-REQUIRED',
    t2: null,
    reason: REKEY_REASON,
  };
}

/**
 * Extract a user's signature private key — GM/T 0044.2 clause 5.3.
 *
 * ds_A = [t2]P1 lands in G1, the SMALL group, which is why SM9 signatures are
 * 32 + 64 bytes rather than 32 + 128.
 */
export function extractSignKey(
  master: SignMasterKey,
  identity: string | Uint8Array,
  options: ExtractOptions = {},
): SignKeyOutcome {
  const hid = options.hid ?? HID.SIGN;
  const identityHash = options.identityHash ?? identityHashH1;
  const { steps, t2 } = inversionSteps(master.ks, identity, hid, identityHash);
  if (t2 === null) return rekeyRequired(steps);
  return { ...steps, ok: true, t2, dsA: mulG1(t2) };
}

/**
 * Extract a user's encryption private key — GM/T 0044.3 clause 5.3.
 *
 * de_B = [t2]P2 lands in G2, mirroring the signature side. The default hid is
 * 0x03, which is what GM/T 0044.5 Annexes B, C and D all declare.
 */
export function extractEncryptKey(
  master: EncryptMasterKey,
  identity: string | Uint8Array,
  options: ExtractOptions = {},
): EncryptKeyOutcome {
  const hid = options.hid ?? HID.ENCRYPT;
  const identityHash = options.identityHash ?? identityHashH1;
  const { steps, t2 } = inversionSteps(master.ke, identity, hid, identityHash);
  if (t2 === null) return rekeyRequired(steps);
  return { ...steps, ok: true, t2, deB: mulG2(t2) };
}

/**
 * The master private key that makes t1 zero for this identity: ks = -H1(ID||hid).
 *
 * A TEACHING DEVICE, and the only honest way to reach the clause 5.3 step A3
 * branch. A real KGC draws ks at random and the odds of landing on this value
 * are about 2^-256, so the branch would otherwise be code nobody has ever
 * executed — the state this repository keeps finding wrong. Solving for it
 * costs one hash and one negation, and the result is a perfectly valid scalar
 * in [1, N-1], so nothing about the extraction call is special-cased.
 */
export function masterKeyForcingT1Zero(
  identity: string | Uint8Array,
  hid: number,
  identityHash: IdentityHash = identityHashH1,
): bigint {
  const h1 = identityHash(encodeIdentity(identity, hid));
  // t1 = h1 + ks == 0 mod N, so ks = -h1 mod N. h1 is in [1, N-1], so N - h1 is
  // too: this never returns 0, and never returns an out-of-range master key.
  return sub(0n, h1);
}
