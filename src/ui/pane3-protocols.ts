/**
 * PANE 3 — the three protocols, each beside the annex that pins it.
 *
 * Three acts, one per mechanism, each collapsible because a reader who came for
 * the extraction should not have to scroll past 2 KB of Fp12 to reach pane 4.
 *
 *   (a) sign and verify          GM/T 0044.2 clauses 6.1 and 7.1, Annex A, hid 0x01
 *   (b) key exchange             GM/T 0044.3 clause 6.1, Annex B, hid 0x03
 *   (c) KEM and encryption       GM/T 0044.4 clauses 6 and 7, Annexes C and D, hid 0x03
 *
 * WHY EVERY ACT CARRIES ITS ANNEX VECTOR. This lab's own round trips cannot
 * catch a wrong H1, a wrong identity encoding or a wrong hid — extraction and
 * verification agreeing on a wrong value is indistinguishable from both being
 * right (see act (a)'s last control, which demonstrates that live). The only
 * thing that catches it is a value somebody else printed. So every act compares
 * against GM/T 0044.5's pinned intermediates and shows the byte-equality, and
 * the "fresh random r" control is deliberately labelled INFO rather than OK when
 * its output differs from the annex: differing there is correct, and a green
 * tick would teach the wrong lesson.
 */
import { HID, N, Q } from '../sm9/params';
import { H1, bytesToHex, concatBytes, hexToBytes } from '../sm9/hash';
import {
  encryptMasterKeyPair,
  extractEncryptKey,
  extractSignKey,
  signMasterKeyPair,
  toFieldHex,
} from '../sm9/extract';
import type { IdentityHash } from '../sm9/extract';
import { randomNonce, sign, signatureToHex, verify } from '../sm9/sign';
import type { Sm9Signature, VerifyFailure } from '../sm9/sign';
import { g1ToHex, gtToHex, runKeyExchange } from '../sm9/exchange';
import {
  compareKemKeys,
  decrypt,
  encrypt,
  kemDecapsulate,
  kemEncapsulate,
} from '../sm9/encrypt';
import annexA from '../sm9/fixtures/annexA-fixture.json';
import annexCD from '../sm9/fixtures/sm9-annex-cd-fixtures.json';
import kexVectors from '../sm9/fixtures/sm9-keyexchange-vectors.json';
import {
  button,
  controls,
  decodeUtf8,
  defer,
  detailsEl,
  el,
  equality,
  heading,
  hexBlock,
  hexDetails,
  kv,
  note,
  pane,
  para,
  replace,
  sourceTag,
  statusPill,
  tableEl,
} from './dom';

// ---------------------------------------------------------------------------
// act (a) — signature
// ---------------------------------------------------------------------------

const SIG = annexA.signature;
const SIG_KS = BigInt(`0x${SIG.ks}`);
const SIG_R = BigInt(`0x${SIG.r}`);
const SIG_MESSAGE = hexToBytes(SIG.message.hex);
const SIG_IDENTITY = SIG.identity.ascii;
const SIG_HID = Number(`0x${SIG.hid}`);

/** Which clause-7.1 step refused, named rather than left as a code. */
const CLAUSE_71_STEP: Record<VerifyFailure, string> = {
  'H-OUT-OF-RANGE': 'S1 — h′ must be an integer in [1, N-1]',
  'S-AT-INFINITY': 'S2 — S′ must be a point of G1, and the identity is not one',
  'S-NOT-ON-CURVE': 'S2 — S′ must be a point of G1; y² ≠ x³ + 5 over F_q',
  'HASH-MISMATCH': 'S6 — h2 = H2(M′ ‖ w′, N) must equal h′',
};

interface SignerState {
  Ppubs: ReturnType<typeof signMasterKeyPair>['Ppubs'];
  dsA: { X: bigint; Y: bigint; Z: bigint };
}

/** The Annex A signer, built once and reused by every control in act (a). */
function signerState(identityHash?: IdentityHash): SignerState {
  const master = signMasterKeyPair(SIG_KS);
  const outcome = extractSignKey(master, SIG_IDENTITY, { hid: SIG_HID, identityHash });
  if (!outcome.ok) throw new Error(`Annex A extraction returned ${outcome.outcome}`);
  return { Ppubs: master.Ppubs, dsA: outcome.dsA };
}

/** The eight negative cases GM/T 0044.5 Annex A's fixture names, each built here. */
interface NegativeCase {
  id: string;
  description: string;
  why: string;
  run: (state: SignerState, signature: Sm9Signature) => ReturnType<typeof verify>;
}

const NEGATIVE_CASES: NegativeCase[] = annexA.must_reject.map((entry) => {
  const build = (state: SignerState, signature: Sm9Signature): ReturnType<typeof verify> => {
    const flip = (index: number, mask: number): Uint8Array => {
      const copy = Uint8Array.from(SIG_MESSAGE);
      copy[index] ^= mask;
      return copy;
    };
    switch (entry.id) {
      case 'N1':
        return verify(flip(SIG_MESSAGE.length - 1, 0x01), SIG_IDENTITY, signature, state.Ppubs, { hid: SIG_HID });
      case 'N2':
        return verify(flip(0, 0x80), SIG_IDENTITY, signature, state.Ppubs, { hid: SIG_HID });
      case 'N3':
        return verify(SIG_MESSAGE, 'Bob', signature, state.Ppubs, { hid: SIG_HID });
      case 'N4':
        return verify(SIG_MESSAGE, 'alice', signature, state.Ppubs, { hid: SIG_HID });
      case 'N5':
        return verify(SIG_MESSAGE, SIG_IDENTITY, { h: signature.h ^ 1n, S: signature.S }, state.Ppubs, { hid: SIG_HID });
      case 'N6':
        return verify(
          SIG_MESSAGE,
          SIG_IDENTITY,
          { h: signature.h, S: { X: (signature.S.X + 1n) % Q, Y: signature.S.Y, Z: signature.S.Z } },
          state.Ppubs,
          { hid: SIG_HID },
        );
      case 'N7':
        return verify(
          SIG_MESSAGE,
          SIG_IDENTITY,
          { h: signature.h, S: { X: signature.S.X, Y: (Q - signature.S.Y) % Q, Z: signature.S.Z } },
          state.Ppubs,
          { hid: SIG_HID },
        );
      case 'N8':
        return verify(SIG_MESSAGE, SIG_IDENTITY, { h: 0n, S: signature.S }, state.Ppubs, { hid: SIG_HID });
      default:
        throw new Error(`no mutation implemented for ${entry.id}`);
    }
  };
  return { id: entry.id, description: entry.case, why: entry.why, run: build };
});

function signatureRows(
  h: bigint,
  S: { X: bigint; Y: bigint },
  label: string,
  expected?: { h: string; S: string },
): HTMLElement {
  const hex = signatureToHex({ h, S: { X: S.X, Y: S.Y, Z: 1n } });
  const rows: (HTMLElement | string)[][] = [
    [
      el('span', { text: 'h' }),
      hexBlock(hex.h, `p3a-${label}-h`),
      expected === undefined ? el('span', { text: 'no pinned value for a fresh r' }) : hexBlock(expected.h),
      expected === undefined
        ? statusPill('info', 'differs from Annex A, as a fresh nonce must', `p3a-${label}-h-badge`)
        : equality(hex.h === expected.h, 'byte-identical', 'differs', `p3a-${label}-h-badge`),
    ],
    [
      el('span', { text: 'S (uncompressed, 0x04 ‖ x ‖ y)' }),
      hexBlock(hex.S, `p3a-${label}-s`),
      expected === undefined ? el('span', { text: 'no pinned value for a fresh r' }) : hexBlock(expected.S),
      expected === undefined
        ? statusPill('info', 'differs from Annex A, as a fresh nonce must', `p3a-${label}-s-badge`)
        : equality(hex.S === expected.S, 'byte-identical', 'differs', `p3a-${label}-s-badge`),
    ],
  ];
  return tableEl(
    ['Component', 'Computed here', 'Printed in Annex A', ''],
    rows,
    `p3a-${label}-table`,
    'Signature components against Annex A',
  );
}

function buildActA(): HTMLElement {
  const runPinned = button('Run Annex A with its pinned r', 'p3a-run');
  const runFresh = button('Sign again with a fresh random r', 'p3a-fresh-r', 'secondary');
  const runNegatives = button('Run the eight must-reject cases', 'p3a-run-negatives', 'secondary');
  const runWrongH1 = button('Extract with a deliberately wrong H1', 'p3a-wrongh1-run', 'danger');

  const output = el('div', { testid: 'p3a-output' }, [statusPill('pending', 'pending — not yet run')]);
  // A host of its own rather than a second write into `output`: the pinned run
  // and the fresh-nonce run are meant to be read BESIDE each other, and a shared
  // host makes the second one look like a correction of the first.
  const freshOutput = el('div', { testid: 'p3a-fresh-output' }, [
    statusPill('pending', 'pending — not yet run'),
  ]);
  const negatives = el('div', { testid: 'p3a-negatives' });
  const wrongH1 = el('div', { testid: 'p3a-wrongh1' });

  runPinned.addEventListener('click', () => {
    replace(output, [statusPill('info', 'computing')]);
    defer(() => {
      const state = signerState();
      const result = sign(SIG_MESSAGE, state.dsA, state.Ppubs, { nonce: () => SIG_R });
      const verified = verify(SIG_MESSAGE, SIG_IDENTITY, result.signature, state.Ppubs, { hid: SIG_HID });
      const dsAHex = `${toFieldHex(state.dsA.X)}${toFieldHex(state.dsA.Y)}`;
      const annexDsA = `${SIG.dsA.x}${SIG.dsA.y}`;

      replace(output, [
        kv(
          [
            ['identity', el('span', { text: `${SIG_IDENTITY} (${SIG.identity.hex})`, testid: 'p3a-identity' })],
            ['hid', el('span', { text: `0x${SIG.hid}` })],
            ['message', el('span', { text: `"${SIG.message.ascii}"` })],
            ['ds_A (x ‖ y)', hexBlock(dsAHex, 'p3a-dsa')],
            ['ds_A against Annex A', equality(dsAHex === annexDsA, 'byte-identical', 'differs', 'p3a-dsa-badge')],
            ['r (A2, pinned by the annex)', hexBlock(toFieldHex(result.r), 'p3a-r')],
            ['l = (r − h) mod N (A6)', hexBlock(toFieldHex(result.l), 'p3a-l')],
            ['nonces drawn', el('span', { text: String(result.attempts) })],
          ],
          'p3a-pinned-values',
        ),
        signatureRows(result.signature.h, result.signature.S, 'pinned', {
          h: SIG.h,
          S: SIG.sig_S_uncompressed,
        }),
        hexDetails('g = e(P1, Ppub-s), step A1', gtToHex(result.g), 'p3a-g'),
        hexDetails('w = g^r, step A4', gtToHex(result.w), 'p3a-w'),
        hexDetails('M ‖ w, the octets H2 consumed at step A5', bytesToHex(result.messageWithW), 'p3a-mw'),
        el('div', {}, [
          statusPill(
            verified.accepted ? 'ok' : 'bad',
            verified.accepted ? 'VERIFIED — clause 7.1 accepted' : `REFUSED at ${verified.failure}`,
            'p3a-verify-status',
          ),
        ]),
      ]);
    });
  });

  runFresh.addEventListener('click', () => {
    replace(freshOutput, [statusPill('info', 'computing')]);
    defer(() => {
      const state = signerState();
      const result = sign(SIG_MESSAGE, state.dsA, state.Ppubs, { nonce: randomNonce });
      const verified = verify(SIG_MESSAGE, SIG_IDENTITY, result.signature, state.Ppubs, { hid: SIG_HID });
      replace(freshOutput, [
        note(
          [
            el('strong', { text: 'A fresh nonce, the same key, the same message. ' }),
            'The signature below is not Annex A\'s and must not be: r is drawn from '
              + 'crypto.getRandomValues by rejection sampling, so h and S change every time. What does '
              + 'not change is that verification holds, because the verifier recovers w′ from S and h '
              + 'rather than from r. The badges are marked INFO rather than green — differing from the '
              + 'annex here is the correct outcome.',
          ],
          false,
          'p3a-fresh-note',
        ),
        kv(
          [
            ['r (A2, drawn fresh)', hexBlock(toFieldHex(result.r), 'p3a-fresh-r-value')],
            ['l = (r − h) mod N', hexBlock(toFieldHex(result.l))],
            ['nonces drawn', el('span', { text: String(result.attempts) })],
          ],
          'p3a-fresh-values',
        ),
        signatureRows(result.signature.h, result.signature.S, 'fresh'),
        el('div', {}, [
          statusPill(
            verified.accepted ? 'ok' : 'bad',
            verified.accepted ? 'VERIFIED — clause 7.1 accepted' : `REFUSED at ${verified.failure}`,
            'p3a-fresh-verify-status',
          ),
        ]),
      ]);
    });
  });

  runNegatives.addEventListener('click', () => {
    replace(negatives, [statusPill('info', 'computing')]);
    defer(() => {
      const state = signerState();
      const result = sign(SIG_MESSAGE, state.dsA, state.Ppubs, { nonce: () => SIG_R });
      const rows = NEGATIVE_CASES.map((testCase) => {
        const outcome = testCase.run(state, result.signature);
        const refused = !outcome.accepted && outcome.failure !== null;
        return {
          testCase,
          outcome,
          refused,
        };
      });
      const allRefused = rows.every((r) => r.refused);
      replace(negatives, [
        el('div', {}, [
          statusPill(
            allRefused ? 'ok' : 'bad',
            allRefused
              ? `all ${rows.length} refused by the real verifier`
              : `${rows.filter((r) => !r.refused).length} of ${rows.length} were ACCEPTED`,
            'p3a-negatives-status',
          ),
        ]),
        tableEl(
          ['Case', 'What was changed', 'Failure code', 'Which clause-7.1 step refused', ''],
          rows.map(({ testCase, outcome, refused }) => [
            el('span', { text: testCase.id }),
            el('span', { text: testCase.description }),
            el('span', {
              text: outcome.failure ?? 'none — ACCEPTED',
              testid: `p3a-negative-${testCase.id}-code`,
            }),
            el('span', {
              text: outcome.failure === null ? 'no step refused it' : CLAUSE_71_STEP[outcome.failure],
              testid: `p3a-negative-${testCase.id}-step`,
            }),
            equality(refused, 'refused', 'ACCEPTED', `p3a-negative-${testCase.id}`),
          ]),
          'p3a-negatives-table',
          'The eight must-reject cases and the clause 7.1 step that refused each',
        ),
        note(
          [
            'Note which step each one lands on. Six of the eight reach S6 and fail the hash comparison, '
              + 'because almost everything an attacker can change — the message, the identity, h, or S '
              + 'moved to another on-curve point — changes w′ and nothing else. Only a malformed S (S2) '
              + 'and an out-of-range h (S1) are caught structurally, before any pairing is computed.',
          ],
          false,
          'p3a-negatives-note',
        ),
      ]);
    });
  });

  runWrongH1.addEventListener('click', () => {
    replace(wrongH1, [statusPill('info', 'computing')]);
    defer(() => {
      // A deliberately wrong identity-to-scalar map: the real H1 with one extra
      // domain byte in front. It is a perfectly good hash and it is not SM9's.
      const brokenH1: IdentityHash = (idWithHid) => H1(concatBytes(Uint8Array.of(0xff), idWithHid), N).h;

      const honest = signerState();
      const broken = signerState(brokenH1);
      const brokenDsA = `${toFieldHex(broken.dsA.X)}${toFieldHex(broken.dsA.Y)}`;
      const honestDsA = `${toFieldHex(honest.dsA.X)}${toFieldHex(honest.dsA.Y)}`;

      const result = sign(SIG_MESSAGE, broken.dsA, broken.Ppubs, { nonce: () => SIG_R });
      // The page's own verifier, unmodified, using the SAME wrong H1 the KGC used.
      const agreeing = verify(SIG_MESSAGE, SIG_IDENTITY, result.signature, broken.Ppubs, {
        hid: SIG_HID,
        identityHash: brokenH1,
      });
      // The same verifier with SM9's real H1.
      const realVerifier = verify(SIG_MESSAGE, SIG_IDENTITY, result.signature, broken.Ppubs, { hid: SIG_HID });

      const verdictHost = el('div', { testid: 'p3a-wrongh1-verdict' });
      replace(verdictHost, [
        el('div', { class: 'verdict verdict-alarm' }, [
          el('span', { class: 'glyph', text: '!' }),
          el('div', {}, [
            el('span', {
              class: 'verdict-text',
              text: `SIGNATURE ACCEPTED — verify() returned accepted: ${String(agreeing.accepted)}`,
            }),
            el('span', {
              class: 'verdict-why',
              text: 'This is the page\'s own unmodified verifier, running clause 7.1 step for step, on a '
                + 'key extracted with an identity hash that is not SM9\'s H1. It accepts, and it is right '
                + 'to: the equation it checks does not contain H1.',
            }),
          ]),
        ]),
      ]);

      replace(wrongH1, [
        verdictHost,
        note(
          [
            el('strong', { text: 'THE LIMITATION, stated in the state that demonstrates it. ' }),
            'An SM9 sign → verify round trip does NOT prove that H1, the identity encoding, or hid is '
              + 'correct. Extraction sets t1 = H1 + ks and t2 = ks · t1⁻¹, so t1 · t2 = ks for ANY H1 '
              + 'whatsoever. Verification forms P = [H1]P2 + Ppub-s = [t1]P2 and S = [l · t2]P1, and takes '
              + 'u = e(S, P) = e(P1, P2)^(l · t2 · t1) = e(P1, P2)^(l · ks). H1 CANCELS — provided BOTH '
              + 'sides use the same one. What a passing check cannot tell you is WHICH identity-to-scalar '
              + 'map produced the key; it establishes that extraction and verification agreed on one. '
              + 'It does NOT mean identity goes unchecked: point SM9\'s real verifier at this same key '
              + 'and it is refused at HASH-MISMATCH, as the row below shows, and so are a key for another '
              + 'identity and a key extracted at a different hid.',
          ],
          true,
          'p3a-wrongh1-limitation',
        ),
        kv(
          [
            ['ds_A with SM9\'s real H1', hexBlock(honestDsA, 'p3a-wrongh1-honest-dsa')],
            ['ds_A with the wrong H1', hexBlock(brokenDsA, 'p3a-wrongh1-dsa')],
            [
              'are they the same key?',
              equality(brokenDsA === honestDsA, 'the same', 'DIFFERENT keys', 'p3a-wrongh1-keys-differ'),
            ],
            [
              'verifier using the SAME wrong H1',
              statusPill(
                agreeing.accepted ? 'ok' : 'bad',
                agreeing.accepted ? 'ACCEPTED' : `refused at ${agreeing.failure}`,
                'p3a-wrongh1-agreeing',
              ),
            ],
            [
              'verifier using SM9\'s real H1',
              statusPill(
                realVerifier.accepted ? 'ok' : 'bad',
                realVerifier.accepted ? 'ACCEPTED' : `refused at ${realVerifier.failure}`,
                'p3a-wrongh1-realverifier',
              ),
            ],
            [
              'h1 the honest verifier computed',
              hexBlock(toFieldHex(realVerifier.steps.h1 ?? 0n), 'p3a-wrongh1-h1-real'),
            ],
            [
              'h1 the agreeing verifier computed',
              hexBlock(toFieldHex(agreeing.steps.h1 ?? 0n), 'p3a-wrongh1-h1-broken'),
            ],
          ],
          'p3a-wrongh1-values',
        ),
        note(
          [
            el('strong', { text: 'What does catch it. ' }),
            'Only a value somebody else printed. Pane 2 compares h1, t1, t2 and ds_A against GM/T 0044.5 '
              + 'Annex A\'s pinned intermediates, and that table is the whole of this lab\'s defence '
              + 'against a wrong H1. The same cancellation runs through key exchange — g1, g2 and g3 are '
              + 'hid-independent because t3 cancels inside e(R_A, de_B) — which is why pane 5\'s two hid '
              + 'conventions reach byte-identical group elements and differ only in the KDF input.',
          ],
          false,
          'p3a-wrongh1-what-catches',
        ),
      ]);
    });
  });

  return detailsEl(
    '(a) Sign and verify — GM/T 0044.5 Annex A, hid 0x01',
    [
      para(
        'Annex A prints a complete worked example: a master key, an identity, a message, the nonce r, '
          + 'and every intermediate down to the signature. With r pinned the whole thing is byte '
          + 'reproducible, which is what makes it a conformance vector rather than an illustration.',
      ),
      controls([runPinned]),
      output,
      heading('The same key and message, a fresh nonce'),
      controls([runFresh]),
      freshOutput,
      detailsEl(
        'The equations, in the standard\'s own notation',
        [
          kv([
            ['A1', el('span', { text: 'g = e(P1, Ppub-s), an element of GT' })],
            ['A2', el('span', { text: 'draw r in [1, N-1]' })],
            ['A4', el('span', { text: 'w = g^r' })],
            ['A5', el('span', { text: 'h = H2(M ‖ w, N)' })],
            ['A6', el('span', { text: 'l = (r − h) mod N; if l = 0, go back to A2' })],
            ['A7', el('span', { text: 'S = [l]ds_A — the signature is the pair (h, S)' })],
            ['S3–S5', el('span', { text: 't = g^h′; P = [H1(ID_A ‖ hid, N)]P2 + Ppub-s; u = e(S′, P); w′ = u · t' })],
            ['S6', el('span', { text: 'accept iff H2(M′ ‖ w′, N) = h′' })],
          ]),
          para(
            'Note that r never appears in the signature and never reaches the verifier. w′ is '
              + 'reconstructed from S and h, which is why a fresh r changes the signature and not the '
              + 'verdict — and why pane 5 can recover the private key from two signatures that shared one.',
          ),
        ],
        'p3a-equations',
      ),
      heading('The eight cases Annex A\'s fixture says must be refused'),
      controls([runNegatives]),
      negatives,
      heading('What the round trip does not prove'),
      para(
        'Everything above verifies. Press the button below and watch the same verifier accept a '
          + 'signature made under a key extracted with an identity hash that is not SM9\'s.',
      ),
      controls([runWrongH1]),
      wrongH1,
    ],
    'p3a-details',
    true,
  );
}

// ---------------------------------------------------------------------------
// act (b) — key exchange
// ---------------------------------------------------------------------------

const KEX = kexVectors.shared_inputs;
const KEX_PUBLISHED = kexVectors.annex_b_published;

function buildActB(): HTMLElement {
  const run = button('Run Annex B at hid 0x03', 'p3b-run');
  const output = el('div', { testid: 'p3b-output' }, [statusPill('pending', 'pending — not yet run')]);

  run.addEventListener('click', () => {
    replace(output, [statusPill('info', 'computing')]);
    defer(() => {
      const transcript = runKeyExchange({
        ke: BigInt(`0x${KEX.ke}`),
        idA: hexToBytes(KEX.ID_A),
        idB: hexToBytes(KEX.ID_B),
        rA: BigInt(`0x${KEX.r_A}`),
        rB: BigInt(`0x${KEX.r_B}`),
        klenBits: KEX.klen_bits,
        hid: HID.ENCRYPT,
      });

      const skB = bytesToHex(transcript.responder.sk);
      const skA = bytesToHex(transcript.initiator.sk);
      const tagB = bytesToHex(transcript.responder.tag82);
      const tagA = bytesToHex(transcript.initiator.tag83);

      const sideBox = (
        title: string,
        role: string,
        side: typeof transcript.responder,
        formulas: [string, string][],
        skTestid: string,
      ): HTMLElement =>
        el('div', { class: 'box' }, [
          el('h4', { text: title }),
          el('div', {}, [sourceTag(role)]),
          kv(formulas.map(([label, text]) => [label, el('span', { text })])),
          hexDetails('g1', gtToHex(side.g1)),
          hexDetails('g2', gtToHex(side.g2)),
          hexDetails('g3', gtToHex(side.g3)),
          kv([['SK (klen 128)', hexBlock(bytesToHex(side.sk), skTestid)]]),
        ]);

      replace(output, [
        kv(
          [
            ['ID_A', el('span', { text: `${KEX.ID_A_ascii} (${KEX.ID_A})` })],
            ['ID_B', el('span', { text: `${KEX.ID_B_ascii} (${KEX.ID_B})` })],
            ['hid', el('span', { text: '0x03 — declared by Annex B, line 574' })],
            ['klen', el('span', { text: `${KEX.klen_bits} bits` })],
            ['R_A = [r_A]Q_B (A3)', hexBlock(g1ToHex(transcript.RA), 'p3b-ra')],
            ['R_B = [r_B]Q_A (B3)', hexBlock(g1ToHex(transcript.RB), 'p3b-rb')],
          ],
          'p3b-inputs',
        ),

        heading('g1 and g2 swap FORMULAS between the two sides'),
        note(
          [
            el('strong', { text: 'This is the thing readers get wrong. ' }),
            'B pairs the point it received with its own private key and exponentiates the master '
              + 'pairing; A does the exact mirror. The formulas swap — the VALUES must not. A side that '
              + 'ran the wrong one of these two derivations is still self-consistent: it produces a '
              + 'well-formed SK, and it verifies its own confirmation tag against itself. It disagrees '
              + 'only with its peer, and only at the very end.',
          ],
          false,
          'p3b-swap-note',
        ),
        tableEl(
          ['', 'responder B (steps B4–B6)', 'initiator A (steps A5–A8)', 'same value?'],
          [
            [
              el('span', { text: 'g1' }),
              el('span', { text: 'e(R_A, de_B)', testid: 'p3b-g1-b-formula' }),
              el('span', { text: 'e(Ppub-e, P2)^r_A', testid: 'p3b-g1-a-formula' }),
              equality(gtToHex(transcript.responder.g1) === gtToHex(transcript.initiator.g1), 'byte-identical', 'differs', 'p3b-g1-equal'),
            ],
            [
              el('span', { text: 'g2' }),
              el('span', { text: 'e(Ppub-e, P2)^r_B', testid: 'p3b-g2-b-formula' }),
              el('span', { text: 'e(R_B, de_A)', testid: 'p3b-g2-a-formula' }),
              equality(gtToHex(transcript.responder.g2) === gtToHex(transcript.initiator.g2), 'byte-identical', 'differs', 'p3b-g2-equal'),
            ],
            [
              el('span', { text: 'g3' }),
              el('span', { text: 'g1^r_B — raised from g1', testid: 'p3b-g3-b-formula' }),
              el('span', { text: '(g2′)^r_A — raised from g2′', testid: 'p3b-g3-a-formula' }),
              equality(gtToHex(transcript.responder.g3) === gtToHex(transcript.initiator.g3), 'byte-identical', 'differs', 'p3b-g3-equal'),
            ],
          ],
          'p3b-swap-table',
          'How g1, g2 and g3 are formed on each side of the key exchange',
        ),

        el('div', { class: 'side-by-side' }, [
          sideBox(
            'Responder B',
            'holds de_B and r_B',
            transcript.responder,
            [
              ['B4', 'g1 = e(R_A, de_B), g2 = e(Ppub-e, P2)^r_B, g3 = g1^r_B'],
              ['B5', 'SK_B = KDF(ID_A ‖ ID_B ‖ R_A ‖ R_B ‖ g1 ‖ g2 ‖ g3, klen)'],
              ['B6', 'S_B = Hv(0x82 ‖ g1 ‖ Hv(g2 ‖ g3 ‖ ID_A ‖ ID_B ‖ R_A ‖ R_B))'],
            ],
            'p3b-sk-b',
          ),
          sideBox(
            'Initiator A',
            'holds de_A and r_A',
            transcript.initiator,
            [
              ['A5', "g1′ = e(Ppub-e, P2)^r_A, g2′ = e(R_B, de_A), g3′ = (g2′)^r_A"],
              ['A7', "SK_A = KDF(ID_A ‖ ID_B ‖ R_A ‖ R_B ‖ g1′ ‖ g2′ ‖ g3′, klen)"],
              ['A8', "S_A = Hv(0x83 ‖ g1′ ‖ Hv(g2′ ‖ g3′ ‖ ID_A ‖ ID_B ‖ R_A ‖ R_B))"],
            ],
            'p3b-sk-a',
          ),
        ]),

        heading('Against Annex B\'s printed values'),
        tableEl(
          ['Value', 'Computed here', `Printed in Annex B`, ''],
          [
            [
              el('span', { text: `SK_B (lines ${KEX_PUBLISHED.SKB.lines})` }),
              hexBlock(skB),
              hexBlock(KEX_PUBLISHED.SKB.hex),
              equality(skB === KEX_PUBLISHED.SKB.hex, 'byte-identical', 'differs', 'p3b-skb-badge'),
            ],
            [
              el('span', { text: `SK_A (lines ${KEX_PUBLISHED.SKA.lines})` }),
              hexBlock(skA),
              hexBlock(KEX_PUBLISHED.SKA.hex),
              equality(skA === KEX_PUBLISHED.SKA.hex, 'byte-identical', 'differs', 'p3b-ska-badge'),
            ],
            [
              el('span', { text: `S_B, the 0x82 tag (lines ${KEX_PUBLISHED.SB.lines})` }),
              hexBlock(tagB, 'p3b-tag82'),
              hexBlock(KEX_PUBLISHED.SB.hex),
              equality(tagB === KEX_PUBLISHED.SB.hex, 'byte-identical', 'differs', 'p3b-sb-badge'),
            ],
            [
              el('span', { text: `S_A, the 0x83 tag (lines ${KEX_PUBLISHED.SA.lines})` }),
              hexBlock(tagA, 'p3b-tag83'),
              hexBlock(KEX_PUBLISHED.SA.hex),
              equality(tagA === KEX_PUBLISHED.SA.hex, 'byte-identical', 'differs', 'p3b-sa-badge'),
            ],
          ],
          'p3b-annex-table',
          'Key exchange session keys and confirmation tags against Annex B',
        ),

        heading('Key confirmation'),
        kv(
          [
            [
              'the two sides agree on SK',
              equality(transcript.agree, 'SK_A = SK_B', 'the sides DISAGREE', 'p3b-agree'),
            ],
            [
              'A6 — does S1 equal S_B?',
              equality(transcript.confirmBtoA, 'confirmed B → A', 'confirmation FAILED', 'p3b-confirm-bta'),
            ],
            [
              'B8 — does S2 equal S_A?',
              equality(transcript.confirmAtoB, 'confirmed A → B', 'confirmation FAILED', 'p3b-confirm-atb'),
            ],
          ],
          'p3b-confirmation',
        ),
        note(
          [
            'The two tags are the same construction separated by one leading byte: 0x82 for B\'s tag and '
              + '0x83 for A\'s. Without that prefix the two directions would be the same string, and B\'s '
              + 'own tag would verify as A\'s reply. Note also that g1 sits OUTSIDE the inner hash while '
              + 'g2 and g3 sit inside it — the outer hash is what binds the tag to the shared secret.',
          ],
          false,
          'p3b-tag-note',
        ),
      ]);
    });
  });

  return detailsEl(
    '(b) Key exchange — GM/T 0044.5 Annex B, hid 0x03',
    [
      para(
        'Two parties who have never met derive a shared key from each other\'s names, one round trip '
          + 'each, with no certificate anywhere. Both sides are computed here, which a real deployment '
          + 'obviously does not do — but each side\'s derivation sees only what that party holds.',
      ),
      controls([run]),
      output,
    ],
    'p3b-details',
  );
}

// ---------------------------------------------------------------------------
// act (c) — KEM and public key encryption
// ---------------------------------------------------------------------------

const KEM = annexCD.annex_C_kem;
const PKE = annexCD.annex_D_encryption;

function buildActC(): HTMLElement {
  const runKem = button('Run Annex C — key encapsulation', 'p3c-run-kem');
  const runPke = button('Run Annex D — both encryption modes', 'p3c-run-pke');
  const kemOut = el('div', { testid: 'p3c-kem-output' }, [statusPill('pending', 'pending — not yet run')]);
  const pkeOut = el('div', { testid: 'p3c-pke-output' }, [statusPill('pending', 'pending — not yet run')]);

  runKem.addEventListener('click', () => {
    replace(kemOut, [statusPill('info', 'computing')]);
    defer(() => {
      const ke = BigInt(`0x${KEM.master_encryption_private_key_ke}`);
      const hid = Number(`0x${KEM.hid}`);
      const klen = KEM.klen_bits.value;
      const master = encryptMasterKeyPair(ke);
      const bob = extractEncryptKey(master, KEM.ID_B_ascii, { hid });
      const alice = extractEncryptKey(master, 'Alice', { hid });
      if (!bob.ok || !alice.ok) throw new Error('Annex C extraction returned a re-key outcome');

      const encapsulated = kemEncapsulate(KEM.ID_B_ascii, hid, master.Ppube, klen, {
        r: BigInt(`0x${KEM.encapsulate.A2_r}`),
      });
      const decapsulated = kemDecapsulate(encapsulated.CBytes, KEM.ID_B_ascii, bob.deB, klen);
      const agreement = compareKemKeys(encapsulated.K, decapsulated);

      // The same ciphertext handed to the WRONG user's private key. Clause 6.2.1
      // has no integrity check, so this reports success and returns another key.
      const wrong = kemDecapsulate(encapsulated.CBytes, KEM.ID_B_ascii, alice.deB, klen);
      const wrongAgreement = compareKemKeys(encapsulated.K, wrong);

      const kHex = bytesToHex(encapsulated.K);
      replace(kemOut, [
        kv(
          [
            ['receiver', el('span', { text: `${KEM.ID_B_ascii} (${KEM.ID_B}), hid 0x${KEM.hid}` })],
            ['klen', el('span', { text: `${klen} bits` })],
            ['C = [r]Q_B (A3)', hexBlock(bytesToHex(encapsulated.CBytes), 'p3c-kem-c')],
            ['K, encapsulated (A6)', hexBlock(kHex, 'p3c-kem-k')],
            ['K printed in Annex C', hexBlock(KEM.encapsulate.A6_K.value)],
            [
              'byte equality',
              equality(kHex === KEM.encapsulate.A6_K.value, 'byte-identical', 'differs', 'p3c-kem-badge'),
            ],
            [
              "K′, decapsulated (B4)",
              hexBlock(decapsulated.ok ? bytesToHex(decapsulated.K) : `refused at ${decapsulated.step}`, 'p3c-kem-kprime'),
            ],
            [
              'K′ printed in Annex C',
              hexBlock(KEM.decapsulate.B3_K.value),
            ],
            [
              'the two sides agree',
              equality(agreement.agreed, 'K = K′', 'the keys differ', 'p3c-kem-agreed'),
            ],
          ],
          'p3c-kem-values',
        ),
        hexDetails('w = g^r, step A5', bytesToHex(encapsulated.wBytes), 'p3c-kem-w'),
        hexDetails('C ‖ w ‖ ID_B, the KDF input at step A6', bytesToHex(encapsulated.kdfInput), 'p3c-kem-kdfin'),

        heading('What the KEM does NOT do'),
        el('div', {}, [
          statusPill(
            'alarm',
            `decapsulation reports integrityChecked: ${String(decapsulated.ok ? decapsulated.integrityChecked : false)}`,
            'p3c-kem-integrity',
          ),
        ]),
        note(
          [
            el('strong', { text: 'Clause 6.2.1 has no integrity check of any kind. ' }),
            'B1 is a membership test on C, B3\'s only error is an all-zero K′, and nothing binds K′ to '
              + 'the private key that produced it. So ok: true means "the procedure completed", never '
              + '"this was the right key". Below, the same ciphertext is decapsulated with ALICE\'s '
              + 'private key instead of Bob\'s.',
          ],
          true,
          'p3c-kem-no-integrity',
        ),
        kv(
          [
            [
              'decapsulated with Alice\'s key',
              hexBlock(wrong.ok ? bytesToHex(wrong.K) : `refused at ${wrong.step}`, 'p3c-kem-wrong-k'),
            ],
            [
              'did it report an error?',
              statusPill(
                wrong.ok ? 'alarm' : 'ok',
                wrong.ok ? 'no — it reported SUCCESS' : `yes, refused at ${wrong.step}`,
                'p3c-kem-wrong-status',
              ),
            ],
            [
              'silent divergence',
              statusPill(
                wrongAgreement.silentDivergence ? 'alarm' : 'ok',
                wrongAgreement.silentDivergence ? 'YES — a different key, reported as success' : 'no',
                'p3c-kem-divergence',
              ),
            ],
            ['what compareKemKeys says', el('span', { text: wrongAgreement.note, testid: 'p3c-kem-divergence-note' })],
          ],
          'p3c-kem-wrong',
        ),
        note(
          [
            'This is by construction rather than by oversight: a KEM\'s job ends at producing a key, and '
              + 'whatever uses that key is what is expected to notice. compareKemKeys is the only honest '
              + 'way to find out, and it needs the ENCAPSULATED key to do it — which is exactly the '
              + 'point, because the decapsulating side does not have one.',
          ],
          false,
          'p3c-kem-by-design',
        ),
      ]);
    });
  });

  runPke.addEventListener('click', () => {
    replace(pkeOut, [statusPill('info', 'computing')]);
    defer(() => {
      const ke = BigInt(`0x${PKE.master_encryption_private_key_ke}`);
      const hid = Number(`0x${PKE.hid}`);
      const master = encryptMasterKeyPair(ke);
      const bob = extractEncryptKey(master, 'Bob', { hid });
      if (!bob.ok) throw new Error('Annex D extraction returned a re-key outcome');

      const message = hexToBytes(PKE.message_hex);
      const pinned = {
        r: BigInt(`0x${PKE.common.A2_r}`),
        k1LenBits: PKE.K1_len_bits.value,
        k2LenBits: PKE.K2_len_bits.value,
      } as const;

      const modes: {
        mode: 'a' | 'b';
        label: string;
        annex: { C2: string; C3: string; full: string };
      }[] = [
        {
          mode: 'a',
          label: 'mode a) — K1 is a one-time pad the length of the message, C2 = M xor K1',
          annex: {
            C2: PKE.mode_a_kdf_stream_cipher.C2.value,
            C3: PKE.mode_a_kdf_stream_cipher.C3.value,
            full: PKE.mode_a_kdf_stream_cipher.ciphertext_C1_C3_C2.value,
          },
        },
        {
          mode: 'b',
          label: 'mode b) — K1 is an SM4 key, C2 = SM4-CBC(K1, M ‖ padding) with an all-zero IV',
          annex: {
            C2: PKE.mode_b_sm4_cbc_block_cipher.C2.value,
            C3: PKE.mode_b_sm4_cbc_block_cipher.C3.value,
            full: PKE.mode_b_sm4_cbc_block_cipher.ciphertext_C1_C3_C2.value,
          },
        },
      ];

      const blocks: HTMLElement[] = [
        kv(
          [
            ['receiver', el('span', { text: `Bob (${PKE.ID_B}), hid 0x${PKE.hid}` })],
            ['message', el('span', { text: `"${PKE.message_ascii}" (${PKE.mlen_bits.value} bits)` })],
            ['K1_len', el('span', { text: `${PKE.K1_len_bits.value} bits` })],
            ['K2_len', el('span', { text: `${PKE.K2_len_bits.value} bits` })],
          ],
          'p3c-pke-inputs',
        ),
      ];

      for (const { mode, label, annex } of modes) {
        const ct = encrypt(message, 'Bob', hid, master.Ppube, { ...pinned, mode });
        const out = decrypt(ct.bytes, 'Bob', bob.deB, {
          mode,
          k1LenBits: pinned.k1LenBits,
          k2LenBits: pinned.k2LenBits,
        });
        // One bit of C2 flipped, so the MAC at step B4 has something to refuse.
        const tampered = Uint8Array.from(ct.bytes);
        tampered[tampered.length - 1] ^= 0x01;
        const refused = decrypt(tampered, 'Bob', bob.deB, {
          mode,
          k1LenBits: pinned.k1LenBits,
          k2LenBits: pinned.k2LenBits,
        });

        const fullHex = bytesToHex(ct.bytes);
        blocks.push(
          el('div', { class: 'box' }, [
            el('h4', { text: label }),
            kv(
              [
                ['C1 = [r]Q_B', hexBlock(bytesToHex(ct.C1Bytes), `p3c-${mode}-c1`)],
                ['C3 = MAC(K2, C2)', hexBlock(bytesToHex(ct.C3), `p3c-${mode}-c3`)],
                ['C2', hexBlock(bytesToHex(ct.C2), `p3c-${mode}-c2`)],
                ['C = C1 ‖ C3 ‖ C2', hexBlock(fullHex, `p3c-${mode}-ciphertext`)],
                ['Annex D prints', hexBlock(annex.full)],
                [
                  'byte equality with Annex D',
                  equality(fullHex === annex.full, 'byte-identical', 'differs', `p3c-${mode}-badge`),
                ],
                [
                  'decrypted plaintext (from the decryption, not the input)',
                  hexBlock(out.ok ? bytesToHex(out.message) : `refused at ${out.step}: ${out.cause}`, `p3c-${mode}-plaintext`),
                ],
                [
                  'as text',
                  el('span', {
                    text: out.ok ? decodeUtf8(out.message) : 'not recovered',
                    testid: `p3c-${mode}-plaintext-text`,
                  }),
                ],
                [
                  'round trip',
                  statusPill(
                    out.ok ? 'ok' : 'bad',
                    out.ok ? 'clause 7.2.1 accepted and recovered M′' : `refused at ${out.step}`,
                    `p3c-${mode}-roundtrip`,
                  ),
                ],
                [
                  'one bit of C flipped',
                  statusPill(
                    refused.ok ? 'bad' : 'ok',
                    refused.ok ? 'ACCEPTED a tampered ciphertext' : `refused at ${refused.step}: ${refused.cause}`,
                    `p3c-${mode}-tampered`,
                  ),
                ],
              ],
              `p3c-${mode}-values`,
            ),
            mode === 'b'
              ? kv([['M ‖ padding, before B5 strips it', hexBlock(bytesToHex(ct.paddedMessage ?? new Uint8Array()), 'p3c-b-padded')]])
              : null,
            hexDetails('w = g^r, step A5', bytesToHex(ct.wBytes), `p3c-${mode}-w`),
          ]),
        );
      }

      blocks.push(
        note(
          [
            el('strong', { text: 'SM4 is an imported call, and its internals are out of scope here. ' }),
            'Mode b) reaches for GB/T 32907 SM4 in CBC with an all-zero IV, which is what Annex D '
              + 'exercises. No round function, key schedule or S-box is shown on this page: this lab is '
              + 'about SM9, and a second cipher\'s internals would be a different exhibit. The dependency '
              + 'is checked against GB/T 32907 Appendix A.1\'s own known-answer vectors in the test suite, '
              + 'including the one-million-round iterate.',
          ],
          false,
          'p3c-sm4-scope',
        ),
        note(
          [
            el('strong', { text: 'The one comparison that separates the two mechanisms. ' }),
            'Public key encryption adds C3 = MAC(K2, C2) and step B4: "u = MAC(K2′, C2); if u ≠ C3, '
              + 'report an error and exit". That single comparison is the entire difference between this '
              + 'act and the KEM above — tamper with a ciphertext here and you get a named cause, tamper '
              + 'with a KEM ciphertext and you get a key.',
          ],
          false,
          'p3c-mac-note',
        ),
      );

      replace(pkeOut, blocks);
    });
  });

  return detailsEl(
    '(c) KEM and public key encryption — GM/T 0044.5 Annexes C and D, hid 0x03',
    [
      para(
        'SM9\'s encryption IS its KEM with a DEM bolted on: steps A1 to A5 are identical. They diverge '
          + 'in exactly one place — what happens when decryption is handed the wrong thing.',
      ),
      controls([runKem]),
      kemOut,
      heading('Annex D — public key encryption, both modes'),
      controls([runPke]),
      pkeOut,
    ],
    'p3c-details',
  );
}

export function buildPane3(): HTMLElement {
  const { root, body } = pane(
    'PANE 3',
    'The three protocols',
    'GM/T 0044.2 clauses 6.1 and 7.1 · GM/T 0044.3 clause 6.1 · GM/T 0044.4 clauses 6 and 7',
    'p3-pane',
  );

  body.appendChild(
    para(
      'Three mechanisms run off the two master key pairs of pane 2, each beside the worked example '
        + 'GM/T 0044.5 prints for it. Every act compares its output against the annex\'s pinned bytes '
        + 'rather than against itself, because a round trip this lab runs against its own code cannot '
        + 'tell a correct implementation from a consistently wrong one — which act (a) finishes by '
        + 'demonstrating.',
    ),
  );
  body.appendChild(buildActA());
  body.appendChild(buildActB());
  body.appendChild(buildActC());

  return root;
}
