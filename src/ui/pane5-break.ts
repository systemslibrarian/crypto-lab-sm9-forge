/**
 * PANE 5 — the break, and the divergence. Two exhibits that fail differently.
 *
 * (a) IS A FAILURE. One reused nonce and the signer's private key falls out in
 * two lines of arithmetic. The page recovers it and then forges a signature on a
 * message the key's owner never saw, which the page's own unmodified verifier
 * accepts. The verdict for that state is ALARM.
 *
 * WHAT MAKES IT AN SM9 EXHIBIT RATHER THAN A GENERIC ONE. Every ECDSA-shaped
 * scheme has this break and every one of them recovers a SCALAR — the private
 * key is a number in Z_N and the reused nonce gives a linear equation it
 * satisfies. An SM9 private key is a GROUP ELEMENT ds_A in G1. There is no
 * number it "is", so there is nothing to solve for and nothing to return but the
 * point. The recovery result type in src/attack/nonce-reuse.ts has NO field for
 * a scalar, deliberately, and this panel says so on screen rather than leaving a
 * reader to notice the absence.
 *
 * (b) IS NOT A FAILURE, AND MUST NOT BE RENDERED AS ONE. The same master key,
 * the same identities and the same nonces produce two different session keys at
 * hid 0x03 and hid 0x02. Neither side is wrong: GM/T 0044.3 clause 5.3 says only
 * that the KGC "chooses a one-byte identifier hid and makes it public" and pins
 * no value, so 0x02 does not contradict the standard and 0x03 is a choice made
 * by an informative annex. Both results are rendered INFO and labelled by the
 * SOURCE that declares them. A divergence is an interoperability fact, not a
 * verdict, and colouring one of them red would be this page picking a side the
 * evidence does not support.
 *
 * THE MISPRINT AND THE CAUSAL CLAIM WE DO NOT MAKE. Annex B prints 0x02 in two
 * places where every other line says 0x03, and those two lines are misprints —
 * established here by recomputing H1 over both readings and seeing which one the
 * annex's own printed digest matches. That is a claim about the annex. It is NOT
 * a claim that the misprint caused GmSSL to choose 0x02: nobody has confirmed
 * that, GmSSL documents no reason, and the panel says so.
 */
import { HID, N } from '../sm9/params';
import { H1, bytesToHex, hexToBytes } from '../sm9/hash';
import { extractSignKey, signMasterKeyPair, toFieldHex } from '../sm9/extract';
import { randomNonce, sign, signatureToHex, verify } from '../sm9/sign';
import { g1ToHex, gtToHex, runKeyExchange } from '../sm9/exchange';
import {
  recoverFromKnownNonce,
  recoverFromReusedNonce,
  sameG1Point,
} from '../attack/nonce-reuse';
import annexA from '../sm9/fixtures/annexA-fixture.json';
import kexVectors from '../sm9/fixtures/sm9-keyexchange-vectors.json';
import {
  button,
  controls,
  defer,
  detailsEl,
  el,
  encodeUtf8,
  equality,
  heading,
  hexBlock,
  hexDetails,
  hidHex,
  kv,
  labelled,
  note,
  pane,
  para,
  replace,
  setVerdict,
  sourceTag,
  statusPill,
  tableEl,
  textInput,
  verdictSlot,
} from './dom';

const KS = BigInt(`0x${annexA.signature.ks}`);
const SM2_FORGE = 'https://systemslibrarian.github.io/crypto-lab-sm2-forge/';

const KEX = kexVectors.shared_inputs;
const PUBLISHED = kexVectors.annex_b_published;
const MISPRINTS = kexVectors.sources['hid-0x03'].known_misprints;

/** The H1 digest Annex B prints beside each misprinted input line. */
const PRINTED_H1_BESIDE: Record<string, { hex: string; lines: string; alsoPrintedAt: string }> = {
  '638-638': {
    hex: PUBLISHED.a1_h1.hex,
    lines: PUBLISHED.a1_h1.lines,
    alsoPrintedAt: `identical to the key-extraction H1 for ID_B at lines ${PUBLISHED.kg_B_h1.lines}`,
  },
  '659-659': {
    hex: PUBLISHED.b1_h1.hex,
    lines: PUBLISHED.b1_h1.lines,
    alsoPrintedAt: `identical to the key-extraction H1 for ID_A at lines ${PUBLISHED.kg_A_h1.lines}`,
  },
};

// ---------------------------------------------------------------------------
// (a) break it yourself
// ---------------------------------------------------------------------------

function buildBreak(): HTMLElement {
  const message1 = textInput('Release the build at 09:00.', 'p5a-msg1', 32);
  const message2 = textInput('Release the build at 17:00.', 'p5a-msg2', 32);
  const message3 = textInput('Grant the deploy key to the bearer of this note.', 'p5a-msg3', 44);
  const runButton = button('Sign both under ONE nonce, then recover and forge', 'p5a-run', 'danger');
  const refusalButton = button('Now sign the SAME message twice under that nonce', 'p5a-refusal-run', 'secondary');

  const breakVerdict = verdictSlot('p5a-forged-verdict', 'pending — nothing has been signed yet');
  const output = el('div', { testid: 'p5a-output' });
  const refusal = el('div', { testid: 'p5a-refusal' });

  runButton.addEventListener('click', () => {
    replace(output, [statusPill('info', 'computing')]);
    defer(() => {
      const master = signMasterKeyPair(KS);
      const extracted = extractSignKey(master, 'Alice', { hid: HID.SIGN });
      if (!extracted.ok) throw new Error(`extraction returned ${extracted.outcome}`);

      // ONE nonce, drawn properly, then handed to two signatures on purpose.
      // This is the only thing the signer does wrong.
      const reused = randomNonce();
      const nonce = (): bigint => reused;

      const m1 = encodeUtf8(message1.value);
      const m2 = encodeUtf8(message2.value);
      const m3 = encodeUtf8(message3.value);

      const sig1 = sign(m1, extracted.dsA, master.Ppubs, { nonce });
      const sig2 = sign(m2, extracted.dsA, master.Ppubs, { nonce });

      // The page's real verifier, before anything is attacked.
      const ok1 = verify(m1, 'Alice', sig1.signature, master.Ppubs, { hid: HID.SIGN });
      const ok2 = verify(m2, 'Alice', sig2.signature, master.Ppubs, { hid: HID.SIGN });

      const recovery = recoverFromReusedNonce(sig1.signature, sig2.signature);
      const fromKnownR = recoverFromKnownNonce(sig1.signature, reused);

      if (!recovery.ok) {
        replace(output, [
          kv([
            ['recovery refused', el('span', { text: recovery.reason, testid: 'p5a-unexpected-refusal' })],
            ['detail', el('span', { text: recovery.detail })],
          ]),
        ]);
        setVerdict(
          breakVerdict,
          'info',
          `the recovery refused: ${recovery.reason}`,
          'The two messages hashed to the same h, so there is no second independent equation. '
            + 'Change one of them and run again.',
        );
        return;
      }

      const recoveredIsGenuine = sameG1Point(recovery.dsA, extracted.dsA);

      // Forge on a THIRD message, with the recovered key and a fresh nonce.
      const forged = sign(m3, recovery.dsA, master.Ppubs, { nonce: randomNonce });
      const forgedChecked = verify(m3, 'Alice', forged.signature, master.Ppubs, { hid: HID.SIGN });
      const forgedHex = signatureToHex(forged.signature);

      replace(output, [
        heading('Step 1 — two signatures, one nonce, both genuine'),
        tableEl(
          ['', 'message', 'h', 'the real verifier'],
          [
            [
              el('span', { text: 'signature 1' }),
              el('span', { text: message1.value }),
              hexBlock(toFieldHex(sig1.signature.h), 'p5a-sig1-h'),
              statusPill(ok1.accepted ? 'ok' : 'bad', ok1.accepted ? 'ACCEPTED' : `refused at ${ok1.failure}`, 'p5a-sig1-verify'),
            ],
            [
              el('span', { text: 'signature 2' }),
              el('span', { text: message2.value }),
              hexBlock(toFieldHex(sig2.signature.h), 'p5a-sig2-h'),
              statusPill(ok2.accepted ? 'ok' : 'bad', ok2.accepted ? 'ACCEPTED' : `refused at ${ok2.failure}`, 'p5a-sig2-verify'),
            ],
          ],
          'p5a-signatures',
          'Two signatures made under one reused nonce',
        ),
        kv(
          [
            ['r, reused across both (never transmitted)', hexBlock(toFieldHex(reused), 'p5a-r')],
            [
              'the two nonces were the same',
              equality(sig1.r === sig2.r, 'yes — this is the mistake', 'no', 'p5a-same-nonce'),
            ],
          ],
          'p5a-nonce',
        ),

        heading('Step 2 — the arithmetic'),
        el('ul', { class: 'steps' }, [
          el('li', {}, [
            el('span', { class: 'step-label', text: 'S1' }),
            el('span', { class: 'step-val', text: '[(r − h1)]ds_A' }),
          ]),
          el('li', {}, [
            el('span', { class: 'step-label', text: 'S2' }),
            el('span', { class: 'step-val', text: '[(r − h2)]ds_A' }),
          ]),
          el('li', {}, [
            el('span', { class: 'step-label', text: 'S1 − S2' }),
            el('span', { class: 'step-val', text: '[(r − h1) − (r − h2)]ds_A = [h2 − h1]ds_A — the r cancels' }),
          ]),
          el('li', {}, [
            el('span', { class: 'step-label', text: 'ds_A' }),
            el('span', { class: 'step-val', text: '[(h2 − h1)⁻¹](S1 − S2) — one inversion mod N, one multiplication in G1' }),
          ]),
        ]),
        kv(
          [
            [
              'S1 − S2, the intermediate',
              hexBlock(
                recovery.sDifference === undefined
                  ? 'not produced by this method'
                  : `${toFieldHex(recovery.sDifference.X)}${toFieldHex(recovery.sDifference.Y)}`,
                'p5a-sdiff',
              ),
            ],
            ['method', el('span', { text: recovery.method, testid: 'p5a-method' })],
            ['recovered ds_A, x', hexBlock(toFieldHex(recovery.dsA.X), 'p5a-recovered-x')],
            ['recovered ds_A, y', hexBlock(toFieldHex(recovery.dsA.Y), 'p5a-recovered-y')],
            [
              'is it the key the KGC issued?',
              equality(recoveredIsGenuine, 'the same point in G1', 'a different point', 'p5a-recovered-matches'),
            ],
            [
              'recovered private SCALAR',
              el('span', {
                text: 'there is none. The result type has no field for one, because an SM9 private key '
                  + 'is a group element and not a number.',
                testid: 'p5a-no-scalar',
              }),
            ],
            [
              'the same key from the nonce alone',
              equality(
                fromKnownR.ok && sameG1Point(fromKnownR.dsA, extracted.dsA),
                'recovered from ONE signature and its r',
                'not recovered',
                'p5a-known-nonce',
              ),
            ],
          ],
          'p5a-recovery',
        ),
        note(
          [
            'The last row is the sharper form of the same fact: a leaked or predictable r on a SINGLE '
              + 'signature is already fatal, because ds_A = [(r − h)⁻¹]S. A second signature is only '
              + 'needed when r is unknown. That is why r must be unpredictable and secret, not merely '
              + 'non-repeating.',
          ],
          false,
          'p5a-known-nonce-note',
        ),

        heading('Step 3 — forge on a message the key\'s owner never saw'),
        kv(
          [
            ['forged message', el('span', { text: message3.value, testid: 'p5a-forged-message' })],
            ['signed with', el('span', { text: 'the RECOVERED ds_A, and a fresh random nonce' })],
            ['h', hexBlock(forgedHex.h, 'p5a-forged-h')],
            ['S', hexBlock(forgedHex.S, 'p5a-forged-s')],
            [
              'the page\'s own verifier, unmodified',
              statusPill(
                forgedChecked.accepted ? 'alarm' : 'ok',
                forgedChecked.accepted ? 'ACCEPTED as a signature by Alice' : `refused at ${forgedChecked.failure}`,
                'p5a-forged-accepted',
              ),
            ],
          ],
          'p5a-forged',
        ),
      ]);

      setVerdict(
        breakVerdict,
        forgedChecked.accepted ? 'alarm' : 'ok',
        forgedChecked.accepted
          ? 'FORGED AND ACCEPTED — the private key was recovered from two signatures and used on a third message'
          : `the forged signature was refused at ${forgedChecked.failure}`,
        'Nothing in the verifier is at fault and nothing was weakened to make this work. The signer '
          + 'reused one nonce, and clause 6.1\'s own algebra did the rest.',
      );
    });
  });

  refusalButton.addEventListener('click', () => {
    replace(refusal, [statusPill('info', 'computing')]);
    defer(() => {
      const master = signMasterKeyPair(KS);
      const extracted = extractSignKey(master, 'Alice', { hid: HID.SIGN });
      if (!extracted.ok) throw new Error(`extraction returned ${extracted.outcome}`);
      const reused = randomNonce();
      const nonce = (): bigint => reused;
      const m = encodeUtf8(message1.value);

      // The SAME message twice, under the same r: identical h, identical S.
      const sigA = sign(m, extracted.dsA, master.Ppubs, { nonce });
      const sigB = sign(m, extracted.dsA, master.Ppubs, { nonce });
      const outcome = recoverFromReusedNonce(sigA.signature, sigB.signature);

      const host = el('div', {});
      setVerdict(
        host,
        outcome.ok ? 'bad' : 'ok',
        outcome.ok
          ? 'a key was returned from a singular system — this should not happen'
          : `REFUSED — ${outcome.reason}`,
        outcome.ok
          ? 'Two signatures with the same h under the same r are one equation written twice.'
          : 'The refusal is a named result, not a caught exception, and no key-shaped value is returned '
            + 'in its place.',
      );

      replace(refusal, [
        host,
        kv(
          [
            ['h of signature A', hexBlock(toFieldHex(sigA.signature.h), 'p5a-refusal-h1')],
            ['h of signature B', hexBlock(toFieldHex(sigB.signature.h), 'p5a-refusal-h2')],
            [
              'are they equal?',
              equality(sigA.signature.h === sigB.signature.h, 'equal — one equation twice', 'different', 'p5a-refusal-equal'),
            ],
            [
              'reason',
              el('span', { text: outcome.ok ? 'none — a key was returned' : outcome.reason, testid: 'p5a-refusal-reason' }),
            ],
            [
              'detail',
              el('span', { text: outcome.ok ? '' : outcome.detail, testid: 'p5a-refusal-detail' }),
            ],
          ],
          'p5a-refusal-values',
        ),
        note(
          [
            'h2 − h1 = 0 has no inverse mod N, and S1 − S2 is the point at infinity. A library that '
              + 'divided anyway would return a plausible-looking point that is not the key. This one '
              + 'returns a structured refusal and never fabricates a key from a singular system.',
          ],
          false,
          'p5a-refusal-note',
        ),
      ]);
    });
  });

  return el('div', {}, [
    heading('(a) Break it yourself'),
    para(
      'SM9 signing draws a nonce r, computes h = H2(M ‖ g^r) and outputs S = [(r − h)]ds_A. Sign two '
        + 'different messages under the same r and the two S values differ by [h2 − h1]ds_A — so '
        + 'dividing by that known scalar hands over the private key. The r never enters the '
        + 'calculation; an attacker neither learns it nor needs it.',
    ),
    controls([
      labelled('First message', message1),
      labelled('Second message', message2),
      labelled('Message to forge', message3),
    ]),
    controls([runButton]),
    breakVerdict,
    output,
    heading('The refusal path: when the two hashes coincide'),
    para(
      'If the two signatures carry the same h there is no second independent equation. The recovery '
        + 'must refuse rather than return something key-shaped, and this is what that looks like.',
    ),
    controls([refusalButton]),
    refusal,
    heading('What was recovered, and why it is not a number'),
    note(
      [
        el('strong', { text: 'A point in G1 — the private key itself — and no scalar. ' }),
        'crypto-lab-sm2-forge runs the equivalent attack on SM2 and recovers a scalar d, because an '
          + 'SM2 private key IS a scalar in Z_N: the reused nonce gives a linear equation that d '
          + 'satisfies, and solving it yields a number. An SM9 private key is a group element ds_A in '
          + 'G1. There is no number it "is", so there is nothing to solve for and nothing to return but '
          + 'the point itself. Same mistake, same severity, a structurally different prize.',
      ],
      false,
      'p5a-sm2-comparison',
    ),
    el('p', {}, [
      'The SM2 version of this exhibit: ',
      el('a', {
        text: 'crypto-lab-sm2-forge',
        attrs: { href: SM2_FORGE, target: '_blank', rel: 'noopener' },
        testid: 'p5a-sm2-link',
      }),
      '.',
    ]),
  ]);
}

// ---------------------------------------------------------------------------
// (b) the divergence
// ---------------------------------------------------------------------------

function buildDivergence(): HTMLElement {
  const runButton = button('Run Annex B at both hid values', 'p5b-run');
  const output = el('div', { testid: 'p5b-output' }, [statusPill('pending', 'pending — not yet run')]);
  const misprintHost = el('div', { testid: 'p5b-misprint' });
  const literalHost = el('div', { testid: 'p5b-literal' });

  const base = {
    ke: BigInt(`0x${KEX.ke}`),
    idA: hexToBytes(KEX.ID_A),
    idB: hexToBytes(KEX.ID_B),
    rA: BigInt(`0x${KEX.r_A}`),
    rB: BigInt(`0x${KEX.r_B}`),
    klenBits: KEX.klen_bits,
  };

  runButton.addEventListener('click', () => {
    replace(output, [statusPill('info', 'computing')]);
    replace(misprintHost, [statusPill('info', 'computing')]);
    replace(literalHost, [statusPill('info', 'computing')]);
    defer(() => {
      const run03 = runKeyExchange({ ...base, hid: HID.ENCRYPT });
      const run02 = runKeyExchange({ ...base, hid: HID.EXCHANGE_GMSSL });
      // The annex read LITERALLY: 0x03 in the clause 5.3 extraction steps and
      // 0x02 in A1/B1, exactly as the two misprinted lines say.
      const literal = runKeyExchange({ ...base, hid: HID.ENCRYPT, protocolHid: HID.EXCHANGE_GMSSL });

      const sideBlock = (
        transcript: typeof run03,
        publishedSk: string,
      ): HTMLElement => {
        const convention = transcript.convention;
        const sk = bytesToHex(transcript.responder.sk);
        return el('div', { class: 'box', testid: `p5b-box-${hidHex(transcript.hid)}` }, [
          el('h4', { text: `hid ${hidHex(transcript.hid)}` }),
          el('div', {}, [
            sourceTag(convention?.source ?? 'no convention this lab knows', `p5b-source-${hidHex(transcript.hid)}`),
          ]),
          kv([
            ['kind of authority', el('span', { text: convention?.kind ?? 'unknown' })],
            ['declared at', el('span', { text: convention?.declaredAt ?? 'nowhere this lab has read' })],
            [
              'written down in GM/T 0044?',
              el('span', {
                text: convention?.inTheStandard === true ? 'yes — in an informative annex' : 'no',
                testid: `p5b-instandard-${hidHex(transcript.hid)}`,
              }),
            ],
            ['SK_B', hexBlock(sk, `p5b-sk-${hidHex(transcript.hid)}`)],
            ['SK_A', hexBlock(bytesToHex(transcript.initiator.sk))],
            [
              'the two sides agree',
              equality(transcript.agree, 'SK_A = SK_B', 'the sides DISAGREE', `p5b-agree-${hidHex(transcript.hid)}`),
            ],
            [
              'matches the key this source publishes',
              equality(sk === publishedSk, 'byte-identical', 'differs', `p5b-published-${hidHex(transcript.hid)}`),
            ],
          ]),
          el('div', {}, [
            statusPill('info', 'a conforming run under a declared convention', `p5b-status-${hidHex(transcript.hid)}`),
          ]),
        ]);
      };

      const gEqual =
        gtToHex(run03.responder.g1) === gtToHex(run02.responder.g1)
        && gtToHex(run03.responder.g2) === gtToHex(run02.responder.g2)
        && gtToHex(run03.responder.g3) === gtToHex(run02.responder.g3);

      replace(output, [
        el('div', { class: 'side-by-side' }, [
          sideBlock(run03, kexVectors.sources['hid-0x03'].published_SK),
          sideBlock(run02, kexVectors.sources['hid-0x02'].published_SK),
        ]),
        note(
          [
            el('strong', { text: 'Neither of those is wrong, and neither is rendered red. ' }),
            'GM/T 0044.2, .3 and .4 clause 5.3 each say only that the KGC "chooses a one-byte '
              + 'identifier hid and makes it public". The normative text pins no value at all, so 0x02 '
              + 'does not contradict the standard, and 0x03 is a choice made by an informative annex '
              + 'rather than a requirement. What the divergence produces is an interoperability failure '
              + 'with no error message: two conforming implementations complete the protocol, each '
              + 'internally consistent, and derive different keys. Each side\'s confirmation tags verify '
              + 'against its own. Nothing anywhere reports a fault.',
          ],
          false,
          'p5b-neither-wrong',
        ),
        heading('And yet the group elements are identical'),
        kv(
          [
            [
              'g1, g2 and g3 across the two hid values',
              equality(gEqual, 'byte-identical at 0x02 and 0x03', 'they differ', 'p5b-g-identical'),
            ],
            ['g1 at hid 0x03', hexDetails('g1, hid 0x03', gtToHex(run03.responder.g1), 'p5b-g1-03')],
            ['g1 at hid 0x02', hexDetails('g1, hid 0x02', gtToHex(run02.responder.g1), 'p5b-g1-02')],
            ['R_A at hid 0x03', hexBlock(g1ToHex(run03.RA), 'p5b-ra-03')],
            ['R_A at hid 0x02', hexBlock(g1ToHex(run02.RA), 'p5b-ra-02')],
            [
              'R_A across the two hid values',
              // INFO, not BAD. R_A differing is the mechanism of the divergence,
              // not a defect in either run, and a red badge here would be the
              // page calling one of two conforming conventions wrong.
              statusPill(
                'info',
                g1ToHex(run03.RA) === g1ToHex(run02.RA)
                  ? 'byte-identical'
                  : 'DIFFERENT — and this is the only thing that changes',
                'p5b-ra-differ',
              ),
            ],
          ],
          'p5b-g-values',
        ),
        note(
          [
            'hid enters in exactly one place — the scalar H1(ID ‖ hid, N) — and that scalar cancels. '
              + 'Writing t3 for B\'s clause 5.3 sum: Q_B = [t3]P1, so R_A = [r_A·t3]P1, while de_B = '
              + '[ke·t3⁻¹]P2. Then g1 = e(R_A, de_B) = e(P1, P2)^(r_A·t3·ke·t3⁻¹) = e(P1, P2)^(r_A·ke). '
              + 't3 is gone. This is the same cancellation that lets pane 3 verify a signature made under '
              + 'a wrong H1: changing hid changes SK only through R_A and R_B in the KDF input, never '
              + 'through the pairings.',
          ],
          false,
          'p5b-cancellation',
        ),
      ]);

      // --- the two misprinted lines -----------------------------------------
      const misprintRows = MISPRINTS.map((m) => {
        const printedBeside = PRINTED_H1_BESIDE[m.line];
        const h1OfPrinted = toFieldHex(H1(hexToBytes(m.printed), N).h);
        const h1OfCorrected = toFieldHex(H1(hexToBytes(m.should_be), N).h);
        return {
          m,
          printedBeside,
          h1OfPrinted,
          h1OfCorrected,
          printedMatches: h1OfPrinted === printedBeside.hex.toLowerCase(),
          correctedMatches: h1OfCorrected === printedBeside.hex.toLowerCase(),
        };
      });

      replace(misprintHost, [
        tableEl(
          [
            'Annex B line',
            'the bytes the annex prints',
            'H1 of those bytes, recomputed here',
            'the H1 the annex prints beside them',
            'do they agree?',
          ],
          misprintRows.flatMap(({ m, printedBeside, h1OfPrinted, h1OfCorrected, printedMatches, correctedMatches }) => [
            [
              el('span', { text: `line ${m.line} — as printed` }),
              hexBlock(m.printed, `p5b-misprint-${m.line}-printed`),
              hexBlock(h1OfPrinted, `p5b-misprint-${m.line}-h1-printed`),
              hexBlock(printedBeside.hex.toLowerCase()),
              equality(printedMatches, 'agree', 'DISAGREE', `p5b-misprint-${m.line}-printed-match`),
            ],
            [
              el('span', { text: `line ${m.line} — read as ${m.should_be.slice(-2)}` }),
              hexBlock(m.should_be, `p5b-misprint-${m.line}-corrected`),
              hexBlock(h1OfCorrected, `p5b-misprint-${m.line}-h1-corrected`),
              hexBlock(printedBeside.hex.toLowerCase()),
              equality(correctedMatches, 'agree', 'DISAGREE', `p5b-misprint-${m.line}-corrected-match`),
            ],
          ]),
          'p5b-misprint-table',
          "Annex B's two misprinted lines, with H1 recomputed over both readings",
        ),
        kv(
          MISPRINTS.map((m) => [
            `line ${m.line}`,
            el('span', { text: `${m.why}; ${PRINTED_H1_BESIDE[m.line].alsoPrintedAt}` }),
          ]),
          'p5b-misprint-why',
        ),
      ]);

      // --- the third leg: run the literal reading ----------------------------
      const literalVerdict = el('div', { testid: 'p5b-literal-verdict' });
      setVerdict(
        literalVerdict,
        literal.agree ? 'bad' : 'info',
        literal.agree
          ? 'the literal reading completed — the diagnosis needs revisiting'
          : 'the literal reading DOES NOT COMPLETE — the two sides derive different keys',
        'Annex B prints SK_A = SK_B. A reading of the annex under which the protocol fails is ruled '
          + 'out by the annex\'s own output, which is the third leg of the diagnosis and the only one '
          + 'that does not depend on recomputing a digest.',
      );

      replace(literalHost, [
        literalVerdict,
        kv(
          [
            [
              'reading',
              el('span', {
                text: 'hid 0x03 in the clause 5.3 extraction steps, hid 0x02 in steps A1 and B1 — exactly '
                  + 'as the two lines above say.',
              }),
            ],
            ['SK_A under that reading', hexBlock(bytesToHex(literal.initiator.sk), 'p5b-literal-ska')],
            ['SK_B under that reading', hexBlock(bytesToHex(literal.responder.sk), 'p5b-literal-skb')],
            [
              'do the two sides agree?',
              equality(literal.agree, 'they agree', 'they DISAGREE', 'p5b-literal-agree'),
            ],
            ['what Annex B publishes', hexBlock(PUBLISHED.SKA.hex, 'p5b-literal-published')],
          ],
          'p5b-literal-values',
        ),
      ]);
    });
  });

  return el('div', {}, [
    heading('(b) The divergence — one byte, two session keys'),
    para(
      'The same master key, the same two identities, the same two nonces. The only difference is the '
        + 'one-byte hid the KGC publishes, and the two widely-used values for it do not agree.',
    ),
    controls([runButton]),
    output,
    heading('The two lines Annex B misprints'),
    para(
      'Annex B declares hid 0x03 at line 574 and uses 0x03 in every extraction step. Two lines print '
        + '0x02 instead. Recomputing H1 over both readings settles which one the annex meant, because '
        + 'the annex prints the resulting digest immediately beside the input.',
    ),
    misprintHost,
    heading('The third leg: run the literal reading and look at the output'),
    misprintThirdLegNote(),
    literalHost,
    note(
      [
        el('strong', { text: 'What this page does NOT claim. ' }),
        'It does not claim the misprint caused GmSSL\'s choice of 0x02. That is an inference nobody has '
          + 'confirmed, GmSSL documents no reason for the value, and 0x02 appears in implementations '
          + 'whose relationship to this annex is unknown. Two separate facts are on this panel: the '
          + 'annex has two misprinted bytes, and the implementations use a different hid. Joining them '
          + 'into a cause would be a third claim with no evidence behind it.',
      ],
      false,
      'p5b-no-causation',
    ),
  ]);
}

function misprintThirdLegNote(): HTMLElement {
  return note(
    [
      'Two legs of the diagnosis are above: the digest printed beside each 02 input is the 0x03 image, '
        + 'and SM3 is not a constant function. The third leg needs no digest at all — take the 02 bytes '
        + 'literally, run the protocol, and see whether it works. The Chinese original carries the same '
        + 'two bytes, so this is a source misprint rather than a translation slip, and Annexes C and D '
        + 'print 03 throughout.',
    ],
    false,
    'p5b-third-leg-note',
  );
}

export function buildPane5(): HTMLElement {
  const { root, body } = pane(
    'PANE 5',
    'The break, and the divergence',
    'GM/T 0044.2 clause 6.1 · GM/T 0044.3 clause 6.1 and GM/T 0044.5 Annex B',
    'p5-pane',
  );

  body.appendChild(
    para(
      'Two exhibits that look similar on a status line and are nothing alike. The first is a failure: '
        + 'one reused nonce and the private key is gone. The second is a divergence: two implementations '
        + 'that both follow the standard and cannot talk to each other. One is rendered as an alarm and '
        + 'the other is not, and the difference between them is the point.',
    ),
  );
  body.appendChild(buildBreak());
  body.appendChild(buildDivergence());
  body.appendChild(
    detailsEl(
      'Where the two exhibits meet',
      [
        para(
          'Both come out of the same structural fact. Extraction makes t1 · t2 = master, so the master '
            + 'scalar can be recovered from the product whatever the identity hashed to — which is why '
            + 'hid cancels out of g1, g2 and g3, and why the verification equation never learns which '
            + 'identity it checked. The reused-nonce break is the same symmetry on the signature side: '
            + 'S is a known multiple of the private key point, and two of them give the multiplier away.',
        ),
      ],
      'p5-synthesis',
    ),
  );

  return root;
}
