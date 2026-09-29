/**
 * PANE 1 — the parameters, and the SM3 layer.
 *
 * WHAT THIS PANE IS FOR. It proves the standard's own numbers before any curve
 * is touched. H1, H2 and the KDF are pure SM3: no pairing, no scalar
 * multiplication, nothing that takes a millisecond. That makes this the
 * cheapest honest check in the lab, and running it FIRST is a claim about
 * method rather than about speed — if the hash layer disagrees with the annexes,
 * every pairing downstream is arithmetic on the wrong bytes, and no amount of
 * curve work will say so.
 *
 * The panel says out loud that no pairing runs here, because the interesting
 * property is the negative one: 30 vectors reproduced, and the elliptic curve
 * has not been involved in any of them.
 *
 * WHY THE ACTION COMES BEFORE THE PARAMETER DUMP. This panel used to open with
 * twelve rows of BN256 constants and a five-row identifier table, which put the
 * first button on the page two thousand pixels down and asked the reader to
 * inspect a parameter set before they had any reason to care what it was for.
 * The constants have not moved out of the lab — they are one disclosure away,
 * where a reader who wants to check q against the formula printed beside it can
 * still reach every nibble. They are no longer the first thing anybody meets.
 *
 * EVERY FIGURE ON THIS PANEL IS DERIVED FROM THE RUN OR FROM THE FIXTURE'S OWN
 * INPUTS. The SM3 message length and block count come back from hash.ts's own
 * result for H1 and H2, and are recomputed the same way for the KDF, which
 * returns bytes alone. Nothing reads the fixture's `sm3_blocks_compressed` and
 * presents it as a measurement; that field is used only as a cross-check column.
 */
import { H1, H2, KDF, bytesToHex, hexToBytes } from '../sm9/hash';
import {
  B,
  BETA,
  CID,
  COFACTOR,
  EID,
  EMBEDDING_DEGREE,
  HID,
  N,
  P1,
  P2,
  Q,
  T,
  TRACE,
} from '../sm9/params';
import { toFieldHex } from '../sm9/extract';
import hashVectorsJson from '../sm9/fixtures/sm9-hash-vectors.json';
import type { Exhibit, ExhibitHost } from './exhibit';
import {
  button,
  clear,
  controls,
  defer,
  detailsEl,
  el,
  hexBlock,
  kv,
  matchMark,
  note,
  pane,
  para,
  replace,
  sourceTag,
  statusPill,
  tableEl,
} from './dom';

/**
 * The vector shape, declared rather than inferred.
 *
 * TypeScript types a JSON array as a union of its element shapes, and these
 * elements differ — the KDF rows carry `klen_bits`, the H1/H2 rows carry
 * `n_hex`, the generated rows carry `identity_utf8`. Declaring the union once
 * here is what keeps every access site optional-aware instead of casting at each
 * one.
 */
interface HashVector {
  id: string;
  fn: 'H1' | 'H2' | 'KDF';
  annex: string;
  description: string;
  input_hex: string;
  input_bytes: number;
  expected_hex: string;
  sm3_blocks_compressed: number;
  n_hex?: string;
  klen_bits?: number;
  identity_utf8?: string;
  standard_correction?: string;
}

const VECTORS = hashVectorsJson.vectors as unknown as HashVector[];

/**
 * A deliberately WRONG vector, run alongside the real ones as a negative control.
 *
 * Every genuine vector here passes, which sounds like good news and is actually a
 * measurement problem: a checker that only ever sees agreement is indistinguishable
 * from a checker that cannot report disagreement. Mutating the per-vector comparison
 * to `actual === expected || true` left the whole claims suite green for exactly that
 * reason -- there was no case the change could alter.
 *
 * This row fixes that. It is the Annex A H1 input with one nibble of its EXPECTED
 * value changed, so the correct answer is that it does NOT match. The page asserts
 * it is reported as a mismatch, and the totals count it separately from the real
 * vectors so it can never be mistaken for one.
 */
const CONTROL_VECTOR: HashVector = (() => {
  const source = VECTORS.find((v) => v.fn === 'H1' && v.annex !== 'GENERATED');
  if (source === undefined) throw new Error('no annex H1 vector to build the control from');
  const flipped = source.expected_hex.toLowerCase();
  const lastNibble = flipped.slice(-1);
  return {
    ...source,
    id: 'CONTROL-must-fail',
    annex: 'CONTROL',
    description: 'negative control: the same input with one nibble of the expected value changed',
    expected_hex: flipped.slice(0, -1) + (lastNibble === '0' ? '1' : '0'),
  };
})();

/** A one-byte identifier as the standard writes it, rendered from the constant
 *  rather than retyped — a literal here could drift from params.ts in silence. */
function hexByte(value: number): string {
  return `0x${value.toString(16).padStart(2, '0')}`;
}

/** SM3 compresses 64-byte blocks and appends a 9-byte length-and-padding tail. */
function sm3BlocksFor(messageBytes: number): number {
  return Math.ceil((messageBytes + 9) / 64);
}

interface VectorRun {
  vector: HashVector;
  expected: string;
  actual: string;
  passed: boolean;
  /** Length of the message SM3 actually compressed, in bytes. */
  sm3MessageBytes: number;
  sm3Blocks: number;
}

/**
 * Drive one vector through the real H1 / H2 / KDF.
 *
 * The H1 and H2 branches take their message length and block count from the
 * function's own returned result; the KDF branch recomputes both from the input
 * it was given, because `KDF` returns key bytes and nothing else. Both are
 * measurements of this run, not figures copied out of the fixture.
 */
function runVector(vector: HashVector): VectorRun {
  const input = hexToBytes(vector.input_hex);
  const expected = vector.expected_hex.toLowerCase();

  if (vector.fn === 'KDF') {
    if (vector.klen_bits === undefined) throw new Error(`${vector.id}: a KDF vector with no klen`);
    const actual = bytesToHex(KDF(input, vector.klen_bits));
    // Z || ct, where ct is the 4-byte counter of GM/T 0044.3 clause 5.4.3 step 2.
    const sm3MessageBytes = input.length + 4;
    return {
      vector,
      expected,
      actual,
      passed: actual === expected,
      sm3MessageBytes,
      sm3Blocks: sm3BlocksFor(sm3MessageBytes),
    };
  }

  const n = vector.n_hex === undefined ? N : BigInt(`0x${vector.n_hex}`);
  const result = vector.fn === 'H1' ? H1(input, n) : H2(input, n);
  const actual = toFieldHex(result.h);
  return {
    vector,
    expected,
    actual,
    passed: actual === expected,
    sm3MessageBytes: result.sm3InputBytes,
    sm3Blocks: result.sm3Blocks,
  };
}

/** Facts about the FIXTURE's inputs, read off the inputs themselves. */
function inputProfile(): {
  annexH1Total: number;
  annexH1Min: number;
  annexH1Max: number;
  annexSingleBlock: number;
  generatedH1: number;
  generatedMultiBlock: number;
} {
  const annexH1 = VECTORS.filter((v) => v.fn === 'H1' && v.annex !== 'GENERATED');
  const generatedH1 = VECTORS.filter((v) => v.fn === 'H1' && v.annex === 'GENERATED');
  const blocks = (v: HashVector): number => sm3BlocksFor(1 + v.input_bytes + 4);
  return {
    annexH1Total: annexH1.length,
    annexH1Min: Math.min(...annexH1.map((v) => v.input_bytes)),
    annexH1Max: Math.max(...annexH1.map((v) => v.input_bytes)),
    annexSingleBlock: annexH1.filter((v) => blocks(v) === 1).length,
    generatedH1: generatedH1.length,
    generatedMultiBlock: generatedH1.filter((v) => blocks(v) > 1).length,
  };
}

function parameterTable(): HTMLElement {
  return kv(
    [
      ['t', hexBlock(`0x${T.toString(16)}`, 'p1-param-t')],
      ['q = 36t⁴+36t³+24t²+6t+1', hexBlock(toFieldHex(Q), 'p1-param-q')],
      ['N = 36t⁴+36t³+18t²+6t+1', hexBlock(toFieldHex(N), 'p1-param-n')],
      ['tr(t) = 6t²+1', hexBlock(`0x${TRACE.toString(16)}`, 'p1-param-trace')],
      ['b, in y² = x³ + b', el('span', { text: B.toString(), testid: 'p1-param-b' })],
      ['cofactor cf', el('span', { text: `${COFACTOR} — so N is the full curve order`, testid: 'p1-param-cofactor' })],
      ['embedding degree k', el('span', { text: String(EMBEDDING_DEGREE), testid: 'p1-param-k' })],
      [
        'β (twist parameter, Fq2 non-residue)',
        el('span', {
          text: `${BETA} — not -1, which every generic BN254 library hardcodes`,
          testid: 'p1-param-beta',
        }),
      ],
      ['P1 x', hexBlock(toFieldHex(P1.x), 'p1-param-p1x')],
      ['P1 y', hexBlock(toFieldHex(P1.y), 'p1-param-p1y')],
      ['P2 x (Fq2, printed high then low)', hexBlock(`${toFieldHex(P2.x.hi)} ${toFieldHex(P2.x.lo)}`, 'p1-param-p2x')],
      ['P2 y (Fq2, printed high then low)', hexBlock(`${toFieldHex(P2.y.hi)} ${toFieldHex(P2.y.lo)}`, 'p1-param-p2y')],
    ],
    'p1-parameters',
  );
}

function identifierTable(): HTMLElement {
  return tableEl(
    ['Identifier', 'Byte', 'What the byte means'],
    [
      [
        el('span', { text: 'curve identifier cid' }),
        el('span', { text: hexByte(CID), testid: 'p1-param-cid' }),
        el('span', {
          text: 'an ordinary curve and its corresponding twist — GM/T 0044.1 clause 8.1 a) and c). '
            + 'The low nibble 2 is the twist, and it is why β appears in the parameter set at all.',
          testid: 'p1-param-cid-words',
        }),
      ],
      [
        el('span', { text: 'pairing identifier eid' }),
        el('span', { text: hexByte(EID), testid: 'p1-param-eid' }),
        el('span', {
          text: 'the R-ate pairing — GM/T 0044.1 clause 8.1 h) assigns 0x01 Tate, 0x02 Weil, '
            + '0x03 Ate, 0x04 R-ate. SM9 is R-ate.',
          testid: 'p1-param-eid-words',
        }),
      ],
      [
        el('span', { text: 'hid, signature' }),
        el('span', { text: hexByte(HID.SIGN), testid: 'p1-hid-sign' }),
        el('span', { text: 'declared by GM/T 0044.5 Annex A. The normative clause 5.3 pins no value.' }),
      ],
      [
        el('span', { text: 'hid, key exchange (GmSSL)' }),
        el('span', { text: hexByte(HID.EXCHANGE_GMSSL), testid: 'p1-hid-exchange' }),
        el('span', {
          text: 'NOT in GM/T 0044 at all — GmSSL\'s SM9_HID_EXCH, also used by emmansun/gmsm. '
            + 'Pane 5 runs both and shows what the difference costs.',
        }),
      ],
      [
        el('span', { text: 'hid, encryption' }),
        el('span', { text: hexByte(HID.ENCRYPT), testid: 'p1-hid-encrypt' }),
        el('span', { text: 'declared by GM/T 0044.5 Annexes B, C and D — key exchange included.' }),
      ],
    ],
    'p1-identifiers',
    'The curve, pairing and hid identifier bytes decoded into words',
  );
}

function vectorRow(run: VectorRun): HTMLElement[] {
  const { vector } = run;
  const source = vector.annex === 'GENERATED'
    ? el('div', {}, [
        sourceTag('generated here'),
        el('div', { text: 'the annexes never exercise a multi-block H1 input, so these were built and cross-checked against OpenSSL SM3 and GmSSL C.' }),
      ])
    : el('div', {}, [
        sourceTag(`GM/T 0044.5 Annex ${vector.annex}`),
        vector.standard_correction === undefined
          ? null
          : el('div', { text: `standard correction: ${vector.standard_correction}` }),
      ]);

  return [
    el('div', {}, [
      el('div', { text: vector.id }),
      el('div', { text: vector.description }),
    ]),
    el('span', { text: vector.fn }),
    source,
    el('span', { text: String(vector.input_bytes) }),
    el('span', { text: String(run.sm3MessageBytes) }),
    el('span', { text: String(run.sm3Blocks) }),
    el('div', {}, [
      matchMark(run.passed, `p1-vec-${vector.id}`),
      // Both values are rendered ALWAYS, not only when they disagree. A tick that
      // is the only evidence for its own claim cannot be checked by anything -- a
      // source mutation that made `passed` unconditionally true left the whole
      // claims suite green precisely because the numbers behind it were hidden on
      // the passing path. Printing both makes the badge falsifiable from the page.
      el('div', {}, [
        hexBlock(run.expected, `p1-vec-${vector.id}-expected`),
        hexBlock(run.actual, `p1-vec-${vector.id}-actual`),
      ]),
    ]),
  ];
}

export function buildPane1(host: ExhibitHost): Exhibit {
  const { root, body } = pane(
    'PANE 1',
    'Parameters, and the SM3 layer',
    'GM/T 0044.5 clause 3.1 · GM/T 0044.4 clauses 5.4.2.2 and 5.4.2.3 · GM/T 0044.3 clause 5.4.3',
    'p1-pane',
  );

  // ONE SENTENCE BEFORE THE BUTTON. The framing this pane needs is real and it is
  // all still here — it just comes after the run, beside the result it is about,
  // because prose above the first control is prose a visitor scrolls past to
  // reach the thing they came to press.
  body.appendChild(
    para(
      'Everything downstream is arithmetic on bytes H1, H2 and the KDF produce, and all three are SM3 '
        + 'and nothing else. Check them first.',
    ),
  );

  const profile = inputProfile();

  const runButton = button('Run the SM3 checks', 'p1-run-sm3');
  const summary = el('div', { testid: 'p1-sm3-summary' }, [
    statusPill('pending', 'pending — not yet run'),
  ]);
  const results = el('div', { testid: 'p1-sm3-results' });

  runButton.addEventListener('click', () => {
    replace(summary, [statusPill('info', 'computing')]);
    clear(results);
    defer(() => {
      const runs = VECTORS.map(runVector);
      // Run the negative control beside them. It MUST be reported as a mismatch;
      // if it ever passes, the comparison has stopped comparing.
      const control = runVector(CONTROL_VECTOR);
      const passed = runs.filter((r) => r.passed).length;
      const failed = runs.length - passed;
      const published = runs.filter((r) => r.vector.annex !== 'GENERATED');
      const generated = runs.filter((r) => r.vector.annex === 'GENERATED');

      replace(summary, [
        statusPill(failed === 0 ? 'ok' : 'bad', failed === 0 ? 'ALL VECTORS REPRODUCED' : 'FAILURES', 'p1-sm3-status'),
        ' ',
        el('span', { text: `${passed} passed`, testid: 'p1-sm3-passed' }),
        ' ',
        statusPill(
          control.passed ? 'bad' : 'ok',
          control.passed
            ? 'NEGATIVE CONTROL PASSED — the comparison has stopped comparing'
            : 'negative control correctly reported as a mismatch',
          'p1-sm3-control',
        ),
        ' · ',
        el('span', { text: `${failed} failed`, testid: 'p1-sm3-failed' }),
        ' · ',
        el('span', { text: `${runs.length} total`, testid: 'p1-sm3-total' }),
        ' · ',
        el('span', {
          text: `${published.filter((r) => r.passed).length}/${published.length} published in the annexes`,
          testid: 'p1-sm3-published',
        }),
        ' · ',
        el('span', {
          text: `${generated.filter((r) => r.passed).length}/${generated.length} generated for the multi-block gap`,
          testid: 'p1-sm3-generated',
        }),
        ' · ',
        el('span', { text: '0 pairings', testid: 'p1-sm3-pairings' }),
      ]);

      // THE HEADLINE FIRST, THE THIRTY-ONE ROWS ONE CLICK AWAY. The table is the
      // evidence and it stays reachable in full; it is not what a reader needs in
      // front of them to know what just happened. Only the summary above is.
      replace(results, [
        note(
          [
            el('strong', { text: 'What the standard does not exercise. ' }),
            `Every H1 input the annexes print is ${profile.annexH1Min} to ${profile.annexH1Max} bytes long — an identity `
              + `plus its one hid byte — and ${profile.annexSingleBlock} of those ${profile.annexH1Total} fit in a single 64-byte SM3 block. `
              + `The multi-block path is therefore never tested by the standard's own vectors. `
              + `The ${profile.generatedH1} vectors marked "generated here", of which ${profile.generatedMultiBlock} span more than one block, `
              + 'were built for that gap and cross-checked against OpenSSL\'s SM3 and against GmSSL C\'s '
              + 'compiled sm9_z256_hash1 — two codebases sharing no line with this one.',
          ],
          false,
          'p1-blocks-note',
        ),
        detailsEl(
          `Inspect all ${runs.length + 1} vector rows, with every expected and computed value`,
          [
            tableEl(
              ['Vector', 'Function', 'Source', 'Z bytes', 'SM3 message bytes', '64-byte blocks', 'Result'],
              // The negative control is rendered as a row like any other, so its printed
              // values can be compared against its badge exactly as the real vectors are.
              // Keeping it as a summary pill only left it unfalsifiable: a mutation that
              // printed the expected value in place of the computed one changed nothing
              // any test could see, because no rendered row disagreed with itself.
              [...runs, control].map(vectorRow),
              'p1-sm3-table',
              'Every SM3 layer vector, with its result',
            ),
          ],
          'p1-sm3-rows',
        ),
      ]);

      // The step is complete only when the run agreed AND the negative control
      // disagreed. A page that unlocked on "the button was pressed" would unlock
      // on a failure as readily as on a pass.
      if (failed === 0 && !control.passed) {
        host.onComplete(
          `${published.filter((r) => r.passed).length}/${published.length} published vectors reproduced · `
            + `${generated.filter((r) => r.passed).length}/${generated.length} generated for the multi-block gap · `
            + 'negative control correctly reported as a mismatch · 0 pairings',
        );
      } else {
        host.onStale();
      }
    });
  });

  body.appendChild(controls([runButton, summary]));
  body.appendChild(
    para(
      'Identity-based cryptography makes a promise: your name is your public key. Nobody fetches a '
        + 'certificate, because anybody holding the system parameters can compute a public point for '
        + 'the string "Alice" without asking Alice. What that buys in convenience it pays for in '
        + 'structure — somebody has to mint the matching private key, which is what step 2 does.',
    ),
  );
  body.appendChild(
    note(
      [
        el('strong', { text: 'No pairing runs on this panel, and that is the point. ' }),
        'H1, H2 and the KDF are SM3 and nothing else — no curve arithmetic, no field extension, no '
          + 'pairing. If this layer disagrees with the annexes then every pairing downstream is '
          + 'operating on the wrong bytes, and no amount of curve work will say so. It is the '
          + 'cheapest honest check in the lab, so it is the first one, and the count of pairings it '
          + 'performed is reported beside its result above.',
      ],
      false,
      'p1-no-pairing-note',
    ),
  );
  body.appendChild(results);

  body.appendChild(
    detailsEl(
      'Inspect the BN256 parameter set',
      [
        para(
          'Read out of the official GM/T 0044.5-2016 text. The defining formulas are printed in the '
            + 'standard alongside the values, so src/sm9/params.test.ts recomputes q, N and the trace '
            + 'from t rather than trusting the transcription.',
        ),
        parameterTable(),
      ],
      'p1-parameter-details',
    ),
  );

  body.appendChild(
    detailsEl(
      'Inspect the identifier bytes, decoded into words',
      [identifierTable()],
      'p1-identifier-details',
    ),
  );

  body.appendChild(
    detailsEl(
      'How H1 and H2 are built, and why they are the same function',
      [
        para(
          'H1 and H2 are one construction separated by a single leading byte — 0x01 for H1, 0x02 for '
            + 'H2. For SM9\'s 256-bit N the standard\'s hlen works out to 320 bits, so each is exactly '
            + 'two SM3 calls concatenated and truncated to 40 bytes, then reduced into [1, N-1]. The '
            + '"SM3 message bytes" column in the table above is 1 + |Z| + 4: the domain byte, the '
            + 'input, and the four-byte counter that the chain increments.',
        ),
        para(
          'The KDF is a different function in a different part of the standard — GM/T 0044.3 clause '
            + '5.4.3 — with no domain byte at all, which is why its SM3 message is |Z| + 4.',
        ),
      ],
      'p1-construction-details',
    ),
  );

  return {
    root,
    reset: () => {
      replace(summary, [statusPill('pending', 'pending — not yet run')]);
      clear(results);
    },
  };
}
