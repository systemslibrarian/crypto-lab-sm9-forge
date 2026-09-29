/**
 * PANE 2 — extraction, and the inversion. The headline act.
 *
 * WHAT A VISITOR SHOULD LEAVE WITH. SM9 does not turn your name into a private
 * key by hashing it onto the curve and multiplying by the master secret. It
 * hashes your name to a SCALAR, adds the master secret to it, and INVERTS that
 * sum in the exponent:
 *
 *     h1 = H1(ID‖hid, N)      t1 = h1 + master      t2 = master · t1⁻¹
 *     key = [t2]P
 *
 * The inversion is the whole mechanism, and it is rendered as its own step
 * below rather than folded into the line that produces t2, because a reader who
 * sees only `t2 = master · t1⁻¹` sees a formula and a reader who sees t1⁻¹ as a
 * value sees an operation.
 *
 * It is also the source of every other exhibit in this lab. t1 · t2 = master
 * for ANY h1 whatsoever, which is why pane 3 can extract with a deliberately
 * wrong H1 and still verify, why pane 5's key exchange reaches the same g1, g2
 * and g3 at two different hid values, and why the KGC in pane 4 can reissue any
 * identity's key at will.
 *
 * THE MASTER KEYS ARE THE ANNEXES' OWN. Both are read from the fixtures rather
 * than drawn at random, so that a visitor running the default settings is
 * reproducing GM/T 0044.5 Annex A byte for byte and can see the annex's pinned
 * intermediates agree — which is the ONLY check that catches a wrong H1, since
 * the round trip cannot.
 */
import { HID, N } from '../sm9/params';
import { inv, mul } from '../sm9/fn';
import { bytesToHex } from '../sm9/hash';
import {
  encryptMasterKeyPair,
  extractEncryptKey,
  extractSignKey,
  fp2Components,
  masterKeyForcingT1Zero,
  signMasterKeyPair,
  toFieldHex,
} from '../sm9/extract';
import type { EncryptKeyOutcome, SignKeyOutcome } from '../sm9/extract';
import annexA from '../sm9/fixtures/annexA-fixture.json';
import annexCD from '../sm9/fixtures/sm9-annex-cd-fixtures.json';
import {
  box,
  button,
  clear,
  controls,
  defer,
  detailsEl,
  el,
  equality,
  heading,
  hexBlock,
  hidHex,
  kv,
  labelled,
  note,
  pane,
  para,
  replace,
  selectInput,
  setVerdict,
  sideBySide,
  sourceTag,
  statusPill,
  stepList,
  svgEl,
  tableEl,
  textInput,
  verdictSlot,
} from './dom';

/** GM/T 0044.5 Annex A's signature master private key. */
const ANNEX_KS = BigInt(`0x${annexA.signature.ks}`);
/** GM/T 0044.5 Annexes C and D's encryption master private key. */
const ANNEX_KE = BigInt(`0x${annexCD.annex_C_kem.master_encryption_private_key_ke}`);

type Side = 'signature' | 'encryption';

const IBE_GATE = 'https://systemslibrarian.github.io/crypto-lab-ibe-gate/';

interface Rendered {
  outcome: SignKeyOutcome | EncryptKeyOutcome;
  master: bigint;
  side: Side;
}

function masterScalar(side: Side): bigint {
  return side === 'signature' ? ANNEX_KS : ANNEX_KE;
}

function extract(side: Side, identity: string, hid: number, master: bigint): SignKeyOutcome | EncryptKeyOutcome {
  return side === 'signature'
    ? extractSignKey(signMasterKeyPair(master), identity, { hid })
    : extractEncryptKey(encryptMasterKeyPair(master), identity, { hid });
}

/** The user key as the annexes print it: x‖y for G1, and each Fq2 high-then-low for G2. */
function keyHex(outcome: SignKeyOutcome | EncryptKeyOutcome): { x: string; y: string; group: string } {
  if (!outcome.ok) throw new Error('keyHex: called on a re-key outcome, which has no key');
  if ('dsA' in outcome) {
    return { x: toFieldHex(outcome.dsA.X), y: toFieldHex(outcome.dsA.Y), group: 'G1' };
  }
  return {
    x: fp2Components(outcome.deB.X).join(''),
    y: fp2Components(outcome.deB.Y).join(''),
    group: 'G2',
  };
}

/**
 * The annex row this run reproduces, if it reproduces one.
 *
 * Only the exact parameter set an annex prints counts: change the identity, the
 * hid or the side and there is nothing pinned to compare against, and the panel
 * says so rather than comparing against the nearest thing.
 */
function annexExpectation(side: Side, identity: string, hid: number):
  | { label: string; h1: string; t1: string; t2: string; x: string; y: string }
  | undefined {
  if (side === 'signature' && identity === annexA.signature.identity.ascii && hid === 0x01) {
    return {
      label: 'GM/T 0044.5 Annex A',
      h1: annexA.signature.H1,
      t1: annexA.signature.t1,
      t2: annexA.signature.t2,
      x: annexA.signature.dsA.x,
      y: annexA.signature.dsA.y,
    };
  }
  if (side === 'encryption' && identity === annexCD.annex_C_kem.ID_B_ascii && hid === 0x03) {
    const k = annexCD.annex_C_kem.key_extraction;
    return {
      label: 'GM/T 0044.5 Annex C',
      h1: k.H1_ID_hid.value,
      t1: k.t1.value,
      t2: k.t2.value,
      x: k.de_B_x.value,
      y: k.de_B_y.value,
    };
  }
  return undefined;
}

/** The SVG label helper — presentation attributes only, never a style attribute. */
function svgText(x: number, y: number, text: string, size = 13, anchor = 'middle', opacity = '1'): SVGElement {
  return svgEl(
    'text',
    {
      x: String(x),
      y: String(y),
      'font-size': String(size),
      'text-anchor': anchor,
      fill: 'currentColor',
      'fill-opacity': opacity,
    },
    [text],
  );
}

function svgBox(x: number, y: number, w: number, h: number, opacity = '0.55'): SVGElement {
  return svgEl('rect', {
    x: String(x),
    y: String(y),
    width: String(w),
    height: String(h),
    rx: '8',
    fill: 'none',
    stroke: 'currentColor',
    'stroke-opacity': opacity,
  });
}

/**
 * The mirror: signature keys live in G1 under a G2 master public key, encryption
 * keys in G2 under a G1 master public key. The crossing dashed lines are the
 * whole message — the same group appears on opposite rows of the two sides.
 */
function mirrorDiagram(): HTMLElement {
  const svg = svgEl(
    'svg',
    {
      viewBox: '0 0 760 260',
      width: '100%',
      role: 'img',
      'aria-labelledby': 'p2-mirror-title p2-mirror-desc',
      'data-testid': 'p2-mirror-diagram',
    },
    [
      svgEl('title', { id: 'p2-mirror-title' }, ['SM9 puts the two key types in mirrored groups']),
      svgEl('desc', { id: 'p2-mirror-desc' }, [
        'The signature master public key is in G2 and the user signature key is in G1. '
          + 'The encryption master public key is in G1 and the user encryption key is in G2. '
          + 'The two sides are mirror images: the same group appears on opposite rows.',
      ]),

      svgText(190, 26, 'SIGNATURE — GM/T 0044.2 clause 5.3', 13),
      svgText(570, 26, 'ENCRYPTION — GM/T 0044.3 clause 5.3', 13),

      // master public keys
      svgBox(30, 46, 320, 64),
      svgText(190, 72, 'Ppub-s = [ks]P2', 15),
      svgText(190, 96, 'master public key in G2', 12, 'middle', '0.75'),

      svgBox(410, 46, 320, 64),
      svgText(570, 72, 'Ppub-e = [ke]P1', 15),
      svgText(570, 96, 'master public key in G1', 12, 'middle', '0.75'),

      // user keys
      svgBox(30, 176, 320, 64),
      svgText(190, 202, 'ds_A = [t2]P1', 15),
      svgText(190, 226, 'user key in G1', 12, 'middle', '0.75'),

      svgBox(410, 176, 320, 64),
      svgText(570, 202, 'de_B = [t2]P2', 15),
      svgText(570, 226, 'user key in G2', 12, 'middle', '0.75'),

      // the crossing that names the mirror
      svgEl('line', {
        x1: '350', y1: '78', x2: '410', y2: '208',
        stroke: 'currentColor', 'stroke-opacity': '0.45', 'stroke-dasharray': '5 4',
      }),
      svgEl('line', {
        x1: '350', y1: '208', x2: '410', y2: '78',
        stroke: 'currentColor', 'stroke-opacity': '0.45', 'stroke-dasharray': '5 4',
      }),
      svgText(380, 140, 'same group', 11, 'middle', '0.7'),
      svgText(380, 154, 'opposite rows', 11, 'middle', '0.7'),

      svgText(380, 260, 'the scalar arithmetic is identical on both sides — only the groups swap', 12, 'middle', '0.75'),
    ],
  );
  return el('div', {}, [svg]);
}

/** Boneh–Franklin beside SM9. Static: nothing here runs, and nothing here should. */
function bonehFranklinDiagram(): HTMLElement {
  const svg = svgEl(
    'svg',
    {
      viewBox: '0 0 780 250',
      width: '100%',
      role: 'img',
      'aria-labelledby': 'p2-bf-title p2-bf-desc',
      'data-testid': 'p2-bf-diagram',
    },
    [
      svgEl('title', { id: 'p2-bf-title' }, ['Boneh-Franklin hashes to a curve point; SM9 hashes to a scalar and inverts']),
      svgEl('desc', { id: 'p2-bf-desc' }, [
        'Boneh-Franklin maps an identity onto a curve point Q_ID and multiplies it by the master '
          + 'scalar s to give d_ID. SM9 maps the identity and its hid byte to a scalar h1, adds the '
          + 'master scalar, inverts the sum, and multiplies the generator by the result.',
      ]),

      svgText(390, 24, 'Boneh-Franklin (2001) — hash to a CURVE POINT, then multiply', 13),
      svgBox(20, 40, 210, 56),
      svgText(125, 64, 'ID', 15),
      svgText(125, 84, 'an identity string', 11, 'middle', '0.7'),
      svgEl('line', { x1: '230', y1: '68', x2: '290', y2: '68', stroke: 'currentColor', 'stroke-opacity': '0.6' }),
      svgText(260, 58, 'H1', 11, 'middle', '0.85'),
      svgBox(290, 40, 210, 56),
      svgText(395, 64, 'Q_ID ∈ G1', 15),
      svgText(395, 84, 'a point on the curve', 11, 'middle', '0.7'),
      svgEl('line', { x1: '500', y1: '68', x2: '560', y2: '68', stroke: 'currentColor', 'stroke-opacity': '0.6' }),
      svgText(530, 58, '× s', 11, 'middle', '0.85'),
      svgBox(560, 40, 200, 56),
      svgText(660, 64, 'd_ID = [s]Q_ID', 15),
      svgText(660, 84, 'one multiplication', 11, 'middle', '0.7'),

      svgText(390, 150, 'SM9 (GM/T 0044.2 clause 5.3) — hash to a SCALAR, then INVERT', 13),
      svgBox(20, 166, 210, 56),
      svgText(125, 190, 'ID ‖ hid', 15),
      svgText(125, 210, 'identity plus one byte', 11, 'middle', '0.7'),
      svgEl('line', { x1: '230', y1: '194', x2: '290', y2: '194', stroke: 'currentColor', 'stroke-opacity': '0.6' }),
      svgText(260, 184, 'H1', 11, 'middle', '0.85'),
      svgBox(290, 166, 210, 56),
      svgText(395, 190, 'h1 ∈ F_N', 15),
      svgText(395, 210, 'a scalar, not a point', 11, 'middle', '0.7'),
      svgEl('line', { x1: '500', y1: '194', x2: '560', y2: '194', stroke: 'currentColor', 'stroke-opacity': '0.6' }),
      svgText(530, 184, '+ ks, invert', 11, 'middle', '0.85'),
      svgBox(560, 166, 200, 56),
      svgText(660, 190, 'ds_A = [ks·(h1+ks)⁻¹]P1', 12),
      svgText(660, 210, 'one inversion mod N', 11, 'middle', '0.7'),
    ],
  );
  return el('div', {}, [svg]);
}

function comparisonTable(): HTMLElement {
  return tableEl(
    ['', 'Boneh-Franklin', 'SM9'],
    [
      [
        el('span', { text: 'what H1 produces' }),
        el('span', { text: 'a point of G1 — the identity is mapped ONTO the curve', testid: 'p2-diff-hash-bf' }),
        el('span', { text: 'a scalar in F_N — the curve is never touched by the hash', testid: 'p2-diff-hash-sm9' }),
      ],
      [
        el('span', { text: 'what the master key does to it' }),
        el('span', { text: 'multiplies it: d_ID = [s]Q_ID', testid: 'p2-diff-op-bf' }),
        el('span', { text: 'is added to it and the sum is INVERTED: t2 = ks·(h1+ks)⁻¹', testid: 'p2-diff-op-sm9' }),
      ],
      [
        el('span', { text: 'consequence for this lab' }),
        el('span', { text: 'the identity survives into the key as a point' }),
        el('span', {
          text: 't1·t2 = ks for any h1 at all, so a verifier using the SAME h1 accepts whichever one it is — see panes 3 and 5',
        }),
      ],
    ],
    'p2-bf-comparison',
    'Boneh-Franklin compared with SM9 extraction',
  );
}

export function buildPane2(): HTMLElement {
  const { root, body } = pane(
    'PANE 2',
    'Extraction — the inversion',
    'GM/T 0044.2 clause 5.3 (signature keys) · GM/T 0044.3 clause 5.3 (encryption keys)',
    'p2-pane',
  );

  body.appendChild(
    para(
      'The KGC holds a master private key. To mint a private key for the name you type below it '
        + 'hashes that name to a scalar, adds the master key, and inverts the sum. That inversion is '
        + 'SM9\'s whole trick and it is rendered as a step of its own, because a formula with a '
        + 'superscript minus one in it reads as notation, and a 64-nibble value reads as an operation.',
    ),
  );

  const identityInput = textInput('Alice', 'p2-identity', 18);
  const hidSelect = selectInput(
    [
      { value: String(HID.SIGN), label: '0x01 — signature (Annex A)' },
      { value: String(HID.EXCHANGE_GMSSL), label: '0x02 — key exchange (GmSSL, not in the standard)' },
      { value: String(HID.ENCRYPT), label: '0x03 — encryption (Annexes B, C, D)' },
    ],
    String(HID.SIGN),
    'p2-hid',
  );
  const sideSelect = selectInput(
    [
      { value: 'signature', label: 'signature master key pair (ks, Ppub-s)' },
      { value: 'encryption', label: 'encryption master key pair (ke, Ppub-e)' },
    ],
    'signature',
    'p2-master',
  );
  const extractButton = button('Extract the key', 'p2-extract');
  const rekeyButton = button('Force t1 = 0 for this identity', 'p2-force-t1zero', 'danger');

  const stepsHost = el('div', { testid: 'p2-steps-host' }, [
    statusPill('pending', 'pending — press Extract'),
  ]);
  const verdictHost = verdictSlot('p2-extract-verdict', 'pending — no key has been extracted yet');
  const annexHost = el('div', { testid: 'p2-annex-host' });
  const rekeyHost = el('div', { testid: 'p2-rekey-host' });

  function render(result: Rendered): void {
    const { outcome, master, side } = result;
    const masterName = side === 'signature' ? 'ks' : 'ke';
    const generator = side === 'signature' ? 'P1' : 'P2';
    const keyName = side === 'signature' ? 'ds_A' : 'de_B';

    if (!outcome.ok) {
      replace(stepsHost, [
        stepList([
          { label: 'ID ‖ hid', value: hexBlock(bytesToHex(outcome.idWithHid)), testid: 'p2-step-idhid' },
          { label: 'h1 = H1(ID‖hid, N)', value: hexBlock(toFieldHex(outcome.h1)), testid: 'p2-step-h1' },
          { label: `${masterName} (KGC only)`, value: hexBlock(toFieldHex(master)), testid: 'p2-step-master' },
          { label: `t1 = h1 + ${masterName}`, value: hexBlock(toFieldHex(outcome.t1)), testid: 'p2-step-t1' },
          { label: 't1⁻¹ mod N', value: el('span', { text: 'does not exist — 0 is not invertible' }), testid: 'p2-step-t1inv' },
          { label: `t2 = ${masterName} · t1⁻¹`, value: el('span', { text: 'not computed — there is no t1⁻¹' }), testid: 'p2-step-t2' },
          { label: keyName, value: el('span', { text: 'not issued' }), testid: 'p2-step-key' },
        ]),
      ]);
      setVerdict(
        verdictHost,
        'alarm',
        `${outcome.outcome} — no key can be issued for this identity under this master key`,
        outcome.reason,
      );
      return;
    }

    const t1Inverse = inv(outcome.t1);
    const key = keyHex(outcome);
    // t1 · t2 = master, for ANY h1. This is the identity every other exhibit
    // in the lab rests on, so it is computed here rather than asserted.
    const cancels = mul(outcome.t1, outcome.t2) === master % N;

    replace(stepsHost, [
      stepList([
        { label: 'ID ‖ hid', value: hexBlock(bytesToHex(outcome.idWithHid)), testid: 'p2-step-idhid' },
        { label: 'h1 = H1(ID‖hid, N)', value: hexBlock(toFieldHex(outcome.h1)), testid: 'p2-step-h1' },
        { label: `${masterName} (KGC only)`, value: hexBlock(toFieldHex(master)), testid: 'p2-step-master' },
        { label: `t1 = h1 + ${masterName}`, value: hexBlock(toFieldHex(outcome.t1)), testid: 'p2-step-t1' },
        { label: 't1⁻¹ mod N', value: hexBlock(toFieldHex(t1Inverse)), testid: 'p2-step-t1inv' },
        { label: `t2 = ${masterName} · t1⁻¹`, value: hexBlock(toFieldHex(outcome.t2)), testid: 'p2-step-t2' },
        {
          label: `${keyName} = [t2]${generator}`,
          value: el('div', {}, [
            el('div', {}, [sourceTag(`in ${key.group}`)]),
            hexBlock(`x  ${key.x}`),
            hexBlock(`y  ${key.y}`),
          ]),
          testid: 'p2-step-key',
        },
      ]),
      el('div', {}, [
        statusPill(cancels ? 'info' : 'bad', cancels ? `t1 · t2 = ${masterName} mod N` : 'the cancellation identity FAILED', 'p2-identity-check'),
      ]),
      note(
        [
          el('strong', { text: 'Why that last line matters. ' }),
          `t1 · t2 = ${masterName} holds for ANY value of h1 — the master key is recovered from the product `
            + 'whatever the identity hashed to. Verification only ever sees that product, so it never '
            + 'learns which identity was used, only that extraction and verification used the same one. '
            + 'Pane 3 runs that live with a deliberately wrong H1.',
        ],
        false,
        'p2-cancellation-note',
      ),
    ]);

    setVerdict(
      verdictHost,
      'ok',
      `${keyName} issued in ${key.group} for "${identityInput.value}" at hid ${hidHex(outcome.hid)}`,
      `One modular inversion in F_N, then one scalar multiplication of ${generator}. `
        + 'The identity appears nowhere in the key except through h1, which cancels later.',
    );

    const expectation = annexExpectation(side, identityInput.value, outcome.hid);
    if (expectation === undefined) {
      replace(annexHost, [
        note(
          [
            el('strong', { text: 'Nothing pinned to compare against. ' }),
            'This identity, hid and master key pair are not a combination any annex of GM/T 0044.5 '
              + 'prints, so there is no published intermediate to check this run against. The default '
              + 'settings (Alice, 0x01, signature) reproduce Annex A; Bob at 0x03 on the encryption '
              + 'side reproduces Annex C.',
          ],
          false,
          'p2-annex-none',
        ),
      ]);
      return;
    }

    const rows: [string, string, string][] = [
      ['h1 = H1(ID‖hid, N)', toFieldHex(outcome.h1), expectation.h1],
      ['t1', toFieldHex(outcome.t1), expectation.t1],
      ['t2', toFieldHex(outcome.t2), expectation.t2],
      [`${keyName} x`, key.x, expectation.x],
      [`${keyName} y`, key.y, expectation.y],
    ];
    const allMatch = rows.every(([, actual, want]) => actual === want.toLowerCase());
    replace(annexHost, [
      heading('Against the annex\'s own pinned intermediates'),
      el('div', {}, [
        sourceTag(expectation.label, 'p2-annex-source'),
        ' ',
        equality(allMatch, 'every intermediate reproduced', 'an intermediate differs', 'p2-annex-badge'),
      ]),
      tableEl(
        ['Value', 'Computed here', 'Printed in the annex', ''],
        rows.map(([label, actual, want]) => [
          el('span', { text: label }),
          hexBlock(actual),
          hexBlock(want.toLowerCase()),
          equality(actual === want.toLowerCase(), 'match', 'differs'),
        ]),
        'p2-annex-table',
        'Extraction intermediates against the annex',
      ),
      note(
        [
          el('strong', { text: 'These pinned values are the only check that catches a wrong H1. ' }),
          'A sign-then-verify round trip cannot tell you WHICH identity-to-scalar map was used, only that both sides used the same one; see panes 3 and 5. An '
            + 'implementation that hashed identities wrongly but consistently would pass every round '
            + 'trip it ran against itself and fail exactly this table.',
        ],
        false,
        'p2-annex-why',
      ),
    ]);
  }

  function run(): void {
    replace(stepsHost, [statusPill('info', 'computing')]);
    clear(rekeyHost);
    defer(() => {
      const side = sideSelect.value as Side;
      const hid = Number(hidSelect.value);
      const master = masterScalar(side);
      render({ outcome: extract(side, identityInput.value, hid, master), master, side });
    });
  }

  function forceRekey(): void {
    replace(rekeyHost, [statusPill('info', 'computing')]);
    defer(() => {
      const side = sideSelect.value as Side;
      const hid = Number(hidSelect.value);
      const identity = identityInput.value;
      // ks = -H1(ID‖hid) is the one master key for which t1 = 0 at this identity.
      // It is a perfectly valid scalar in [1, N-1], so nothing about the call below
      // is special-cased — the branch is reached the way the standard describes it.
      const forced = masterKeyForcingT1Zero(identity, hid);
      const outcome = extract(side, identity, hid, forced);
      const masterName = side === 'signature' ? 'ks' : 'ke';

      if (outcome.ok) {
        // Unreachable: masterKeyForcingT1Zero solves t1 = 0 for exactly this
        // identity and hid. Reported rather than thrown, because a page that
        // cannot reach the branch it claims to reach must say so.
        const host = el('div', {});
        setVerdict(
          host,
          'bad',
          'the forced master key did not produce t1 = 0',
          'The identity or hid changed between solving for the master key and extracting with it. '
            + 'Press the button again.',
        );
        replace(rekeyHost, [host]);
        return;
      }

      replace(rekeyHost, [
        el('div', {}, [
          verdictEl(
            outcome.outcome,
            `GM/T 0044.2 clause 5.3 step A3. t1 = h1 + ${masterName} came out zero, so t1⁻¹ does not exist `
              + 'and this identity cannot be issued a key under this master key.',
          ),
        ]),
        kv(
          [
            [`forced ${masterName} = -h1 mod N`, hexBlock(toFieldHex(forced), 'p2-rekey-master')],
            ['h1 = H1(ID‖hid, N)', hexBlock(toFieldHex(outcome.h1), 'p2-rekey-h1')],
            [`t1 = h1 + ${masterName}`, hexBlock(toFieldHex(outcome.t1), 'p2-rekey-t1')],
            ['t2', el('span', { text: 'null — there is no inverse to multiply by', testid: 'p2-rekey-t2' })],
            ['outcome', el('span', { text: outcome.outcome, testid: 'p2-rekey-outcome' })],
          ],
          'p2-rekey-values',
        ),
        note(
          [
            el('strong', { text: 'What this costs. ' }),
            'The remedy the clause names is not a retry. t1 is a deterministic function of the identity '
              + 'and the master key, so drawing again changes nothing: the KGC must REGENERATE the master '
              + 'key pair, republish the master public key, and RE-ISSUE every user key it has already '
              + 'handed out. One unlucky identity re-keys the entire deployment.',
          ],
          true,
          'p2-rekey-cost',
        ),
        note(
          [
            'A real KGC draws its master key at random, so the odds of landing on this value are about '
              + '2⁻²⁵⁶ and the branch would otherwise be code nobody has ever executed. Solving for the '
              + 'master key that triggers it costs one hash and one negation, which is why it is reachable '
              + 'from this button rather than described in a comment.',
          ],
          false,
          'p2-rekey-reachability',
        ),
      ]);
    });
  }

  /** A local verdict builder, so the re-key block can name the outcome as its own text. */
  function verdictEl(text: string, why: string): HTMLElement {
    const host = el('div', { testid: 'p2-rekey-verdict' });
    setVerdict(host, 'alarm', text, why);
    return host;
  }

  extractButton.addEventListener('click', run);
  identityInput.addEventListener('change', run);
  hidSelect.addEventListener('change', run);
  sideSelect.addEventListener('change', run);
  rekeyButton.addEventListener('click', forceRekey);

  body.appendChild(
    controls([
      labelled('Identity', identityInput),
      labelled('hid byte', hidSelect),
      labelled('Master key pair', sideSelect),
      extractButton,
    ]),
  );
  body.appendChild(
    note(
      [
        el('strong', { text: 'The master keys here are the annexes\' own. ' }),
        'ks is GM/T 0044.5 Annex A\'s signature master private key and ke is Annexes C and D\'s '
          + 'encryption master private key, both read from the standard rather than generated, so the '
          + 'default settings reproduce a published worked example exactly.',
      ],
      false,
      'p2-master-provenance',
    ),
  );
  body.appendChild(verdictHost);
  body.appendChild(stepsHost);
  body.appendChild(annexHost);

  body.appendChild(heading('The t1 = 0 branch, reachable on this page'));
  body.appendChild(
    para(
      'GM/T 0044.2 clause 5.3 step A3 has a branch nobody ever reaches by accident: if t1 comes out '
        + 'zero the key cannot be issued. The button below solves for the master key that makes it '
        + 'happen for whatever identity and hid are selected above, and runs the same extraction code '
        + 'path with it.',
    ),
  );
  body.appendChild(controls([rekeyButton]));
  body.appendChild(rekeyHost);

  body.appendChild(heading('Two master key pairs, mirrored across the two groups'));
  body.appendChild(
    para(
      'The scalar arithmetic above is identical on both sides — the same h1, the same sum, the same '
        + 'inversion. What differs is which group each key lands in, and the two sides are exact '
        + 'mirrors of each other. Getting them the wrong way round produces a key that is a perfectly '
        + 'good curve point and is useless, with nothing thrown.',
    ),
  );
  body.appendChild(mirrorDiagram());
  body.appendChild(
    sideBySide([
      box(
        'Signature — GM/T 0044.2 clause 5.3',
        [
          kv([
            ['master private', el('span', { text: 'ks, held only by the KGC' })],
            ['master public', el('span', { text: 'Ppub-s = [ks]P2 — in G2, the LARGE group' })],
            ['user key', el('span', { text: 'ds_A = [t2]P1 — in G1, the small group' })],
            ['consequence', el('span', { text: 'an SM9 signature is 32 + 64 bytes, because S lives in G1' })],
          ]),
        ],
        'p2-mirror-sign',
      ),
      box(
        'Encryption — GM/T 0044.3 clause 5.3',
        [
          kv([
            ['master private', el('span', { text: 'ke, held only by the KGC' })],
            ['master public', el('span', { text: 'Ppub-e = [ke]P1 — in G1, the small group' })],
            ['user key', el('span', { text: 'de_B = [t2]P2 — in G2, the large group' })],
            ['consequence', el('span', { text: 'a ciphertext carries C1 in G1 and the private key does the G2 work' })],
          ]),
        ],
        'p2-mirror-encrypt',
      ),
    ]),
  );

  body.appendChild(heading('What SM9 is not: Boneh-Franklin'));
  body.appendChild(
    para(
      'The scheme most readers meet first is Boneh-Franklin, and it does the obvious thing: hash the '
        + 'identity onto the curve, then multiply that point by the master scalar. SM9 does neither '
        + 'half of that. The diagram below is static — nothing on this page runs Boneh-Franklin, and '
        + 'nothing here should be read as an implementation of it.',
    ),
  );
  body.appendChild(bonehFranklinDiagram());
  body.appendChild(comparisonTable());
  body.appendChild(
    note(
      [
        'A running Boneh-Franklin scheme, with its own hash-to-curve and its own master key, is a '
          + 'different exhibit in this fleet: ',
        el('a', { text: 'crypto-lab-ibe-gate', attrs: { href: IBE_GATE, target: '_blank', rel: 'noopener' }, testid: 'p2-bf-link' }),
        '.',
      ],
      false,
      'p2-bf-note',
    ),
  );
  body.appendChild(
    detailsEl(
      'Why the inversion, rather than the multiplication?',
      [
        para(
          'Hashing onto a curve is awkward to do in constant time and awkward to standardise — the map '
            + 'has to be indifferentiable from a random oracle and cheap, and the literature took years '
            + 'to settle it. Hashing to a scalar is just a hash with a reduction, which is why SM9\'s H1 '
            + 'is SM3 and nothing more. The cost is paid elsewhere: the exponent inversion means the '
            + 'identity is bound into the key by a relation, t1·t2 = ks, rather than carried in it as a '
            + 'point, and that relation is symmetric enough to cancel. The rest of this lab is that '
            + 'trade-off being paid.',
        ),
      ],
      'p2-why-inversion',
    ),
  );

  // First render, so the pane is never empty of the act it is about.
  run();

  return root;
}
