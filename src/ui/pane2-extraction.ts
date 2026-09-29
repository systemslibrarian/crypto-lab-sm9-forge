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
 * THE SYMBOLIC PATH IS PAINTED BEFORE ANY HEX EXISTS, AND THAT IS THE POINT.
 * The five lines of the relation are on screen from the first paint with empty
 * value slots. Pressing Extract fills them one at a time, in the order the
 * standard performs them, so the reader watches the inversion happen rather than
 * arriving at a finished table of 64-nibble strings. Nothing on this pane
 * computes until the reader causes it: the pane used to run an extraction on
 * load, which meant the headline act had already happened, unattributed, above a
 * pane 1 that still said "not yet run".
 *
 * THE DECISIVE EXPERIMENT LIVES HERE, NOT THREE THOUSAND PIXELS DOWN. t1 · t2 =
 * master for ANY h1 whatsoever, so an implementation that hashed identities
 * wrongly but CONSISTENTLY passes every round trip it runs against itself. That
 * used to be demonstrated in a nested act inside pane 3, separated from the
 * relation it is about. It is now a two-state control on this pane: the same five
 * questions are asked under SM9's real H1 and under an altered map, and the two
 * that still say yes are exactly the two a round trip can ask about itself. That is the lab's actual thesis — a green round trip
 * is weaker evidence than one pinned external value — and it fits in one screen.
 *
 * THE MASTER KEYS ARE THE ANNEXES' OWN. Both are read from the fixtures rather
 * than drawn at random, so that a visitor running the default settings is
 * reproducing GM/T 0044.5 Annex A byte for byte and can see the annex's pinned
 * intermediates agree — which is the ONLY check that catches a wrong H1, since
 * the round trip cannot.
 */
import { HID, N } from '../sm9/params';
import { inv, mul } from '../sm9/fn';
import { H1, bytesToHex, concatBytes, hexToBytes } from '../sm9/hash';
import {
  encryptMasterKeyPair,
  extractEncryptKey,
  extractSignKey,
  fp2Components,
  masterKeyForcingT1Zero,
  signMasterKeyPair,
  toFieldHex,
} from '../sm9/extract';
import type { EncryptKeyOutcome, IdentityHash, SignKeyOutcome } from '../sm9/extract';
import { sign, verify } from '../sm9/sign';
import annexA from '../sm9/fixtures/annexA-fixture.json';
import annexCD from '../sm9/fixtures/sm9-annex-cd-fixtures.json';
import type { Exhibit, ExhibitHost } from './exhibit';
import {
  box,
  button,
  clear,
  controls,
  defer,
  detailsEl,
  el,
  equality,
  figureEl,
  flow,
  heading,
  hexBlock,
  hidHex,
  kv,
  labelled,
  note,
  pane,
  para,
  replace,
  segmented,
  selectInput,
  setVerdict,
  sideBySide,
  sourceTag,
  statusPill,
  tableEl,
  textInput,
  verdictSlot,
} from './dom';

/** GM/T 0044.5 Annex A's signature master private key. */
const ANNEX_KS = BigInt(`0x${annexA.signature.ks}`);
/** GM/T 0044.5 Annexes C and D's encryption master private key. */
const ANNEX_KE = BigInt(`0x${annexCD.annex_C_kem.master_encryption_private_key_ke}`);
/** Annex A's message and nonce, so the round-trip rows below reproduce it exactly. */
const ANNEX_MESSAGE = hexToBytes(annexA.signature.message.hex);
const ANNEX_R = BigInt(`0x${annexA.signature.r}`);

type Side = 'signature' | 'encryption';
type Map1 = 'standard' | 'altered';

const IBE_GATE = 'https://systemslibrarian.github.io/crypto-lab-ibe-gate/';

/**
 * The altered identity-to-scalar map: SM9's own H1 over the same bytes with one
 * extra domain byte in front.
 *
 * It is a perfectly good hash. It is not SM9's, it produces a different scalar
 * for every identity, and that is the entire content of the experiment — the
 * arithmetic downstream neither knows nor cares which map produced h1.
 */
const ALTERED_H1: IdentityHash = (idWithHid) => H1(concatBytes(Uint8Array.of(0xff), idWithHid), N).h;

function mapOf(which: Map1): IdentityHash | undefined {
  return which === 'standard' ? undefined : ALTERED_H1;
}

interface Rendered {
  outcome: SignKeyOutcome | EncryptKeyOutcome;
  master: bigint;
  side: Side;
  map: Map1;
}

function masterScalar(side: Side): bigint {
  return side === 'signature' ? ANNEX_KS : ANNEX_KE;
}

function extract(
  side: Side,
  identity: string,
  hid: number,
  master: bigint,
  map: Map1,
): SignKeyOutcome | EncryptKeyOutcome {
  const options = { hid, identityHash: mapOf(map) };
  return side === 'signature'
    ? extractSignKey(signMasterKeyPair(master), identity, options)
    : extractEncryptKey(encryptMasterKeyPair(master), identity, options);
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
 * says so rather than comparing against the nearest thing. An ALTERED map has no
 * pinned row either, by construction — that is the finding, not an omission.
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

/**
 * The mirror, as a two-by-two rather than a picture.
 *
 * This was an inline SVG. The thing it was carrying is a table — two key types
 * against two roles, and the finding is that the same group name appears on
 * opposite rows — and a table reflows onto a phone, keeps its text at the
 * reader's own size, and needs no scale arithmetic to stay legible. See the note
 * at the top of src/ui/dom.ts.
 */
function mirrorTable(): HTMLElement {
  return figureEl(
    'The same group name appears on opposite rows: that crossing is the mirror. The scalar '
      + 'arithmetic is identical on both sides — only the groups swap.',
    [
      tableEl(
        ['', 'Signature — GM/T 0044.2 clause 5.3', 'Encryption — GM/T 0044.3 clause 5.3'],
        [
          [
            el('span', { text: 'master public key' }),
            el('span', { text: 'Ppub-s = [ks]P2 — in G2', testid: 'p2-mirror-master-sign' }),
            el('span', { text: 'Ppub-e = [ke]P1 — in G1', testid: 'p2-mirror-master-encrypt' }),
          ],
          [
            el('span', { text: 'user key' }),
            el('span', { text: 'ds_A = [t2]P1 — in G1', testid: 'p2-mirror-user-sign' }),
            el('span', { text: 'de_B = [t2]P2 — in G2', testid: 'p2-mirror-user-encrypt' }),
          ],
        ],
        'p2-mirror-table',
        'The two master key pairs and the groups their keys land in',
      ),
    ],
    'p2-mirror-figure',
  );
}

/** Boneh–Franklin beside SM9, as two flows. Static: nothing here runs either scheme. */
function bonehFranklinFlows(): HTMLElement {
  return figureEl(
    'Boneh-Franklin maps an identity ONTO the curve and multiplies the point by the master '
      + 'scalar. SM9 maps it to a scalar, adds the master scalar, and inverts the sum. Both flows '
      + 'are static text: nothing on this page runs Boneh-Franklin.',
    [
      sideBySide([
        box('Boneh-Franklin (2001) — hash to a CURVE POINT, then multiply', [
          flow(
            [
              { term: 'ID', hint: 'an identity string' },
              { op: 'H1, a hash ONTO the curve', term: 'Q_ID ∈ G1', hint: 'a point on the curve' },
              { op: '× s', term: 'd_ID = [s]Q_ID', hint: 'one scalar multiplication' },
            ],
            'p2-bf-flow',
          ),
        ], 'p2-bf-box'),
        box('SM9 (GM/T 0044.2 clause 5.3) — hash to a SCALAR, then INVERT', [
          flow(
            [
              { term: 'ID ‖ hid', hint: 'an identity plus one byte' },
              { op: 'H1, a hash into F_N', term: 'h1 ∈ F_N', hint: 'a scalar, not a point' },
              { op: '+ ks, then invert', term: 'ds_A = [ks·(h1+ks)⁻¹]P1', hint: 'one inversion mod N' },
            ],
            'p2-sm9-flow',
          ),
        ], 'p2-sm9-box'),
      ]),
    ],
    'p2-bf-figure',
  );
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
          text: 't1·t2 = ks for any h1 at all, so a verifier using the SAME h1 accepts whichever one it is — see the experiment above',
        }),
      ],
    ],
    'p2-bf-comparison',
    'Boneh-Franklin compared with SM9 extraction',
  );
}

/** The five lines of the relation, plus the bytes they start from. */
interface RelationLine {
  key: string;
  op?: string;
  term: string;
  hint: string;
}

function relationLines(masterName: string, generator: string, keyName: string): RelationLine[] {
  return [
    { key: 'idhid', term: 'ID ‖ hid', hint: 'the identity, and the one byte naming which function issued the key' },
    { key: 'h1', op: 'H1', term: 'h1 = H1(ID‖hid, N)', hint: 'a scalar in F_N — the curve has not been touched yet' },
    { key: 't1', op: `+ ${masterName}`, term: `t1 = h1 + ${masterName}`, hint: 'the identity and the master secret, added' },
    { key: 't1inv', op: 'invert mod N', term: 't1⁻¹', hint: 'the whole mechanism, as a value rather than a superscript' },
    { key: 't2', op: `× ${masterName}`, term: `t2 = ${masterName} · t1⁻¹`, hint: 'the scalar the key is actually made of' },
    { key: 'key', op: `[t2]${generator}`, term: `${keyName} = [t2]${generator}`, hint: 'one scalar multiplication, and the key exists' },
  ];
}

const PENDING_SLOT = '—';

/** How long the staged reveal takes per line, unless the reader asked for less motion. */
const REVEAL_MS = 110;

export function buildPane2(host: ExhibitHost): Exhibit {
  const { root, body } = pane(
    'PANE 2',
    'Extraction — the inversion',
    'GM/T 0044.2 clause 5.3 (signature keys) · GM/T 0044.3 clause 5.3 (encryption keys)',
    'p2-pane',
  );

  body.appendChild(
    para(
      'The KGC holds a master private key. To mint a private key for the name you type below it '
        + 'hashes that name to a scalar, adds the master key, and inverts the sum. The five lines of '
        + 'that relation are already on screen; press Extract and they fill in, one operation at a '
        + 'time, in the order the standard performs them.',
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

  const mapControl = segmented(
    'Identity-to-scalar map',
    [
      { value: 'standard', label: 'SM9\'s H1', hint: 'the standard\'s own map' },
      { value: 'altered', label: 'An altered H1', hint: 'a good hash that is not SM9\'s' },
    ],
    'standard',
    () => {
      // Changing the map changes every value below it, so the old ones go.
      retire();
      run();
    },
    'p2-map',
  );

  const relationHost = el('div', { testid: 'p2-relation' });
  const verdictHost = verdictSlot('p2-extract-verdict', 'pending — no key has been extracted yet');
  const questionsHost = el('div', { testid: 'p2-questions-host' });
  const annexHost = el('div', { testid: 'p2-annex-host' });
  const rekeyHost = el('div', { testid: 'p2-rekey-host' });

  /** Handles of the value slots, so a reveal writes into the line already painted. */
  let slots: Map<string, HTMLElement> = new Map();
  let revealTimers: number[] = [];

  function cancelReveal(): void {
    for (const timer of revealTimers) window.clearTimeout(timer);
    revealTimers = [];
  }

  /**
   * Paint the relation's lines with empty slots.
   *
   * Called on first mount and on every retire, so the symbolic path is the one
   * thing on this pane that is never absent: a reader who has computed nothing
   * still sees what pressing the button is going to do.
   */
  function paintRelation(side: Side): void {
    const masterName = side === 'signature' ? 'ks' : 'ke';
    const generator = side === 'signature' ? 'P1' : 'P2';
    const keyName = side === 'signature' ? 'ds_A' : 'de_B';
    const lines = relationLines(masterName, generator, keyName);

    const list = el('ol', { class: 'relation', testid: 'p2-relation-list' });
    slots = new Map();
    for (const line of lines) {
      const slot = el('div', { class: 'relation-slot', testid: `p2-step-${line.key}` }, [
        el('span', { class: 'relation-pending', text: PENDING_SLOT }),
      ]);
      slots.set(line.key, slot);
      list.appendChild(
        el('li', { class: 'relation-line', testid: `p2-line-${line.key}` }, [
          // Description and value are two grid columns above 62rem and one below
          // it. Stacked at every width, the six lines ran to seven hundred pixels
          // and pushed the experiment they exist to set up off the screen.
          el('div', { class: 'relation-desc' }, [
            el('div', { class: 'relation-head' }, [
              line.op === undefined
                ? el('span', { class: 'relation-op relation-op-first', text: 'start' })
                : el('span', { class: 'relation-op', text: line.op }),
              el('span', { class: 'relation-term', text: line.term }),
            ]),
            el('span', { class: 'relation-hint', text: line.hint }),
          ]),
          slot,
        ]),
      );
    }
    replace(relationHost, [
      list,
      el('div', { class: 'relation-master' }, [
        kv(
          [[
            `${masterName} — the master private key, held only by the KGC`,
            el('div', { testid: 'p2-step-master' }, [el('span', { class: 'relation-pending', text: PENDING_SLOT })]),
          ]],
          'p2-master-value',
        ),
      ]),
    ]);
    slots.set('master', relationHost.querySelector('[data-testid="p2-step-master"]') as HTMLElement);
  }

  function fill(key: string, contents: HTMLElement[]): void {
    const slot = slots.get(key);
    if (slot === undefined) return;
    replace(slot, contents);
    const line = slot.closest('.relation-line');
    if (line !== null) line.classList.add('is-filled');
  }

  /**
   * Fill the slots one at a time, marking the line being performed.
   *
   * The values are computed BEFORE any of this runs — the stagger is a rendering
   * of work already finished, never a simulation of work in progress, because a
   * page that pretended to compute slowly would be lying about a measurement.
   * Under `prefers-reduced-motion: reduce` every line lands at once.
   */
  function reveal(order: { key: string; contents: HTMLElement[] }[]): void {
    cancelReveal();
    const instant = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    if (instant) {
      for (const entry of order) fill(entry.key, entry.contents);
      return;
    }
    order.forEach((entry, index) => {
      revealTimers.push(
        window.setTimeout(() => {
          const line = slots.get(entry.key)?.closest('.relation-line');
          if (line !== null && line !== undefined) {
            line.classList.add('is-active');
            window.setTimeout(() => line.classList.remove('is-active'), REVEAL_MS * 2);
          }
          fill(entry.key, entry.contents);
        }, index * REVEAL_MS),
      );
    });
  }

  /**
   * The five questions, asked identically under both maps.
   *
   * WHY THIS IS A TABLE AND NOT PROSE. The finding is a DIFFERENCE, and a
   * difference is only visible when the questions are held still. Under SM9's own
   * H1 every row agrees. Under the altered map exactly two rows change — the key
   * is a different key, and the annex's pinned value no longer matches — while
   * the cancellation identity and the agreeing verifier stay exactly as green as
   * they were. That is the whole thesis of the lab on one screen.
   */
  function renderQuestions(result: Rendered): void {
    const { outcome, master, side, map } = result;
    if (!outcome.ok) {
      replace(questionsHost, []);
      return;
    }
    const identity = identityInput.value;
    const hid = outcome.hid;
    const key = keyHex(outcome);

    // Q1 — the same key SM9's own H1 would have issued?
    const standardOutcome = extract(side, identity, hid, master, 'standard');
    const standardKey = standardOutcome.ok ? keyHex(standardOutcome) : undefined;
    const sameKey = standardKey !== undefined && standardKey.x === key.x && standardKey.y === key.y;

    // Q2 — the cancellation identity.
    const cancels = mul(outcome.t1, outcome.t2) === master % N;

    // Q3 and Q5 — the round trip, which only exists on the signature side.
    const roundTrip = (():
      | { kind: 'ran'; agreeing: boolean; agreeingFailure: string | null; real: boolean; realFailure: string | null }
      | { kind: 'not-applicable' } => {
      if (side !== 'signature' || !('dsA' in outcome)) return { kind: 'not-applicable' };
      const Ppubs = signMasterKeyPair(master).Ppubs;
      const signature = sign(ANNEX_MESSAGE, outcome.dsA, Ppubs, { nonce: () => ANNEX_R }).signature;
      const agreeing = verify(ANNEX_MESSAGE, identity, signature, Ppubs, { hid, identityHash: mapOf(map) });
      const real = verify(ANNEX_MESSAGE, identity, signature, Ppubs, { hid });
      return {
        kind: 'ran',
        agreeing: agreeing.accepted,
        agreeingFailure: agreeing.failure,
        real: real.accepted,
        realFailure: real.failure,
      };
    })();

    // Q4 — the pinned value, which exists only for the exact annex parameter set.
    const expectation = annexExpectation(side, identity, hid);
    const pinnedRows = expectation === undefined
      ? undefined
      : [
          [toFieldHex(outcome.h1), expectation.h1],
          [toFieldHex(outcome.t1), expectation.t1],
          [toFieldHex(outcome.t2), expectation.t2],
          [key.x, expectation.x],
          [key.y, expectation.y],
        ] as [string, string][];
    const pinnedAgrees = pinnedRows?.every(([actual, want]) => actual === want.toLowerCase());

    const naPill = (why: string, testid: string): HTMLElement => statusPill('info', why, testid);

    replace(questionsHost, [
      heading('The decisive experiment — the same five questions under either map'),
      el('div', { class: 'questions' }, [
        tableEl(
          ['What is being asked', 'The answer in the state on screen'],
          [
            [
              el('span', { text: 'Is this the key SM9\'s own H1 would have issued for this name?' }),
              statusPill(
                sameKey ? 'ok' : 'bad',
                sameKey ? 'the same key, byte for byte' : 'a DIFFERENT key',
                'p2-q-samekey',
              ),
            ],
            [
              el('span', { text: 'Does the cancellation identity t1 · t2 = master still hold?' }),
              statusPill(
                cancels ? 'info' : 'bad',
                cancels ? 'it holds — and it holds for ANY h1' : 'the cancellation identity FAILED',
                'p2-q-cancels',
              ),
            ],
            [
              el('span', { text: 'Does a verifier using THIS SAME map accept a signature under this key?' }),
              roundTrip.kind === 'not-applicable'
                ? naPill('not asked — a signature round trip needs the signature master key', 'p2-q-agreeing')
                : statusPill(
                    roundTrip.agreeing ? (map === 'altered' ? 'alarm' : 'ok') : 'bad',
                    roundTrip.agreeing
                      ? map === 'altered' ? 'ACCEPTED — and that is the finding' : 'ACCEPTED'
                      : `refused at ${roundTrip.agreeingFailure}`,
                    'p2-q-agreeing',
                  ),
            ],
            [
              el('span', { text: 'Does SM9\'s REAL verifier accept that same signature?' }),
              roundTrip.kind === 'not-applicable'
                ? naPill('not asked — a signature round trip needs the signature master key', 'p2-q-realverifier')
                : statusPill(
                    roundTrip.real ? 'ok' : 'bad',
                    roundTrip.real ? 'ACCEPTED' : `refused at ${roundTrip.realFailure}`,
                    'p2-q-realverifier',
                  ),
            ],
            [
              el('span', { text: 'Do the intermediates GM/T 0044.5 pins for this identity agree?' }),
              pinnedAgrees === undefined
                ? naPill('nothing pinned for this identity, hid and master key pair', 'p2-q-pinned')
                : statusPill(
                    pinnedAgrees ? 'ok' : 'bad',
                    pinnedAgrees
                      ? `every intermediate matches ${expectation?.label}`
                      : `an intermediate DIFFERS from ${expectation?.label}`,
                    'p2-q-pinned',
                  ),
            ],
          ],
          'p2-questions-table',
          'The same five questions, answered in the state currently on screen',
        ),
      ]),
      note(
        map === 'altered'
          ? [
              el('strong', { text: 'Three rows now say no. Two still say yes. ' }),
              'The two that held — the cancellation identity, and a verifier using this same altered '
                + 'map — are the only checks a round trip can make about itself, and neither of them '
                + 'can see WHICH identity map produced the key. Extraction sets t1 = h1 + master and '
                + 't2 = master · t1⁻¹, so t1 · t2 = master whatever h1 was, and the equation '
                + 'verification checks does not contain H1 at all. The three that went red each needed '
                + 'something this run does not contain: SM9\'s own H1, or the intermediates GM/T '
                + '0044.5 prints. An implementation that hashed identities wrongly but CONSISTENTLY '
                + 'would pass every round trip it ever ran against itself and fail exactly those three. '
                + 'That is why a green round trip is weaker evidence than one pinned external value.',
            ]
          : [
              el('strong', { text: 'Now switch the map above to "An altered H1". ' }),
              'Every row agrees, which is the state most implementations ship in. Two of these five '
                + 'rows will still say yes under a map that is not SM9\'s — and those two are exactly '
                + 'the checks a round trip performs on itself.',
            ],
        map === 'altered',
        'p2-questions-note',
      ),
      roundTrip.kind === 'not-applicable'
        ? note(
            [
              'The round-trip rows need a signature key. Switch the master key pair above back to the '
                + 'signature pair to ask them.',
            ],
            false,
            'p2-questions-na',
          )
        : note(
            [
              `The round trip signs GM/T 0044.5 Annex A's own message, "${annexA.signature.message.ascii}", `
                + 'on the annex\'s own nonce r, under whichever key was just extracted. Only the key and '
                + 'the map change between the two states.',
            ],
            false,
            'p2-questions-inputs',
          ),
    ]);
  }

  function render(result: Rendered): void {
    const { outcome, master, side, map } = result;
    const generator = side === 'signature' ? 'P1' : 'P2';
    const keyName = side === 'signature' ? 'ds_A' : 'de_B';

    if (!outcome.ok) {
      reveal([
        { key: 'master', contents: [hexBlock(toFieldHex(master))] },
        { key: 'idhid', contents: [hexBlock(bytesToHex(outcome.idWithHid))] },
        { key: 'h1', contents: [hexBlock(toFieldHex(outcome.h1))] },
        { key: 't1', contents: [hexBlock(toFieldHex(outcome.t1))] },
        { key: 't1inv', contents: [el('span', { text: 'does not exist — 0 is not invertible' })] },
        { key: 't2', contents: [el('span', { text: 'not computed — there is no t1⁻¹' })] },
        { key: 'key', contents: [el('span', { text: 'not issued' })] },
      ]);
      setVerdict(
        verdictHost,
        'alarm',
        `${outcome.outcome} — no key can be issued for this identity under this master key`,
        outcome.reason,
      );
      replace(questionsHost, []);
      replace(annexHost, []);
      return;
    }

    const t1Inverse = inv(outcome.t1);
    const key = keyHex(outcome);

    reveal([
      { key: 'master', contents: [hexBlock(toFieldHex(master))] },
      { key: 'idhid', contents: [hexBlock(bytesToHex(outcome.idWithHid))] },
      { key: 'h1', contents: [hexBlock(toFieldHex(outcome.h1))] },
      { key: 't1', contents: [hexBlock(toFieldHex(outcome.t1))] },
      { key: 't1inv', contents: [hexBlock(toFieldHex(t1Inverse))] },
      { key: 't2', contents: [hexBlock(toFieldHex(outcome.t2))] },
      {
        key: 'key',
        contents: [
          el('div', {}, [
            el('div', {}, [sourceTag(`in ${key.group}`)]),
            hexBlock(`x  ${key.x}`),
            hexBlock(`y  ${key.y}`),
          ]),
        ],
      },
    ]);

    setVerdict(
      verdictHost,
      map === 'altered' ? 'alarm' : 'ok',
      `${keyName} issued in ${key.group} for "${identityInput.value}" at hid ${hidHex(outcome.hid)}`
        + (map === 'altered' ? ' — under an altered H1' : ''),
      `One modular inversion in F_N, then one scalar multiplication of ${generator}. `
        + (map === 'altered'
          ? 'The map that produced h1 is not SM9\'s, and nothing downstream of the inversion can tell.'
          : 'The identity appears nowhere in the key except through h1, which cancels later.'),
    );

    renderQuestions(result);
    renderAnnex(result, key, keyName);
  }

  function renderAnnex(
    result: Rendered,
    key: { x: string; y: string; group: string },
    keyName: string,
  ): void {
    const { outcome, map } = result;
    if (!outcome.ok) return;
    const expectation = annexExpectation(result.side, identityInput.value, outcome.hid);
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
      heading('Every intermediate, against the annex\'s own pinned values'),
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
          'A sign-then-verify round trip cannot tell you WHICH identity-to-scalar map was used, only '
            + 'that both sides used the same one — the experiment above runs exactly that. An '
            + `implementation that hashed identities wrongly but consistently would pass every round `
            + 'trip it ran against itself and fail exactly this table.',
          map === 'altered'
            ? ' The map above is currently the altered one, which is why this table disagrees.'
            : '',
        ],
        false,
        'p2-annex-why',
      ),
    ]);
  }

  function run(): void {
    cancelReveal();
    const side = sideSelect.value as Side;
    paintRelation(side);
    clear(rekeyHost);
    defer(() => {
      const hid = Number(hidSelect.value);
      const master = masterScalar(side);
      const map = mapControl.get() as Map1;
      const outcome = extract(side, identityInput.value, hid, master, map);
      render({ outcome, master, side, map });
      if (outcome.ok) {
        const keyName = side === 'signature' ? 'ds_A' : 'de_B';
        host.onComplete(
          `${keyName} issued for "${identityInput.value}" at hid ${hidHex(hid)}`
            + (map === 'altered' ? ', under an ALTERED H1' : ', reproducing the annex')
            + ' — one inversion mod N, one scalar multiplication',
        );
      } else {
        // The refusal is a real result and the reader caused it, but it issued no
        // key, so the step it unlocks has nothing to work with.
        host.onStale();
      }
    });
  }

  /** Drop every verdict about the previous input, and say nothing in its place. */
  function retire(): void {
    cancelReveal();
    paintRelation(sideSelect.value as Side);
    setVerdict(verdictHost, 'pending', 'pending — no key has been extracted yet');
    replace(questionsHost, []);
    replace(annexHost, []);
    clear(rekeyHost);
    host.onStale();
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
      const outcome = extract(side, identity, hid, forced, 'standard');
      const masterName = side === 'signature' ? 'ks' : 'ke';

      if (outcome.ok) {
        // Unreachable: masterKeyForcingT1Zero solves t1 = 0 for exactly this
        // identity and hid. Reported rather than thrown, because a page that
        // cannot reach the branch it claims to reach must say so.
        const errorHost = el('div', {});
        setVerdict(
          errorHost,
          'bad',
          'the forced master key did not produce t1 = 0',
          'The identity or hid changed between solving for the master key and extracting with it. '
            + 'Press the button again.',
        );
        replace(rekeyHost, [errorHost]);
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
    const verdictRoot = el('div', { testid: 'p2-rekey-verdict' });
    setVerdict(verdictRoot, 'alarm', text, why);
    return verdictRoot;
  }

  extractButton.addEventListener('click', run);
  identityInput.addEventListener('change', () => {
    retire();
    run();
  });
  hidSelect.addEventListener('change', () => {
    retire();
    run();
  });
  sideSelect.addEventListener('change', () => {
    retire();
    run();
  });
  rekeyButton.addEventListener('click', forceRekey);

  body.appendChild(
    controls([
      labelled('Identity', identityInput),
      labelled('hid byte', hidSelect),
      labelled('Master key pair', sideSelect),
      mapControl.root,
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
  // RESULT, THEN THE FINDING, THEN THE DERIVATION. The five questions sit
  // directly under the verdict so the thing worth carrying away is in the same
  // screen as the control that produced it; the six lines of the relation are the
  // derivation underneath. Before anything is run `questionsHost` is empty, so the
  // symbolic path with its empty slots is still the first thing under the verdict.
  body.appendChild(verdictHost);
  body.appendChild(questionsHost);
  body.appendChild(heading('The relation, line by line'));
  body.appendChild(relationHost);
  body.appendChild(annexHost);

  body.appendChild(
    detailsEl(
      'The t1 = 0 branch — the refusal nobody reaches by accident',
      [
        para(
          'GM/T 0044.2 clause 5.3 step A3 has a branch nobody ever reaches by accident: if t1 comes out '
            + 'zero the key cannot be issued. The button below solves for the master key that makes it '
            + 'happen for whatever identity and hid are selected above, and runs the same extraction code '
            + 'path with it.',
        ),
        controls([rekeyButton]),
        rekeyHost,
      ],
      'p2-t1zero-details',
    ),
  );

  body.appendChild(
    detailsEl(
      'Two master key pairs, mirrored across the two groups',
      [
        para(
          'The scalar arithmetic above is identical on both sides — the same h1, the same sum, the same '
            + 'inversion. What differs is which group each key lands in, and the two sides are exact '
            + 'mirrors of each other. Getting them the wrong way round produces a key that is a perfectly '
            + 'good curve point and is useless, with nothing thrown.',
        ),
        mirrorTable(),
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
      ],
      'p2-mirror-details',
    ),
  );

  body.appendChild(
    detailsEl(
      'What SM9 is not: Boneh-Franklin, and why the inversion is there at all',
      [
        para(
          'The scheme most readers meet first is Boneh-Franklin, and it does the obvious thing: hash the '
            + 'identity onto the curve, then multiply that point by the master scalar. SM9 does neither '
            + 'half of that.',
        ),
        bonehFranklinFlows(),
        comparisonTable(),
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

  // The symbolic path, with nothing computed. Painted on mount so the reader can
  // see what the button is going to do before pressing it.
  paintRelation('signature');

  return {
    root,
    reset: () => {
      cancelReveal();
      identityInput.value = 'Alice';
      hidSelect.value = String(HID.SIGN);
      sideSelect.value = 'signature';
      mapControl.set('standard');
      paintRelation('signature');
      setVerdict(verdictHost, 'pending', 'pending — no key has been extracted yet');
      replace(questionsHost, []);
      replace(annexHost, []);
      clear(rekeyHost);
    },
  };
}
