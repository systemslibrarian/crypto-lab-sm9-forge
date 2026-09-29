/**
 * Mounts the five exhibits as the five steps of one guided lab, plus the security
 * level note that closes the page.
 *
 * THE ORDER IS AN ARGUMENT, NOT A LAYOUT. SM3 first because it is the cheapest
 * honest check and everything downstream is arithmetic on its output; extraction
 * second because it is the mechanism the whole scheme turns on; the protocols
 * third because they are what the mechanism is for; the KGC's two powers fourth
 * because they follow from the mechanism rather than from any protocol; and the
 * break last because it is the only exhibit that needs a mistake rather than a
 * design. src/ui/lab.ts gates them in that order and explains why it gates
 * anything at all.
 *
 * WHY THE SECURITY NOTE IS A RANGE AND NOT A NUMBER. SM9's BN256 curve has two
 * published post-exTNFS estimates and they do not agree. Picking one and
 * printing it would be this page making a judgement it has no standing to make,
 * and a single number on a page like this is read as settled. Both are quoted,
 * both are attributed, and the page says outright that it does not choose.
 *
 * Note what is NOT carried across: crypto-lab-pairing-gate publishes a figure for
 * BLS12-381, which is a different curve with a different embedding degree. A
 * number that belongs to another curve is exactly the kind of inheritance this
 * fleet keeps having to correct.
 */
import { buildPane1 } from './ui/pane1-parameters';
import { buildPane2 } from './ui/pane2-extraction';
import { buildPane3 } from './ui/pane3-protocols';
import { buildPane4 } from './ui/pane4-escrow';
import { buildPane5 } from './ui/pane5-break';
import { buildLab } from './ui/lab';
import type { StepSpec } from './ui/lab';
import { detailsEl, el, heading, note, pane, para, tableEl } from './ui/dom';

const PAIRING_GATE = 'https://systemslibrarian.github.io/crypto-lab-pairing-gate/';

/**
 * The security level of SM9's curve, as two published estimates rather than one
 * figure. Both quotations and both attributions come from the sources named
 * beside them; neither is this lab's own analysis and neither is averaged with
 * the other.
 */
function buildSecurityLevelNote(): HTMLElement {
  const { root, body } = pane(
    'NOTE',
    'Security level — a range, with two attributions',
    'Post-exTNFS estimates for a BN curve with a 256-bit prime',
    'security-note',
  );

  body.appendChild(
    para(
      'SM9 is built on a BN curve with a 256-bit prime and embedding degree 12. Before 2016 a '
        + 'parameter set like this one was routinely described as offering 128-bit security. The '
        + 'extended tower number field sieve changed the cost of the finite-field discrete logarithm '
        + 'in the target group, and the published re-estimates for this curve do not agree with each '
        + 'other. Both are quoted below. This page does not pick one, and does not average them.',
    ),
  );

  body.appendChild(
    tableEl(
      ['Estimate', 'What the source says', 'Source'],
      [
        [
          el('span', { text: '110 bits', testid: 'security-mss-figure' }),
          el('span', {
            text: 'a conservative estimate … is 110 bits',
            testid: 'security-mss-quote',
          }),
          el('span', {
            text: 'A. Menezes, P. Sarkar and S. Singh, "Challenges with Assessing the Impact of NFS '
              + 'Advances on the Security of Pairing-based Cryptography", IACR ePrint 2016/1102, Remark 6',
            testid: 'security-mss-source',
          }),
        ],
        [
          el('span', { text: '100 bits', testid: 'security-bd-figure' }),
          el('span', {
            text: 'in fact 100 bits — arguing that the more conservative estimate is not precise enough',
            testid: 'security-bd-quote',
          }),
          el('span', {
            text: 'R. Barbulescu and S. Duquesne, "Updating Key Size Estimations for Pairings"',
            testid: 'security-bd-source',
          }),
        ],
      ],
      'security-table',
      'The two published post-exTNFS estimates for this curve',
    ),
  );

  body.appendChild(
    note(
      [
        el('strong', { text: 'Read it as a range. ' }),
        'Two published analyses of the same curve, differing by ten bits, with one explicitly arguing '
          + 'the other is imprecise. That is the honest state of the estimate, and the useful thing to '
          + 'carry away is the shape of it: this curve is not a 128-bit parameter set, and the gap '
          + 'between the two figures is smaller than the gap between either of them and what the curve '
          + 'was assumed to offer before exTNFS.',
      ],
      false,
      'security-range',
    ),
  );

  body.appendChild(
    note(
      [
        'What a bilinear pairing is, and why the embedding degree decides where the discrete logarithm '
          + 'has to be hard, is a different exhibit: ',
        el('a', {
          text: 'crypto-lab-pairing-gate',
          attrs: { href: PAIRING_GATE, target: '_blank', rel: 'noopener' },
          testid: 'security-pairing-gate-link',
        }),
        '. Any security figure published there belongs to the curve that exhibit is about and does not '
          + 'transfer to BN256 — a number carried across from an adjacent curve looks exactly like a '
          + 'derived one on the page.',
      ],
      false,
      'security-scope',
    ),
  );

  body.appendChild(heading('What this page is not a statement about'));
  body.appendChild(
    para(
      'Nothing on this page is an attack on the curve or on the pairing, and nothing here compares '
        + 'SM9\'s strength with Boneh-Franklin\'s, ECDSA\'s or BLS\'s. The two exhibits that end in an '
        + 'alarm — the KGC\'s two powers in pane 4, and the reused-nonce recovery in pane 5 — are a '
        + 'property of the design and an implementation mistake respectively, and neither is a weakness '
        + 'in the underlying mathematics.',
    ),
  );

  return root;
}

/**
 * The limits of this lab's own verification, inside the lab.
 *
 * These were in the README and nowhere on the page, which is the wrong way round:
 * the reader who most needs them is the one looking at a screen of green badges,
 * and they are not reading the repository. Each line names a specific thing that
 * was NOT established, because "this is a teaching demo" is a disclaimer and
 * these are facts.
 */
function buildEvidenceLimits(): HTMLElement {
  return detailsEl(
    'Evidence and limits — what this lab did not establish',
    [
      para(
        'Everything on this page is computed in the browser and compared against values printed in '
          + 'GM/T 0044.5 or produced by implementations sharing no code with this one. That is a real '
          + 'standard of evidence and it has edges. These are the edges.',
      ),
      el('ul', { class: 'limits' }, [
        el('li', {}, [
          el('strong', { text: 'The Fp12 pairing values rest on one engine. ' }),
          'Three implementations agree on every non-pairing value, but g, w, u and w′ are the '
            + 'standard\'s printed values agreeing with one runtime pairing engine — not two '
            + 'independent pairing engines agreeing with each other. No second browser-capable SM9 '
            + 'pairing implementation exists to close this.',
        ]),
        el('li', {}, [
          el('strong', { text: 'No constant-time property is claimed or tested. ' }),
          'This is ordinary JavaScript over BigInt. Nothing here is hardened against timing analysis '
            + 'and nothing here measures it.',
        ]),
        el('li', {}, [
          el('strong', { text: 'GB/T 41389-2022 has not been read. ' }),
          'It is reportedly where the hid = 1 / hid = 3 convention is actually pinned, which makes it '
            + 'the most load-bearing document for the hid question in step 5. It is cited as unread '
            + 'rather than summarised second-hand.',
        ]),
        el('li', {}, [
          el('strong', { text: 'ISO/IEC 14888-3:2018 clause 7.4\'s body is paywalled. ' }),
          'The mechanism is named "Chinese IBS" in the publicly readable front matter, which never '
            + 'uses the string "SM9". That the body matches GM/T 0044.2 step for step is not verified '
            + 'here.',
        ]),
        el('li', {}, [
          el('strong', { text: 'The hid 0x02 attributions were read, not inherited. ' }),
          'GmSSL, emmansun/gmsm and Bouncy Castle were each checked in source. Bouncy Castle declares ',
          el('code', { class: 'path', text: 'HID_EXCHANGE = (byte)0x02' }),
          ' in ',
          // A 90-character path with no break opportunity in it, which at 380px
          // pushed the whole document 351px wider than the viewport. `.path`
          // carries overflow-wrap: anywhere for exactly this.
          el('code', {
            class: 'path',
            text: 'core/src/main/java/org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters.java',
          }),
          ', and its own comment attributes the value to the Chinese edition of the GM/T 0044.5-2016 '
            + 'Annex B worked example, noting that the official English edition of the same annex chose '
            + '0x03. That last attribution is Bouncy Castle\'s claim about the two editions, quoted '
            + 'here, not this lab\'s finding.',
        ]),
        el('li', {}, [
          el('strong', { text: 'A round trip is not a conformance check, and this lab says so twice. ' }),
          'Step 2\'s two-state experiment and step 3\'s act (a) both demonstrate it live: extraction '
            + 'and verification agreeing on a wrong identity map is indistinguishable from both being '
            + 'right. Only the pinned annex intermediates catch it.',
        ]),
      ]),
      para(
        'Nothing on this page is production cryptography, and no key material leaves it or is stored '
          + 'anywhere — including the progress of the run itself, which lives only in memory and is '
          + 'gone on reload.',
      ),
    ],
    'lab-limits',
  );
}

const STEPS: StepSpec[] = [
  {
    id: 'sm3',
    short: 'SM3',
    action: 'run the SM3 layer against the standard\'s own vectors',
    unlocks: 'This step is locked until step 1 reproduces the SM3 layer. That is not ceremony: H1, H2 '
      + 'and the KDF are what every value downstream is computed from, so a lab that let you extract a '
      + 'key before checking them would be inviting you to trust arithmetic over bytes nobody had '
      + 'verified.',
    build: buildPane1,
  },
  {
    id: 'extract',
    short: 'Extract',
    action: 'extract an identity key, and watch the inversion',
    unlocks: 'Locked until step 1 reproduces the SM3 layer. H1 is the first line of the relation this '
      + 'step performs; checking it afterwards would be checking it too late.',
    build: buildPane2,
  },
  {
    id: 'protocols',
    short: 'Protocols',
    action: 'sign, exchange and encrypt against the annexes',
    unlocks: 'Locked until step 2 issues a key. All three protocols run on a key the KGC extracted, so '
      + 'there is nothing for them to run on until one exists.',
    build: buildPane3,
  },
  {
    id: 'kgc',
    short: 'KGC',
    action: 'see what the KGC can do with the same two lines',
    unlocks: 'Locked until step 3 reproduces Annex A. The two powers below are the same verifier and '
      + 'the same decryption accepting the KGC\'s work, and they mean nothing until you have seen that '
      + 'verifier accept a genuine signature first.',
    build: buildPane4,
  },
  {
    id: 'break',
    short: 'Break',
    action: 'recover a key from a reused nonce, and meet the divergence',
    unlocks: 'Locked until step 4 has shown both of the KGC\'s powers. This step is the only one that '
      + 'needs an implementation mistake rather than a design property, and the contrast is the point.',
    build: buildPane5,
  },
];

const host = document.getElementById('panes');
if (host === null) {
  throw new Error('main.ts: index.html is missing its #panes mount point');
}

host.appendChild(buildLab(STEPS, buildEvidenceLimits(), buildSecurityLevelNote()));
