/**
 * Mounts the five exhibits into the shell's #panes, in order, plus the security
 * level note that closes the page.
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
import { el, heading, note, pane, para, tableEl } from './ui/dom';

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

const host = document.getElementById('panes');
if (host === null) {
  throw new Error('main.ts: index.html is missing its #panes mount point');
}

host.appendChild(buildPane1());
host.appendChild(buildPane2());
host.appendChild(buildPane3());
host.appendChild(buildPane4());
host.appendChild(buildPane5());
host.appendChild(buildSecurityLevelNote());
