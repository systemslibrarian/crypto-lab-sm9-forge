/**
 * PANE 4 — what the KGC can do.
 *
 * WHY THIS PANE NEEDS TWO MASTER KEYS TO BE INTERESTING. A single-master-key IBE
 * lab can show escrow, but it can only show it as one power: the authority can
 * read. SM9 splits the master key in two — ks for signatures, ke for encryption
 * — and clause 5.3 defines extraction identically on both sides. So the same two
 * lines of arithmetic give the KGC two structurally different capabilities, and
 * a deployment can hold one without the other. That separation is what this pane
 * exists to make visible, and it is not available to an exhibit with one master
 * key.
 *
 *   with ke — derive any identity's DECRYPTION key, and read the message
 *   with ks — derive any identity's SIGNING key, and sign AS that identity
 *
 * BOTH RUN LIVE, AGAINST DERIVED KEYS. Nothing on this panel echoes its input:
 * the recovered plaintext is rendered from the bytes `decrypt` returned, and the
 * forged signature is put to the same `verify` function pane 3 uses, unmodified.
 * A panel that printed the message it was handed would demonstrate nothing, and
 * would look exactly the same.
 *
 * THE SECOND VERDICT IS AN ALARM, NOT A SUCCESS. The KGC's signature is
 * cryptographically correct — that is the problem with it. Rendering it green
 * because the maths worked would be the page agreeing with the attacker.
 */
import { HID } from '../sm9/params';
import { bytesToHex } from '../sm9/hash';
import {
  encryptMasterKeyPair,
  extractEncryptKey,
  extractSignKey,
  fp2Components,
  signMasterKeyPair,
  toFieldHex,
} from '../sm9/extract';
import { sign, signatureToHex, verify } from '../sm9/sign';
import { decrypt, encrypt } from '../sm9/encrypt';
import annexA from '../sm9/fixtures/annexA-fixture.json';
import annexCD from '../sm9/fixtures/sm9-annex-cd-fixtures.json';
import {
  box,
  button,
  clear,
  controls,
  decodeUtf8,
  defer,
  detailsEl,
  el,
  encodeUtf8,
  equality,
  heading,
  hexBlock,
  kv,
  labelled,
  note,
  pane,
  para,
  replace,
  setVerdict,
  sideBySide,
  statusPill,
  textInput,
  verdictSlot,
} from './dom';

import type { Exhibit, ExhibitHost } from './exhibit';

const KS = BigInt(`0x${annexA.signature.ks}`);
const KE = BigInt(`0x${annexCD.annex_C_kem.master_encryption_private_key_ke}`);

export function buildPane4(host: ExhibitHost): Exhibit {
  const { root, body } = pane(
    'PANE 4',
    'What the KGC can do',
    'GM/T 0044.2 clause 5.3 and GM/T 0044.3 clause 5.3 — the same two lines that define extraction',
    'p4-pane',
  );

  body.appendChild(
    para(
      'Identity-based cryptography removes the certificate authority and replaces it with something '
        + 'stronger. A certificate authority can vouch for a public key it did not generate; a Key '
        + 'Generation Centre generates the private key itself. Everything below follows from that one '
        + 'fact, and none of it is a flaw — it is the design, stated in the same clause that defines '
        + 'how keys are issued.',
    ),
  );

  const identityInput = textInput('Alice', 'p4-identity', 14);
  const messageInput = textInput('Meet me at the usual place at nine.', 'p4-message', 38);
  const readButton = button('KGC: derive the decryption key and read it', 'p4-run-read', 'danger');
  const signButton = button('KGC: derive the signing key and sign as this identity', 'p4-run-sign', 'danger');

  /**
   * Both powers, or the step is not done.
   *
   * The pane's claim is that the KGC holds TWO capabilities from the same two
   * lines of arithmetic. A step that completed on the first of them would let a
   * reader move on having seen half the finding.
   */
  const performed = { read: false, sign: false };
  function reportBoth(): void {
    if (performed.read && performed.sign) {
      host.onComplete(
        'the KGC read a message encrypted to an identity it does not hold, and signed as that same '
          + 'identity — both accepted by this page\'s own unmodified code',
      );
    } else {
      host.onStale();
    }
  }

  const readVerdict = verdictSlot('p4-read-verdict', 'pending — the KGC has not derived anything yet');
  const readOut = el('div', { testid: 'p4-read-output' });
  const signVerdict = verdictSlot('p4-sign-verdict', 'pending — the KGC has not derived anything yet');
  const signOut = el('div', { testid: 'p4-sign-output' });

  readButton.addEventListener('click', () => {
    replace(readOut, [statusPill('info', 'computing')]);
    defer(() => {
      const identity = identityInput.value;
      const plaintext = encodeUtf8(messageInput.value);
      const master = encryptMasterKeyPair(KE);

      // The sender. Holds only the identity string and the master PUBLIC key —
      // no certificate, no round trip, no contact with the receiver or the KGC.
      const ciphertext = encrypt(plaintext, identity, HID.ENCRYPT, master.Ppube, { mode: 'a' });

      // The KGC. Holds ke, and therefore holds every user's private key whether
      // or not it has ever issued one.
      const derived = extractEncryptKey(master, identity, { hid: HID.ENCRYPT });
      if (!derived.ok) {
        replace(readOut, []);
        setVerdict(
          readVerdict,
          'info',
          `${derived.outcome} for this identity`,
          'This identity happens to land on the clause 5.3 step A3 re-key branch under this master key. '
            + 'Pane 2 has that branch as an exhibit of its own.',
        );
        return;
      }

      const recovered = decrypt(ciphertext.bytes, identity, derived.deB, { mode: 'a' });
      const recoveredBytes = recovered.ok ? recovered.message : new Uint8Array();

      replace(readOut, [
        kv(
          [
            ['the sender knew', el('span', { text: `the string "${identity}" and Ppub-e. Nothing else.` })],
            ['Ppub-e = [ke]P1', hexBlock(`${toFieldHex(master.Ppube.X)}${toFieldHex(master.Ppube.Y)}`, 'p4-read-ppube')],
            ['ciphertext C = C1 ‖ C3 ‖ C2', hexBlock(bytesToHex(ciphertext.bytes), 'p4-read-ciphertext')],
            [
              'de (derived by the KGC from ke)',
              hexBlock(
                `${fp2Components(derived.deB.X).join('')}${fp2Components(derived.deB.Y).join('')}`,
                'p4-read-de',
              ),
            ],
            ['t1 = H1(ID‖hid) + ke', hexBlock(toFieldHex(derived.t1), 'p4-read-t1')],
            ['t2 = ke · t1⁻¹', hexBlock(toFieldHex(derived.t2), 'p4-read-t2')],
            [
              'plaintext recovered by decrypt()',
              hexBlock(
                recovered.ok ? bytesToHex(recoveredBytes) : `refused at ${recovered.step}: ${recovered.cause}`,
                'p4-read-recovered',
              ),
            ],
            [
              'the same bytes, decoded as text',
              el('span', {
                text: recovered.ok ? decodeUtf8(recoveredBytes) : 'nothing was recovered',
                testid: 'p4-read-recovered-text',
              }),
            ],
            [
              'does it match what the sender encrypted?',
              equality(
                recovered.ok && bytesToHex(recoveredBytes) === bytesToHex(plaintext),
                'byte-identical',
                'differs',
                'p4-read-match',
              ),
            ],
          ],
          'p4-read-values',
        ),
        note(
          [
            'Everything in the two rows above came out of ',
            el('strong', { text: 'decrypt()' }),
            ', not out of the input box. The KGC never saw the plaintext, never saw a private key from '
              + 'the receiver, and never contacted anybody: it recomputed clause 5.3 with ke and the '
              + 'string in the identity field, and that was sufficient.',
          ],
          false,
          'p4-read-not-echo',
        ),
      ]);

      setVerdict(
        readVerdict,
        'alarm',
        recovered.ok
          ? 'THE KGC READ THE MESSAGE — it holds every user\'s decryption key by construction'
          : `decryption was refused at step ${recovered.step}: ${recovered.cause}`,
        'Holding ke is holding de for every identity that exists or ever will. No key escrow database '
          + 'is involved and no key was ever stored: each one is two lines of arithmetic away from the '
          + 'master key. Revoking a compromised user key is therefore not possible either — the '
          + 'identity is the key, and the KGC can reissue it.',
      );
      performed.read = recovered.ok;
      reportBoth();
    });
  });

  signButton.addEventListener('click', () => {
    replace(signOut, [statusPill('info', 'computing')]);
    defer(() => {
      const identity = identityInput.value;
      const statement = encodeUtf8(messageInput.value);
      const master = signMasterKeyPair(KS);

      const derived = extractSignKey(master, identity, { hid: HID.SIGN });
      if (!derived.ok) {
        replace(signOut, []);
        setVerdict(
          signVerdict,
          'info',
          `${derived.outcome} for this identity`,
          'This identity lands on the clause 5.3 step A3 re-key branch under this master key.',
        );
        return;
      }

      const forged = sign(statement, derived.dsA, master.Ppubs);
      // The page's own verifier. Not a copy, not a relaxed variant — the same
      // function pane 3 runs against GM/T 0044.5 Annex A.
      const checked = verify(statement, identity, forged.signature, master.Ppubs, { hid: HID.SIGN });
      const hex = signatureToHex(forged.signature);

      replace(signOut, [
        kv(
          [
            ['statement signed', el('span', { text: `"${messageInput.value}"` })],
            ['signed as', el('span', { text: identity, testid: 'p4-sign-identity' })],
            [
              'ds (derived by the KGC from ks)',
              hexBlock(`${toFieldHex(derived.dsA.X)}${toFieldHex(derived.dsA.Y)}`, 'p4-sign-ds'),
            ],
            ['h', hexBlock(hex.h, 'p4-sign-h')],
            ['S', hexBlock(hex.S, 'p4-sign-s')],
            [
              'the page\'s own verifier, unmodified',
              statusPill(
                checked.accepted ? 'alarm' : 'ok',
                checked.accepted ? 'ACCEPTED as a signature by this identity' : `refused at ${checked.failure}`,
                'p4-sign-accepted',
              ),
            ],
            [
              'h2 the verifier recomputed',
              hexBlock(toFieldHex(checked.steps.h2 ?? 0n), 'p4-sign-h2'),
            ],
            [
              'does h2 equal the signature\'s h?',
              equality(checked.steps.h2 === forged.signature.h, 'equal — clause 7.1 step S6 passes', 'differs', 'p4-sign-h2-match'),
            ],
          ],
          'p4-sign-values',
        ),
        note(
          [
            el('strong', { text: 'Nothing here is a forgery in the cryptographic sense. ' }),
            'The KGC did not break anything or guess anything. It ran clause 5.3 with ks and the '
              + 'identity string, and got the same ds that identity\'s owner holds — bit for bit, because '
              + 'extraction is deterministic. The signature is genuine. It is simply not evidence that '
              + 'the named party wrote anything, and no verifier anywhere can tell the difference.',
          ],
          true,
          'p4-sign-not-forgery',
        ),
      ]);

      setVerdict(
        signVerdict,
        'alarm',
        checked.accepted
          ? 'THE KGC SIGNED AS THIS IDENTITY, AND THE REAL VERIFIER ACCEPTED'
          : `the verifier refused at ${checked.failure}`,
        'A cryptographically correct result, and a catastrophic one. SM9 signatures are therefore not '
          + 'non-repudiable against the KGC: the named signer can always say the authority did it, and '
          + 'nothing in the signature contradicts them.',
      );
      performed.sign = checked.accepted;
      reportBoth();
    });
  });

  body.appendChild(
    controls([
      labelled('Identity', identityInput),
      labelled('Message or statement', messageInput),
    ]),
  );

  // SIDE BY SIDE, BECAUSE THE FINDING IS THAT THERE ARE TWO OF THEM. Stacked
  // under two headings, the second power was a screen below the first and read as
  // a variation on it. `.side-by-side` collapses to one column below 19rem, so on
  // a phone these are still two focused acts, one after the other.
  body.appendChild(heading('The two powers, from the same two lines of arithmetic'));
  body.appendChild(
    sideBySide([
      box('Power one — with ke, the KGC reads', [
        para(
          'A sender encrypts to the identity string above using only the master public key. The KGC '
            + 'then derives that identity\'s decryption key from ke and decrypts. The receiver is not '
            + 'involved and need not exist.',
        ),
        controls([readButton]),
        readVerdict,
        readOut,
      ], 'p4-power-read'),
      box('Power two — with ks, the KGC signs as you', [
        para(
          'The same arithmetic on the other master key gives the other capability. The KGC derives the '
            + 'identity\'s signing key, signs the statement above, and the signature is put to the same '
            + 'verify() this page runs against GM/T 0044.5 Annex A.',
        ),
        controls([signButton]),
        signVerdict,
        signOut,
      ], 'p4-power-sign'),
    ]),
  );

  body.appendChild(
    note(
      [
        el('strong', { text: 'This is the design, not a flaw, and the standard does not hide it. ' }),
        'GM/T 0044.2 clause 5.3 and GM/T 0044.3 clause 5.3 are the same two lines — t1 = H1(ID‖hid) + '
          + 'master, t2 = master · t1⁻¹ — and they are simultaneously the definition of key issuance and '
          + 'the definition of the escrow. There is no version of SM9 in which the KGC can issue keys '
          + 'and cannot also use them. The engineering question is never "how do we remove this?" but '
          + '"who is the KGC, what are they bound by, and is that acceptable for this use?".',
      ],
      false,
      'p4-design-note',
    ),
  );

  body.appendChild(
    detailsEl(
      'What the two-master-key split does and does not buy',
      [
        para(
          'Because ks and ke are independent scalars, a deployment can put them in different hands or '
            + 'under different controls. An operator holding only ke can read traffic and cannot sign as '
            + 'anybody; an operator holding only ks can sign as anybody and cannot read. That is a real '
            + 'separation and it is worth having.',
        ),
        para(
          'What it does not buy is any reduction in either power. Splitting the key does not weaken the '
            + 'escrow; it partitions it. Threshold or multi-party generation of ks and ke is the usual '
            + 'answer to that, and it is out of scope for this lab: SM9 as standardised has one holder '
            + 'per master key.',
        ),
      ],
      'p4-split-details',
    ),
  );

  return {
    root,
    reset: () => {
      performed.read = false;
      performed.sign = false;
      clear(readOut);
      clear(signOut);
      setVerdict(readVerdict, 'pending', 'pending — the KGC has not derived anything yet');
      setVerdict(signVerdict, 'pending', 'pending — the KGC has not derived anything yet');
    },
  };
}
