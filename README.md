# SM9 Forge

**GM/T 0044 · GB/T 38635 · ISO/IEC 14888-3 · ISO/IEC 18033-5**

SM9 identity-based key extraction, digital signature, key exchange and public key
encryption, run in the browser against the worked examples printed in the standard
itself.

**Live demo:** https://systemslibrarian.github.io/crypto-lab-sm9-forge/

---

## What It Is

SM9 is China's identity-based cryptography standard: your identity string *is* your
public key, and an authority called the KGC mints the matching private key. This lab
implements the whole family — key extraction, the digital signature algorithm
(GM/T 0044.2), the key exchange protocol (GM/T 0044.3), and the key encapsulation
mechanism and public key encryption (GM/T 0044.4) — over the 256-bit Barreto-Naehrig
curve and R-ate pairing of GM/T 0044.5 clause 3.1.

The thing worth coming for is **how the private key is made**. Boneh-Franklin IBE, the
scheme most people meet first, hashes an identity *to a curve point* and multiplies it
by the master secret. SM9 hashes the identity *to a scalar*, adds the master secret,
and **inverts** — `t1 = H1(ID‖hid, N) + ks`, `t2 = ks · t1⁻¹`, `ds_A = [t2]P1`. No
hash-to-curve appears anywhere in SM9 key extraction. That one structural difference
pays for itself twice over: SM9 carries **two** master key pairs in mirrored pairing
groups, so the authority can both read your mail and sign in your name; and the
inversion makes the identity hash **cancel** out of the verification equation, so a
passing check proves that extraction and verification agreed on a map, not that either
of them used SM9's.

**Security model.** Every private key in SM9 is derivable by the KGC from the identity
alone, by design. There is no forward secrecy against the KGC and no way to opt out:
the same two lines of clause 5.3 that define extraction define the escrow. Pane 4
demonstrates both halves of that rather than describing them.

**Not production cryptography — a teaching demo.** Everything runs in your browser.
Key material is per-session and in memory; nothing is persisted and nothing leaves the
page.

## Exhibits

1. **Parameters, and the SM3 layer** — the BN256 curve constants read from
   GM/T 0044.5 clause 3.1, with `cid = 0x12` and `eid = 0x04` decoded into words, then
   H1, H2 and the KDF reproduced against the standard's own printed sub-values **with
   no pairing running**. A deliberately wrong negative control runs beside them and
   must be reported as a mismatch.
2. **Extraction — the inversion** — the headline. The five lines of the relation are
   painted before anything is computed and fill one operation at a time when you press
   Extract. A two-state control then asks the same five questions under SM9's own H1 and
   under an altered identity map: the key differs, the annex's pinned intermediates stop
   matching and the real verifier refuses — while the cancellation identity still holds
   and a verifier using the same altered map still accepts. Boneh-Franklin's
   multiplication is drawn beside it for contrast, the two master key pairs are shown in
   their mirrored groups, and a control drives the `t1 = 0` branch the standard defines
   and almost nothing ever reaches.
3. **The three protocols** — sign/verify against Annex A, key exchange against
   Annex B, and KEM/encryption against Annexes C and D, each beside its pinned vector
   with a byte-equality badge. Signing with the annex's pinned nonce is
   byte-reproducible; a fresh nonce changes the signature and still verifies.
4. **What the KGC can do** — escrow as two separate powers: with `ke` it derives any
   identity's decryption key and reads the message, and with `ks` it derives any
   identity's signing key and produces a signature this page's own verifier accepts.
5. **The break, and the divergence** — a reused nonce recovers the private key and
   forges with it, and Annex B runs at both `hid` values from one master key, reaching
   two different session keys that are labelled by source rather than ranked.

## How the Lab Is Sequenced

The five exhibits are **five gated steps**, not five panels on a page. A step unlocks
when the step before it has produced a real result — not when its button was pressed,
which is a different claim — so the SM3 layer is reproduced before a key is extracted,
and a key exists before any protocol runs on it. Completed steps collapse to the one
line they earned, with a control to reopen them, and a sticky rail carries anchors
(`#step-sm3`, `#step-extract`, `#step-protocols`, `#step-kgc`, `#step-break`) so a
presenter can jump to an act without scrolling through the audit trail.

Nothing is computed that the visitor did not cause. The page used to open with pane 1
saying *pending — not yet run* directly above pane 2 saying *ds_A issued*: the headline
act had already happened and nobody had pressed anything.

**Guided** is the default. **Full evidence** unlocks and expands everything at once and
is one control away at the top — progressive disclosure that cannot be switched off is
just material hidden from the people most likely to check it. Neither view persists:
progress lives in memory and a reload is a full reset, deliberately, because a restored
half-run would be restoring verdicts about inputs the reader can no longer see.

**Copy run transcript** exports the run as JSON — inputs, verdicts, status words,
source labels and computed values — read off the rendered page rather than assembled
beside it, so it cannot disagree with what the page claimed.

### The five-minute path

1. **Run the SM3 checks.** Published vectors reproduced, the negative control reported
   as a mismatch, and zero pairings.
2. **Extract Alice.** Watch `ID‖hid → h1 → t1 → t1⁻¹ → t2 → ds_A` fill one operation at
   a time.
3. **Switch the identity map to an altered H1.** Same five questions; three answers
   change and two do not, and the two that hold are exactly what a round trip can check
   about itself.
4. **Run the KGC's two powers.** It reads a message encrypted to an identity it does
   not hold, and signs as that identity.
5. **Reuse a nonce.** Recover the private key point and forge a third message through
   the real verifier, then meet the `hid` divergence beside it.

## When to Use It

- Use it to see **why an identity-based private key is not a hashed point**, because
  the inversion is visible as its own step and the Boneh-Franklin comparison is drawn
  beside it.
- Use it to understand **what key escrow actually buys an authority**, because both
  powers run live against derived keys rather than being asserted in prose.
- Use it to learn **what a passing signature check does and does not establish**,
  because the page reaches a state where every self-check is green and the identity
  binding is still wrong.
- Do **not** use it for anything real — it is a demo app and does not provide hardened
  operational controls. No constant-time guarantees are claimed or tested, key
  material lives in ordinary JavaScript memory, and the nonce-reuse path exists
  precisely to break the scheme.

## What Can Go Wrong

**A passing check does not pin which identity-to-scalar map produced the key.**
This is the lab's headline finding, and it needs stating precisely because the loose
version of it is false. SM9 verification *does* check the identity binding:
`h1 = H1(ID‖hid, N)` feeds `P = [h1]P2 + Ppub-s`, and a key for another identity, a
key extracted at a different `hid`, or a key extracted under a non-standard H1 are all
refused at `HASH-MISMATCH`.

What the equation does not pin is *which* map both sides used. Extraction sets
`t1 = H1 + ks` and `t2 = ks · t1⁻¹`, so `t1 · t2 = ks` for any H1 whatsoever, and
verification computes `u = e(S, P) = e(P1, P2)^(l·ks)` — **H1 cancels, provided both
sides use the same one.** So a KGC and a verifier that agree on a non-standard
identity hash interoperate perfectly, and their green check says nothing about
conformance to SM9. Pane 3 runs exactly that: the same identity and the same `hid`,
with one extra domain byte in front of H1 on *both* sides, and the page's own
unmodified verifier accepts — while the row beneath shows SM9's real verifier refusing
the same key.

**Conformance is not self-certifying, and the fleet has a real instance of it.** The
same structure runs through key exchange, where `g1`, `g2` and `g3` are
`hid`-independent because `t3` cancels inside `e(R_A, de_B)`, so `hid` reaches the
session key only through the KDF input. That is not a hypothetical: GmSSL and the
standard's own Annex B disagree about `hid` for key exchange, each is internally
consistent, and each produces passing checks against itself. Pane 5 runs both.

**The KEM has no integrity check, and public key encryption does.** GM/T 0044.4
clause 6.2.1 is: check `C` is in G1, pair, KDF, output — with an error only if `K' = 0`.
Decapsulating with a different user key therefore yields a *different key silently*,
not a failure. Encryption fails closed at the MAC, clause 7.2.1 step B4. The page shows
the two outcomes side by side because the difference is the lesson.

**One reused nonce is fatal, and what it costs is a point.** Two signatures over
different messages under one `r` give `S1 − S2 = [h2 − h1]ds_A`, so
`ds_A = [(h2 − h1)⁻¹](S1 − S2)`. The `r` cancels — an attacker never needs it. What
comes back is the private key **point** in G1 and no scalar at all, because an SM9
private key *is* a group element. [SM2 Forge](https://systemslibrarian.github.io/crypto-lab-sm2-forge/)
makes the same mistake and recovers a scalar `d`; the difference is not the attack, it
is what a private key is.

**`hid = 0x02` and `hid = 0x03` do not interoperate.** GM/T 0044.5 Annex B declares
`0x03` and reaches `SK = 68b20d30…`; GmSSL, `emmansun/gmsm` and Bouncy
Castle use `0x02` for key exchange and reach `SK = c5c13a8f…`. Both are internally
consistent. The normative text pins no value at all — clause 5.3 says only that the
KGC "selects a one-byte identifier hid and makes it public".

**Two lines of Annex B are misprinted, in the Chinese original as well as the English.**
Inside an otherwise-`0x03` example, two lines print the `hid` byte as `02`. They are
typos, established three ways: the H1 digest printed beside each is byte-identical to
the `0x03` digest printed in key extraction; `H1("Bob"‖0x02)` appears nowhere in the
document; and taking the bytes literally makes the two sides **disagree**, while the
annex itself prints `SK_A == SK_B`. Transcribing those lines literally will not
reproduce `R_A`. **This does not establish why GmSSL chose `0x02`** — that is an
inference nobody has confirmed, and GmSSL documents no reason.

## Real-World Usage

SM9 is standardised domestically as GM/T 0044-2016 (five parts) and GB/T 38635-2020
(two parts), both in force in different standards systems. Internationally, its
signature is **ISO/IEC 14888-3:2018 clause 7.4, under the name "Chinese IBS"**, and its
key encapsulation is **ISO/IEC 18033-5:2015/Amd 1:2021, "Amendment 1: SM9 mechanism"**,
clause 9.4.

## How to Run Locally

```
npm ci
npm run dev
```

`npm test` runs the unit suite, the known-answer tests and the CSP hash guard.
`npm run test:oracle` runs the independent cross-check. `npm run test:e2e` runs the
claims suite, `npm run test:a11y` the accessibility gate and `npm run test:geometry`
the visual-quality gate; all three need `npx playwright install chromium` first.

The browser gates build first and serve the production build on **port 4646**, which is
this lab's own rather than Vite's default 4173. That is not a preference: several labs
in this fleet kept the default, and `reuseExistingServer` then hands the suites whatever
is already answering on it — a cold run here was silently judged against
`crypto-lab-glass-box` until the port was changed. All three places that name it
(`use.baseURL`, `webServer.command`, `webServer.url`) live in `playwright.config.ts`.

## Related Demos

- [SM2 Forge](https://systemslibrarian.github.io/crypto-lab-sm2-forge/) — the other
  ShangMi public-key standard, and the nonce-reuse contrast: there the recovered key
  is a scalar.
- [IBE Gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/) — Boneh-Franklin
  identity-based encryption, the multiplication this lab's extraction is contrasted
  against.
- [Pairing Gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/) — what a
  bilinear pairing is, on BLS12-381. This lab assumes it.

## Build & Verify

**419 unit tests, 35 rendered-verdict claims tests, a 26-test independent cross-check
and a 5-test geometry gate.** The accessibility gate scans the production build at
1280px and 380px across 20 driven states each — the guided path a visitor actually
walks, including the locked, collapsed and Full-evidence renderings — and blocks the
deploy on any WCAG 2.1 A/AA violation.

**The geometry gate is the one axe cannot run.** It measures the landing page's height,
where the first meaningful action sits in the viewport, the hero's stacked gap at phone
width, and the painted size of every text run. It exists because the two pane-2 SVG
diagrams passed the accessibility gate while rendering their labels at roughly five CSS
pixels on a phone: the contrast oracle measured them correctly, and contrast is not
legibility. Both diagrams are HTML now, and the rule that caught them is a test.

**Known-answer tests.** Every figure comes from GM/T 0044.5, fetched directly from
gmbz.org.cn (`md5 40cee7ca9ab2b885dee2158b2d4a12cc`) and pinned in
`src/sm9/fixtures/`. Annex A signature 47/47 including all eight must-reject cases,
Annex B key exchange 37/37, Annex C KEM 25/25, Annex D encryption 53/53 across both
modes, failure direction 15/15. The BN256 constants are not merely transcribed: their
test re-derives `q`, `N` and the trace from `t` using the standard's own polynomials.

**The independent cross-check shares no code path with the runtime** — GmSSL C's own
pinned vectors from `tests/sm9test.c`, plus OpenSSL's SM3 through `node:crypto` driving
the same H1/H2/KDF constructions. It is not decorative: writing it caught a mis-derived
assertion, where `hex_fn_nsub` turned out to be the reverse subtraction `y − x` rather
than `N − x`.

**A multi-block H1 case had to be generated.** Every H1 input in the entire standard is
an identity plus one `hid` byte — 4 to 6 bytes — so H1 never crosses a 64-byte SM3
block anywhere in the annexes. H2 and the KDF are already multi-block there (404, 451
and 1288 bytes). The generated cases run at 49, 50, 60, 62, 119 and 200 bytes and are
cross-checked three ways.

**The pairing engine is vendored, and was verified before use.**
`src/vendor/gmssl-sm9.js` is GmSSL-JS's `js/sm9.js`, Apache-2.0, with its notice
preserved. The single change is at the end of the file: the bare `pairing_test()` call
was removed and the function exported instead, because upstream's self-check only
`console.log`s a boolean and exits 0 whether it passes or fails. It was driven through
65 of GmSSL C's own `hex_*` vectors plus 24 consistency checks covering the branches
that have no C vector.

### Limits of that verification, stated rather than implied

- **The Fp12 pairing values rest on one engine.** Three implementations agree on every
  non-pairing value, but `g`, `w`, `u` and `w'` are the *standard's printed values
  agreeing with GmSSL-JS*, not two independent pairing engines agreeing. No second
  browser-capable SM9 pairing implementation exists to close this.
- **No constant-time claim is made or tested.** This is ordinary JavaScript with BigInt
  arithmetic; it is not hardened against timing analysis and nothing here measures that.
- **`GB/T 41389-2022` has not been read** by anyone who worked on this lab. It is
  reportedly where the `hid = 1` / `hid = 3` convention is actually pinned, which makes
  it the most load-bearing document for the `hid` question, and it is cited here as
  unread rather than summarised second-hand.
- **ISO/IEC 14888-3:2018's clause 7.4 body is paywalled.** The mechanism is named
  "Chinese IBS" in the publicly readable front matter, which never uses the string
  "SM9"; that the body matches GM/T 0044.2 step for step is not verified here.
- **The `hid = 0x02` attributions were read, not inherited.** GmSSL, `emmansun/gmsm`
  and Bouncy Castle were each checked in source. Bouncy Castle declares
  `HID_EXCHANGE = (byte)0x02` in
  `core/src/main/java/org/bouncycastle/crypto/params/SM9EncMasterPrivateKeyParameters.java`,
  and its own comment there attributes the value to the Chinese edition of the
  GM/T 0044.5-2016 Annex B worked example, noting the official English edition of the
  same annex chose `0x03`. **That last attribution is Bouncy Castle's claim about the
  two editions, quoted rather than confirmed here** — this lab has not compared the two
  editions itself, and says so on the page.

### A note on npm packages claiming SM9

**`@lryncloud/crypto` is not SM9, and should not be used.** Its G1 and G2 elements are
bare scalars, its "pairing" multiplies two scalars mod `n`, GT is a single integer, and
its signature is `s = d·h mod n` — while it pins the genuine SM9 `q`, `n`, `P1` and
`hid` bytes so the parameter file looks authentic. It hashes domain-separation strings
such as `"SM9-H1-SIGN"` in place of H1's `0x01`-prefixed two-block counter chain. At the
time of writing no vetted browser-capable SM9 package exists on npm: `@li0ard/sm9` does
not exist, and `gmssl-node` is a native addon that cannot run in a browser and exposes
no way to load a pinned master key.

## Performance

One R-ate pairing measures **median 12.92 ms, p95 17.64 ms** in Node on an Apple M5
(n = 50, warmed). In the browser it is roughly **4-5 ms in Chromium and 18-22 ms in
Firefox**. Verification costs two pairings and is comfortable everywhere; key exchange
costs several. These are measurements of one machine and one build, not a benchmark of
SM9.

## Security level

Post-exTNFS estimates for a BN curve with a 256-bit prime differ between published
sources, and both are quoted here rather than averaged or picked between:
Menezes, Sarkar and Singh give *"a conservative estimate … is 110 bits"*
([ePrint 2016/1102](https://eprint.iacr.org/2016/1102), Remark 6); Barbulescu and
Duquesne, arguing the former is not precise enough, give *"in fact 100 bits"*. Neither
is this lab's own measurement.

## License

MIT — see [LICENSE](LICENSE).

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
