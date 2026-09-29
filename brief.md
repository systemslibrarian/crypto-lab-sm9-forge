# BUILD BRIEF — crypto-lab-sm9-forge

Binding spec: `audits/_MASTER-TEMPLATE.md` (copy it into this repo before building;
the catalog root `CLAUDE.md` wins where the two touch).
Lifecycle: Build → Teach → Look → Accessibility → README → Deploy.

Written 2026-09-29. This is a brief only — no lab code is written here.
`--accent`, the favicon emoji and the catalog `data-category` are **left for central
assignment** and must not be chosen in this repo.

---

## WHY THIS IS A SEPARATE LAB

Derived by reading the sibling labs' source, not their READMEs' claims about
themselves. **Every negative claim below is scoped to a commit and re-checkable**:
`crypto-lab-ibe-gate` at `aa8f030`, `crypto-lab-pairing-gate` at `0e3edf0`,
`crypto-lab-sm2-forge` at `4205cbf`. A sibling lab can grow an act at any time, so
re-read before repeating any of this in shipped copy — these are findings with a
date, not properties of those labs.

`crypto-lab-ibe-gate` implements Boneh-Franklin BasicIdent. Its extraction is a
**multiplication of a hashed-to-curve point** — `d_ID = s·H1(ID)`, literally
`Q_ID.multiply(masterKey.s)` at `src/ibe.ts:104`, with `H1 = bls.G1.hashToCurve`
at `src/pairing.ts:58`. At that commit it derives one key type per
identity (`extract()` is the only extraction in the tree), implements no signature
scheme, demonstrates no key-agreement protocol, and states no bit-level security
figure — its hardness statements are qualitative and the only numeric parameter
shown is the 255-bit group order.

SM9's extraction is an **inversion in the exponent**: `t1 = H1(ID‖hid, N) + ks`
over F_N, re-key and re-issue every user key if `t1 = 0`, else `t2 = ks·t1⁻¹` and
`ds_A = [t2]P1` (GM/T 0044.2 §5.3). Same promise — your identity is your public
key — reached by a structurally different route, with a failure branch that has no
counterpart in `ibe-gate`. There is no hash-to-curve in SM9 key extraction at all.

`crypto-lab-pairing-gate` owns the pairing as a primitive on BLS12-381 and BLS as
the scheme over it: bilinearity, aggregation, the rogue-key attack, the type-3 /
XDH / co-CDH framing. It names the optimal Ate pairing (`src/main.ts:218,223,227`)
and carries no BN material. **Treat bilinearity as assumed and link out** — do not
re-teach what a pairing is.

`crypto-lab-sm2-forge` uses no pairing arithmetic: its curve is a plain prime-field
short Weierstrass instance (`src/sm2/curve.ts:25`). Its `brief.md:174` reserved
this scope in one line — *"SM9 (identity-based, pairing) as a sibling lab, not
built here."* This file is that seam.

### VERIFY BEFORE RELYING ON THE NOVELTY CLAIM

Do not write "first", "only", or "no other lab" into any shipped copy. The
supporting sweep is recorded here so it can be **re-run**, not inherited:

- A case-insensitive sweep of the lab clones for `Sakai-Kasahara`, `SK-IBE`,
  `SK-KEM`, `SAKKE`, `RFC 6508`, `MIKEY-SAKKE`, `Boneh-Boyen`, `BB1`, `BB2`,
  `Gentry IBE`, `Waters IBE`, `Chen-Cheng`, `exponent inversion`, `SM9`,
  `ShangMi`, `GM/T 0044`, `GB/T 38635`, `BN256`, `R-ate` returned no
  identity-based exponent-inversion implementation. **Separator classes must
  include Unicode en/em dashes** `[ _–—-]`, and the sweep must exclude
  `node_modules`, `.git`, `dist`, `build`, `coverage` and `*.min.js`, or it will
  miss hyphenated spellings and drown in vendored code.
- **The broader claim "nothing in the fleet does exponent inversion" is FALSE and
  must not be written.** `crypto-lab-credential-veil` computes `A = B^(1/(sk+e))`
  on BLS12-381 in executable code (`src/bbs/bbs.ts:137`) and its README names the
  Boneh-Boyen-Shacham lineage outright. It is not identity-based — no PKG, no
  Extract, `e` is a hash of messages — so the IBE-scoped claim survives and the
  general one does not.
- `crypto-lab-sm2-forge` already inverts a sum containing the private key,
  `(1+d)⁻¹`, at `src/sm2/sm2.ts:145`. **This sharpens the contrast rather than
  weakening it**: the distinction is not inversion-versus-multiplication in
  general, it is *where the inversion sits* — in SM2 inside the signing scalar,
  in SM9 inside the identity key extraction.
- Expect exactly two inversion-of-a-sum hits, both non-IBE, at the two anchors
  above. **If a third appears, the claim has changed** and the copy must change
  with it.

---

## KEY FACTS PINNED (verify each against the primary source before it ships)

All five parts of GM/T 0044-2016 are free and public in official English on the
Cryptography Standardization Technical Committee's own site, with explicit
reproduction permission — pin from there, not from a reseller or a third-party
repository.

- **The worked examples are in Part 5, not Parts 2/3/4.** GM/T 0044.5-2016
  (Parameter Definition) carries Annex A (signature), Annex B (key exchange),
  Annex C (key encapsulation) and Annex D (public key encryption), all
  informative. Parts 2, 3 and 4 end at their process-flow figures and contain no
  numerical examples. *An earlier draft of this brief planned KATs against "the
  standard's annex examples" while citing Parts 2-4; that was false, and the
  correction is why the KAT plan below names Part 5 explicitly.*
- **The curve.** A 256-bit Barreto-Naehrig curve, `y² = x³ + b` with `b = 5`,
  parameter `t = 0x600000000058F98A`, embedding degree 12, twist parameter
  `beta = -2`, curve identifier `cid = 0x12`, pairing identifier `eid = 0x04`
  (R-ate). Read `q`, `N`, `P1` and `P2` out of GM/T 0044.5 §3.1 and do **not**
  paste them from memory or from an implementation.
- **The field tower is 1-2-4-12, not 1-2-6-12.** `Fp2 = Fp[u]/(u² - beta)` with
  `beta = -2`, `Fp4 = Fp2[v]/(v² - u)`, `Fp12 = Fp4[w]/(w³ - v)` (GM/T 0044.5
  §3.2). Common BN254 libraries use 1-2-6-12, so Fp12 serialization and the final
  exponentiation **do not compare across the two** without conversion.
- **Two master key pairs, three protocols, in mirrored groups.** Signature:
  `Ppub-s = [ks]P2` in G2, user key `ds_A` in G1 (GM/T 0044.2 §5.3). Encryption:
  `Ppub-e = [ke]P1` in G1, user key `de_B` in G2 (GM/T 0044.4 §5.3). **Key
  exchange has no master key of its own** — GM/T 0044.3 §5.3 is titled
  *"Generation of the encryption master key and the user's encryption private
  key"* and derives its keys from `ke`. Independently confirmed by ISO/IEC
  18033-5:2015/Amd 1:2021 §9.4.1-9.4.2 (`R = sQ1` in G1, `skID = tQ2` in G2 with
  `t = (M + s)⁻¹s mod p`).
- **The selector is the MASTER KEY PAIR, not `hid`.** A signing key and an
  encryption key differ because they come from different master key pairs, not
  because a byte differs. `hid` is a one-byte private-key-generating-function
  identifier the normative text leaves to the KGC — it *"selects a one-byte …
  identifier hid and makes it public"* — and no part pins a value. *An earlier
  draft of this brief asserted a three-way split, 0x01 sign / 0x02 key-exchange /
  0x03 encrypt. That is false about the standard: SM9 derives two key types, and
  in GM/T 0044 one identity yields two keys, not three, because Annexes B, C and D
  all use the SAME hid off the SAME encryption master key.*
- **The circulating values are convention, and key exchange is genuinely
  contested.** GM/T 0044.5's informative annexes — the conformance vectors — pin
  `hid = 0x01` in Annex A and `hid = 0x03` in Annexes B, C and D, printing the
  `ID‖hid` byte strings (`416C696365 01`, `416C696365 03`, `426F62 03`). *A second
  earlier draft said "0x02 appears nowhere". That is also false and must not be
  inherited:* GmSSL defines `SM9_HID_SIGN`/`EXCH`/`ENC` as `0x01`/`0x02`/`0x03`,
  genuinely uses `0x02` in a dedicated third extract function and in the exchange
  protocol, and `emmansun/gmsm`'s key-exchange tests use `0x02` as well. `0x02` is
  absent from the standard, not from the ecosystem.
- **The split is reproducible from one master key, and was proven rather than
  inferred.** Using Annex B's own master key and the identity "Alice",
  `hid = 0x03` reproduces the standard's `deA` exactly and `hid = 0x02` reproduces
  GmSSL's asserted `deA` exactly. GmSSL's key-exchange test borrows Annex B's
  master key, identities and both random values, then extracts with `0x02` — so
  its vectors are internally consistent and are **not** the standard's.
- **`GB/T 41389-2022` (SM9 密码算法使用规范) is where `hid = 1` / `hid = 3` is
  reportedly pinned, and NOBODY ON THIS BRIEF HAS OPENED IT.** It is the most
  load-bearing document for the whole `hid` question. Fetch it before any page
  copy or CI assertion states where the convention comes from.
- **H1 and H2 are one SM3 counter construction separated by a leading byte.**
  `H_i(Z, n)`: `ct = 0x00000001`, `hlen = 8·ceil((5·ceil(log2 n))/32)` bits,
  `Ha_j = SM3(0x01 ‖ Z ‖ ct)` for H1 and `SM3(0x02 ‖ Z ‖ ct)` for H2, concatenate,
  truncate to `hlen`, output `(Ha mod (n-1)) + 1` in `[1, n-1]` (GM/T 0044.4
  §5.4.2.2-5.4.2.3). For SM9's 256-bit `N` that is exactly two SM3 blocks
  truncated to 320 bits. The KDF is a counter-mode SM3 chain, defined once in
  GM/T 0044.3 §5.4.3 and incorporated by reference into Part 4.
- **Signing.** `g = e(P1, Ppub-s)`; random `r` in `[1, N-1]`; `w = g^r`;
  `h = H2(M ‖ w, N)`; `l = (r - h) mod N`, restart if `l = 0`; `S = [l]ds_A` in
  G1; signature is `(h, S)` (GM/T 0044.2 §6.1).
- **Security level is a range with two attributions, not one number.** Post-exTNFS
  estimates for a BN curve with a 256-bit prime: Menezes-Sarkar-Singh give *"a
  conservative estimate … is 110 bits"*; Barbulescu-Duquesne, arguing the former
  *"is not precise enough"*, give *"in fact 100 bits"*. **Quote both with their
  sources.** Do not carry `crypto-lab-pairing-gate`'s ~128-bit figure across — it
  is about BLS12-381 and is not a statement about this curve.

---

## NEW DEMO BRIEF

```
repo name      : crypto-lab-sm9-forge
short name (H1): SM9 Forge
subtitle       : GM/T 0044 · GB/T 38635 · ISO/IEC 14888-3 · ISO/IEC 18033-5
one-liner      : Extract an identity key by inverting in the exponent, run SM9's
                 signature, key exchange and encryption against the standard's own
                 worked examples, and reach two different session keys from one
                 master key because the standard and the reference implementations
                 chose different bytes.
concept        : An identity-based private key does not have to be a hashed point
                 multiplied by a master secret. SM9 inverts instead — and pays for
                 it with two master key pairs, which makes escrow two separate
                 powers rather than one — and leaves one byte to the authority
                 that the ecosystem never agreed on.
primitives/spec: SM9 (GM/T 0044.1-.5-2016; GB/T 38635.1/.2-2020), SM3 (GM/T 0004 /
                 GB/T 32905) as the hash under H1, H2 and the KDF, the BN256 curve
                 and R-ate pairing of GM/T 0044.5 §3.1, ISO/IEC 14888-3:2018
                 clause 7.4 "Chinese IBS", ISO/IEC 18033-5:2015/Amd 1:2021 §9.4.
--accent       : ASSIGNED CENTRALLY — do not set in this repo
favicon        : ASSIGNED CENTRALLY — do not set in this repo
in scope       : The BN256 parameter set built from GM/T 0044.5 §3.1; H1/H2/KDF over
                 SM3 with annex sub-value KATs; identity key extraction for BOTH
                 master key pairs, showing the inversion and the t1 = 0 branch;
                 sign/verify (Annex A), key exchange with confirmation tags
                 (Annex B), KEM (Annex C) and public key encryption (Annex D); the
                 two-master-key escrow demonstration; reused-r private key
                 recovery, isolated and marked broken; the hid = 0x02/0x03 key-
                 exchange divergence as a live interop exhibit run from one master
                 key; a sourced security-level panel quoting both published
                 post-exTNFS estimates.
non-goals      : No SM4 internals — SM4 appears only if Annex D's block-cipher mode
                 is implemented, as an imported primitive, never dissected. No SM3
                 internals (that is world-hashes). No SM2 (that is sm2-forge). No
                 re-teaching of what a bilinear pairing is (that is pairing-gate) —
                 link, do not restate. No Boneh-Franklin implementation (that is
                 ibe-gate) — the comparison is a link and a diagram, not a second
                 scheme. No claim that SM9 is stronger or weaker than Boneh-Franklin,
                 ECDSA or BLS. No TLS. Not an attack on the curve or the pairing.
                 The reused-r path is never the default.
```

### Repo description (house style)

> Browser-based SM9 lab — China's identity-based standard, where a private key is
> an inversion in the exponent rather than a hashed point, with two master key
> pairs in mirrored groups, the standard's own annex worked examples as
> known-answer tests, and one published key-exchange vector that the standard and
> the reference implementations do not agree on.

**Check every non-goal against the acts below before building.** A non-goal that
the UI quietly violates is worse than one never written: "no SM4 internals" holds
only while SM4 stays an imported call with no state display, and "no
Boneh-Franklin implementation" holds only while §1.4 Pane 2's comparison stays a
rendered diagram of two formulae rather than a second running scheme.

---

## §1.1 SCOPE

Five panes, left to right, each gated on the one before. The thesis is carried by
Pane 2; every other pane exists to make Pane 2 legible or to test it.

1. **PARAMETERS AND THE SM3 LAYER** — build the BN256 curve from the standard's
   own constants, then reproduce H1, H2 and the KDF against annex sub-values
   **using SM3 alone, with no pairing code running**. This is the cheapest honest
   first test in the lab and it must pass before any pane to its right renders a
   result.
2. **EXTRACTION — THE INVERSION** (headline) — `t1 = H1(ID‖hid, N) + ks`, the
   `t1 = 0` re-key branch, `t2 = ks·t1⁻¹`, `ds_A = [t2]P1`. Beside it, as a
   **rendered diagram and not a running scheme**, Boneh-Franklin's `d_ID = s·H1(ID)`
   with a link to `crypto-lab-ibe-gate`.
3. **THE THREE PROTOCOLS** — sign/verify, key exchange with confirmation tags, and
   KEM/encryption, each run against its Part 5 annex vector.
4. **WHAT THE KGC CAN DO** — escrow, as two distinct powers.
5. **THE BREAK, AND THE DIVERGENCE** — reused-`r` key recovery, and the
   `hid = 0x02` / `0x03` split between the standard's annex and the major
   implementations.

---

## §1.2 SECURITY / CORRECTNESS INVARIANTS (these beat features on conflict)

INV-1  **Annex agreement for all three algorithms.** Sign/verify reproduces
       GM/T 0044.5 Annex A byte-for-byte with the annex's pinned `r`, so signing is
       deterministic and *reproducible*, not merely verifiable. Key exchange
       reproduces Annex B — `deA`, `deB`, `RA`, `RB`, `g1`, `g2`, `g3`, `SK` and
       both confirmation tags — with the annex's pinned `rA`, `rB`. KEM reproduces
       Annex C (`C`, `K`); encryption reproduces Annex D. Byte equality is the
       acceptance test.
INV-2  **Port the vectors; do not hand-transcribe them.** Annex B prints the hid
       byte as `02` on two lines inside an otherwise-`0x03` example, and prints the
       `SK_B` derivation omitting `ID_B` while `SK_A` includes it — yet both print
       the same `SK`. Transcribing those lines literally will not reproduce `RA`.
       The normative steps (GM/T 0044.3 §6.1 A7/B5) are what the code must follow.
       *Both anomalies were established by recomputing H1 independently: the
       digests printed beside the `02` lines are the `0x03` digests, and
       `H1("Bob"‖0x02)` appears nowhere in the document.*
INV-3  **An independent cross-check that shares no code path with the runtime.**
       The oracle is `gmssl-node` (Apache-2.0, GmSSL's C implementation through
       N-API) run in a **Node-only CI step** — not in the browser bundle, and not a
       second JavaScript implementation, because a second JS implementation is not
       guaranteed to share no code path. `emmansun/gmsm` (Go, MIT) is the
       machine-readable KAT source to port from: `KATSignSample`,
       `KATKeyExchangeSample`, `KATWrapKeySample` and `KATEncryptSample` replay the
       worked examples with fixed nonces. Port expected values; import neither at
       runtime. **Three cautions:** `gmsm`'s KAT comment miscites GB/T 32918, which
       is the SM2 standard, and must not be inherited; `gmsm/internal/sm9/bn256` is
       BSD-3-Clause inside an MIT repository; and `gmssl-node` exposes no key
       exchange, so Annex B needs a different second route — `gmsm`'s ported
       vectors, or the GmSSL CLI's `sm9exch`. Note which route checked which act.
INV-4  **A multi-block H1 vector that the standard does not supply.** Every H1
       input in the whole standard is an identity plus one `hid` byte — 4 to 6
       bytes, an 11-byte SM3 call at most, which never exercises the compression
       loop. Generate an identity of at least 60 bytes so H1's input crosses one
       64-byte SM3 block, pin the result, and cross-check it against a second
       implementation. H2 and the KDF are already multi-block in the annexes (H2's
       Annex A input is 404 bytes; the KDF inputs are 451, 451 and 1288 bytes) —
       H1 is the one that must be generated, and it must not be skipped because
       the annexes look complete.
INV-5  **The `hid` divergence is executed, never asserted.** The page runs Annex
       B's key exchange at `hid = 0x03` and reaches the standard's `SK`, runs the
       same exchange at `hid = 0x02` and reaches the implementations' `SK`, and
       names which published source each result agrees with. Neither is labelled
       "wrong" — they are labelled by their source, the way `sm2-forge` labels its
       two ciphertext byte orders rather than ranking them.
INV-6  **The `t1 = 0` branch is reachable and shown.** The standard requires the
       KGC to regenerate the master key and re-issue *every* user key. The page
       must be able to drive that branch and must say what it costs. A branch that
       cannot be reached is dead code and should be reported as such rather than
       described.
INV-7  **Reused-`r` recovery returns a POINT.** Two signatures over different
       messages under one `r` give `S1 - S2 = [h2 - h1]ds_A`, so
       `ds_A = [(h2 - h1)⁻¹ mod N](S1 - S2)`; the `r` cancels and no scalar is
       recovered. The recovered key must then forge a signature on a fresh message
       that the page's own real verifier accepts. Where `h1 = h2` there are not two
       independent equations — say so rather than showing a bogus key. *This
       algebra was derived from GM/T 0044.2 §6.1 A5-A6 and checked numerically in a
       stand-in prime-order group before entering this brief.*
INV-8  **The vulnerable path is isolated**, never the default, and visibly marked
       broken (§1 isolation rule). It lives in its own module.
INV-9  **MUTATION GATE (§4.1c).** Perturbing any curve parameter, the extraction
       inversion, the H1/H2 leading byte, the KDF counter, or the recovery
       arithmetic must make the owning invariant FAIL in CI. Per §4.1c the build
       must still succeed and the bundle hash must change, or the mutation proves
       nothing.
INV-10 **Every negative claim carries a §4.1d fixture** — a reachable state where
       every rendered verdict reports success and the named property is violated
       anyway. See §1.5.

---

## §1.3 ARCHITECTURE

### Implementation path — settled, with the reasoning kept

**There is no vetted JS/TS SM9 to depend on.** Verify this before accepting it:
query the npm registry directly rather than trusting this paragraph. As read on
2026-09-29, `@li0ard/sm9` returns 404 (while `@li0ard/sm2` and `@li0ard/sm3`,
already used by `sm2-forge`, return 200), and a registry search for `sm9` surfaces
only two candidates:

- `gmssl-node` (Apache-2.0) — a native N-API addon requiring the GmSSL C library
  installed. **Cannot run in a browser**, and exposes no key exchange.
- `@lryncloud/crypto` (Apache-2.0, one version, no repository) — **not SM9, and it
  must be named in the README as a thing not to use.** Its G1/G2 elements are bare
  scalars, its "pairing" multiplies two scalars mod `n`, GT is a single integer,
  and its signature is `s = d·h mod n` — while pinning the genuine SM9 `q`, `n`,
  `P1` and `hid` bytes so the parameter file looks authentic. A lab about
  identity-based cryptography that does not flag this is leaving the trap set.
  **Consider an act for it** (scope it deliberately rather than letting it grow):
  showing `e(P,Q) = g^(sP·sQ)` collapsing into integer multiplication is the
  concrete answer to *"why doesn't a library just do this?"*, and it is the same
  lesson `crypto-lab-hqc-timing` exists to make — a card can be true while the
  cryptography underneath it is not. **Verify the package's current contents
  before describing them**; a later version could change what is true here.

**`@noble/curves` cannot be bent to this curve, and the reason is not parameters.**
Its `abstract/tower.js` `tower12()` hardcodes `u² = -1`, which cannot define Fp2
over SM9's prime at all: `p ≡ 1 mod 4` there, so `-1` is a quadratic residue and
the extension degenerates. SM9 needs `u² = -2`. Its `bn254` is Ethereum's
alt_bn128 — different seed, `b = 3`, D-type twist, the 6x+2 optimal-ate loop and a
1-2-6-12 tower. `mcl-wasm`'s `BN_P256` is TCG's curve, not SM9's, and is
deprecated. **This is a "write a pairing", not a "supply parameters", and the
brief says so rather than discovering it in week two.**

**Recommended path: hand-roll the protocol layer over a vetted pairing substrate.**
Start from `guanzhi/GmSSL-JS` `js/sm9.js` (Apache-2.0, by the GmSSL author) — it
carries the Fp/Fp2/Fp4/Fp12 tower, G1 and twist-G2 arithmetic, the R-ate Miller
loop and the final exponentiation, and self-checks at load against the same Fp12
pairing constant GmSSL's C tests pin. It contains **no protocol layer at all** —
H1/H2, the KDF, hid-separated extraction, sign/verify, key exchange and
encryption/KEM are all absent — which is exactly the surface this lab exists to
teach. The pairing becomes vetted-ish substrate rather than lab homework, and
every line the lab writes is a line a visitor is meant to read.

**Compiling GmSSL to WebAssembly is rejected for the runtime**, and kept as a
recorded decision rather than left to be rediscovered: no such build exists — the
one GmSSL-wasm project on GitHub commits no binary and exposes only SM2, GmSSL's
own CMake has no Emscripten awareness, and the SM9 precompute tables alone are a
148 KiB static floor before any code. GmSSL stays the **oracle** (INV-3), reached
through `gmssl-node` in CI, not the runtime.

**Tradeoffs of vendoring, stated plainly.** It means owning an unmaintained 2022
file carrying one test. Against that: it is 1,580 readable lines, it already
reproduces the standard's own Annex A pairing value, and §4.1c mutation discipline
can cover the arithmetic that matters. It also covers only the field/group/pairing
layer — the protocol layer is genuinely new code and is most of the build.

**Verify before committing to it**, because the recommendation rests on reading
one file and its pairing path only:
- Confirm `js/sm9.js` implements SM9's own BN curve and the 1-2-4-12 tower rather
  than a generic BN254, and confirm the Apache-2.0 header. **Preserve attribution**
  in the vendored copy.
- Confirm the load-time self-check actually runs rather than being dead code.
- **Its point and twist-point arithmetic has NOT been checked against GmSSL C's
  own `hex_point_*` / `hex_tpoint_*` vectors** — only insofar as one pairing KAT
  happens to touch it, which leaves `fp12_inv`, `fp12_pow`, `twist_point_add_full`
  and the hard part of the final exponentiation largely unexercised. Those vectors
  sit in GmSSL's `tests/sm9test.c`. **Make this the first build step**; it is cheap
  and it is the difference between a vetted substrate and an assumed one.
If any of those fails, the fallback is writing the tower and Miller loop against
GM/T 0044.5 §3.2 directly — cost that before choosing, do not drift into it.

### Cost — estimated, and labelled as estimated

- **Pairing time — budget from Firefox, not Chromium.** Measured on the GmSSL-JS
  engine: roughly **4-5 ms per pairing in Chromium and 18-22 ms in Firefox**, about
  a 4x spread. Verification is two pairings and is comfortable everywhere; key
  exchange is several and needs a Web Worker or an explicit *computing* state on
  the slower engine. A separate **proxy** figure, recorded so it is not mistaken
  for SM9's: `@noble/curves` 2.3.0 `bn254.pairing()` ran median 5.91 ms / p95
  7.07 ms (n = 50, warmed, Node 26, Apple silicon) — a different BN curve of the
  same size class, not this one. **Re-measure in-browser on the chosen build
  before any figure reaches the page**, per the repo's rule that a figure which
  cannot be derived is recorded as not derived rather than inherited.
- **Bundle.** `GmSSL-JS` `js/sm9.js` is ~1,580 lines, about **6.4 KB gzipped over
  the source file**. That is gzip over source, **not a Vite production build** —
  minification and tree-shaking will move it. Measure the real bundle with
  `vite build` and publish that number instead as soon as one exists. For contrast,
  the `@noble/curves` modules a generic path would have pulled are ~166 KB
  unminified. **Do not publish any WASM size figure**: no GmSSL WebAssembly build
  exists to measure.
- If the pairing cost makes the page janky, run derivation in a **Web Worker** and
  render per-act pending states — a result that has not been computed shows
  *computing*, never a placeholder value.

### Modules

Small and separately testable, with the inspectable crypto out of the UI layer:

```
src/sm9/params.ts     BN256 constants read from GM/T 0044.5 §3.1, frozen
src/sm9/field.ts      the 1-2-4-12 tower, or the adapter onto the chosen substrate
src/sm9/pairing.ts    R-ate; eid = 0x04
src/sm9/hash.ts       H1, H2, KDF over SM3
src/sm9/extract.ts    both master key pairs; the t1 = 0 branch
src/sm9/sign.ts       sign / verify
src/sm9/exchange.ts   key exchange + confirmation tags
src/sm9/encrypt.ts    KEM + public key encryption
src/sm9/fixtures.ts   Annex A-D vectors, ported
src/attack/nonce-reuse.ts   ISOLATED, never imported by a default path
src/ui/
```

---

## §1.4 UI

**PANE 1 — Parameters and the SM3 layer**

Show the BN256 parameters loaded from the standard, with `cid = 0x12` and
`eid = 0x04` decoded into words rather than left as bytes. Then a "run the SM3
layer" control that reproduces H1, H2 and the KDF against the annex sub-values
**with no pairing running**, and reports pass/fail per value. Plain-language
on-ramp above the first hex: what identity-based cryptography promises, and what a
KGC is.

**PANE 2 — Extraction, the inversion (HEADLINE)**

One identity field. Show the extraction assembling term by term:
`H1(ID‖hid, N)` → `+ ks` → `t1` → `t1⁻¹` → `·ks` → `[t2]P1`. Beside it, as a
**static rendered diagram**, Boneh-Franklin's `d_ID = s·H1(ID)`, with the two
differences called out: SM9 hashes the identity to a **scalar** and inverts;
Boneh-Franklin hashes it to a **curve point** and multiplies. Link to
`crypto-lab-ibe-gate` for the running Boneh-Franklin scheme.

A `hid` selector, and a master-key-pair selector (signature / encryption). Changing
either changes the extracted key on screen. **Show that the two sides live in
mirrored groups** — signature keys in G1 under a G2 master public key, encryption
keys in G2 under a G1 master public key. A control that drives the `t1 = 0` branch,
with what it costs stated on the panel: the KGC re-keys and every issued user key
is re-issued.

**PANE 3 — The three protocols**

Three collapsible acts, each with its annex vector beside its live result and a
byte-equality badge:

- **Sign / verify** (Annex A, `hid = 0x01`). The equation
  `h = H2(M ‖ g^r, N)`, `l = (r - h) mod N`, `S = [l]ds_A` in a `<details>`
  disclosure. Signing with the annex's pinned `r` is byte-reproducible; a
  "use a fresh random r" toggle shows the signature changing while verification
  still holds.
- **Key exchange** (Annex B, `hid = 0x03`). Both sides side by side. **Show that
  `g1` and `g2` swap roles between A and B** — that asymmetry is the part a reader
  gets wrong. Confirmation tags `S_A`, `S_B` rendered and checked.
- **KEM and encryption** (Annexes C and D). If Annex D's block-cipher mode is
  built, SM4 is an imported call with no internal state shown.

**PANE 4 — What the KGC can do**

Escrow as **two separate powers**, which is the thing `ibe-gate` structurally
cannot show because it has no signature scheme:

- with `ke`, the KGC derives any identity's decryption key and **reads** the
  message;
- with `ks`, the KGC derives any identity's signing key and **signs as that
  identity** — producing a signature the page's own real verifier accepts.

Both run live against derived keys, printing what the derived key actually
produced, never echoing the input. The panel states plainly that this is not a
flaw in SM9 but the design: the same two lines of §5.3 that define extraction
define the escrow.

**PANE 5 — The break, and the divergence**

- **Break-it-yourself.** Reuse one `r` across two messages; the page's real
  verifier accepts both signatures first; then recover `ds_A` and forge on a third
  message. **State what was recovered**: a point in G1, the private key itself —
  and **no scalar**. Put `sm2-forge` beside it, where the same mistake yields a
  scalar `d` (`src/attack/nonce-reuse.ts`), and name the reason: the SM9 private
  key *is* a group element, so there is nothing to solve for.
- **The divergence.** Run Annex B at `hid = 0x03` and at `hid = 0x02`, reaching two
  different session keys, and name which published source each agrees with — the
  committee's English Annex B on one side, GmSSL / `emmansun/gmsm` / Bouncy Castle
  on the other. **Verify the Bouncy Castle claim before it ships** — it reached
  this brief second-hand and was not read in its source. Show the two misprinted
  lines and the recomputed H1 digests that identify them as misprints.
  **Label by source, never by correctness — and do not claim the misprint caused
  the divergence.** That the `02` lines in Annex B are typos is established: the
  digests printed beside them are the `0x03` digests. That they are *why* GmSSL
  chose `0x02` is an inference nobody has confirmed, and GmSSL documents no
  reason. A right conclusion reached down a wrong causal chain is a failure here,
  not a rounding error.

**HERO — three text roles, each saying something different**

```
subtitle    : GM/T 0044 · GB/T 38635 · ISO/IEC 14888-3 · ISO/IEC 18033-5
description : SM9 identity key extraction, signature, key exchange and encryption,
              run against the standard's own worked examples.
why it matters: An identity-based key can be built by inverting instead of hashing
              to a curve — and the choice decides how many master keys the
              authority holds, and therefore how many different things it can do
              to you.
```

Stacks below 640px. Mount at `#app`; `:root` defines `--accent` (value assigned
centrally).

---

## §1.5 VISUAL SEMANTICS

Colour tracks **system integrity**, never the raw return value, and state is never
conveyed by colour alone — icon + text + colour throughout (WCAG 1.4.1), verified
in grayscale and under deuteranopia.

```
green        annex vector matched byte-for-byte; verifier accepted; round-trip held
red, sticky  KAT mismatch, verify rejected, or confirmation tag mismatch —
             persists so the visitor can find the exact failing value
ALARM        a forged-but-accepted signature in Pane 5, and the KGC signing as
             another identity in Pane 4. Both are cryptographically correct
             successes and both must read as alarm, not as green.
neutral+named the two hid results in Pane 5 — each labelled by its source. Neither
             is red. A divergence is not a failure.
pending      a value still computing. Never a placeholder number.
```

Never draw an identity flowing into a key that then verifies under a different
identity. No decorative motion.

**§4.1d negative claims — each needs a reachable fixture where every rendered
verdict is green and the property is violated anyway.** At least these:

1. *SM9 signature verification proves the KGC issued a key for that identity — it
   does not prove the identity's owner consented, or even exists.* Fixture: Pane 4
   signing as an identity that never requested a key, with every verdict green.
2. *Reaching the same session key proves both sides used the same `hid`, not that
   either followed the standard.* Fixture: both sides at `0x02`, exchange succeeds,
   confirmation tags match, and the result disagrees with the standard's annex.
3. *An annex KAT passing proves agreement with one published vector — not that the
   implementation is constant-time, nor that the curve is sound.*

Per §4.1c each must bite: delete the negative-claim text and assertion 3 fails;
break a check inside the fixture and assertion 2 fails.

---

## §1.6 EDGE CASES

Each teaches via a tooltip; each fails closed and names the cause.

- `t1 = 0` in extraction — the standard's own re-key branch. Reachable, shown, and
  costed (INV-6).
- `l = 0` in signing — restart, per GM/T 0044.2 §6.1; never emit the signature.
- `K = 0` from the KEM's KDF — restart, per GM/T 0044.4 §6.1.1; never encapsulate.
- `h1 = h2` in reused-`r` recovery — not two independent equations. Say so; do not
  render a bogus key.
- Identity longer than one SM3 block — must work, and is the INV-4 case the
  standard never exercises.
- Empty identity string, and an identity containing non-ASCII bytes — define the
  encoding on screen rather than leaving it implicit.
- A point not on the curve, or not in the correct subgroup, fed to verify or
  decrypt — validate and fail closed with the cause named, not a thrown error.
- Signature `h` outside `[1, N-1]` — reject at parse.
- Mismatched `hid` between extraction and verification — the natural failure, and
  the one that makes Pane 5's divergence legible.

---

## §1.7 EXTENSION SEAMS

Mark each with `// [extension] point`. Do not build them.

- SM9's second encryption mode, if only one of Annex D's two is built first.
- A `crypto-lab-ibe-gate` side-by-side running both extractions in one page — the
  natural successor once both labs exist, and deliberately not this lab.
- SM4 as a dissected primitive, if a lab for it is ever built.
- The ISO/IEC 18033-5 DEM2/DEM3 composition around the SM9 KEM.

---

## VERIFY BEFORE WRITING COPY — do not assert, grep

- **Do not state a count, an ordinal, or a "first/only" claim about the catalog in
  any revision.** If a claim of that shape seems warranted, write the check that
  would establish it instead, and leave the result to whoever runs it.
- Re-run the exponent-inversion sweep above before any copy implies novelty, and
  expect the two known non-IBE hits.
- Grep the catalog for existing SM9 / ShangMi / GM-standard / IBE / pairing
  coverage and report the overlaps before any comparative phrasing ships.
- Grep for `crypto-lab-sm9-*` name collisions before creating anything further.
- Read the BN256 parameters out of GM/T 0044.5 §3.1 and cross-check them against
  an independent implementation. Do not paste them from this brief — **this brief
  is not a primary source**, and a value that entered it by transcription would
  propagate silently.
- Confirm in-body naming before writing that ISO calls this SM9: clause 7.4 of
  ISO/IEC 14888-3:2018 is titled **"Chinese IBS"**, and the publicly readable
  preview front matter never uses the string "SM9". The body is paywalled.
- The gmbz.org.cn cover pages read *"Issued on 2012-03-21 / Translated on
  2024-10-30"*, which conflicts with the 2016 designation in `GM/T 0044-2016`.
  **Do not print an issue date** until a primary source for it is found.
- **PROVENANCE GAP, recorded rather than smoothed over.** Parts 2, 3 and 4 were
  fetched directly from gmbz.org.cn (that host refuses HTTPS; plain HTTP works).
  **Parts 1 and 5 were not** — their content was checked against their own title
  pages, forewords and normative references and every numeric parameter in Part 5
  was independently re-derived, but the download URL could not be confirmed
  because the committee's listing is JavaScript-driven. **Every BN256 parameter in
  this brief therefore rests on a file whose content was checked and whose
  provenance was not.** Fetch Part 5 from the committee site yourself and diff it
  before those constants enter `src/sm9/params.ts`.
- **`GB/T 41389-2022` has not been opened by anyone on this brief.** Do not let its
  contents become a CI assertion or README copy on the strength of a third party's
  description of it.

---

## CI GATES (existing mechanisms — reference them, do not reinvent)

- `e2e/claims.spec.ts` — §4.1b cross-checks and independent re-derivations (the
  lab's own result vs the ported annex vector vs the independent cross-check of
  INV-3), plus the §4.1d negative-claim fixtures above.
- §4.1c mutation discipline. **Every rendered verdict gets a mutation**: each annex
  KAT badge, each verify verdict, each confirmation-tag check, the recovery result,
  the escrow panels, and both `hid` results in Pane 5. Commit the real work before
  mutating; one mutation at a time, restored immediately.
- §4 axe/WCAG 2.1 AA gate on the production build, blocking the deploy.
- §5 README sections. §6.1/§6.2 Dependabot grouping, auto-merge on the same gate
  the deploy runs, and the deploy dispatch.
- §4.1d explicitly names `CLAIMS.yaml`, `THREAT-MODEL.md` and a second-language
  verifier as things **not** to build. Do not build them here. The claims suite is
  the enforceable home.

---

## CITATIONS (verify each against the primary source before it ships)

- **GM/T 0044-2016**, 《SM9标识密码算法》, five parts: .1 General, .2 Digital
  Signature Algorithm, .3 Key Exchange Protocol, .4 Key Encapsulation Mechanism and
  Public Key Encryption Algorithm, .5 Parameter Definition. Official English texts
  on gmbz.org.cn. **Annexes A-D of Part 5** carry the worked examples.
- **GB/T 38635-2020**, 信息安全技术 SM9标识密码算法, **two** parts (.1 General,
  .2 Algorithms), issued 2020-04-28, effective 2020-11-01. It does not supersede
  GM/T 0044-2016; both are in force in different standards systems, with the five
  GM/T parts folded into two GB/T parts.
- **ISO/IEC 14888-3:2018** (Fourth edition, 2018-11), clause 7.4 **"Chinese IBS"**.
  Arrived in the edition itself, not by a published amendment.
- **ISO/IEC 18033-5:2015/Amd 1:2021**, *"Amendment 1: SM9 mechanism"*, clause 9.4
  "The SM9 key encapsulation mechanism".
- **GM/T 0004 / GB/T 32905**, SM3 — the hash under H1, H2 and the KDF.
- A. Menezes, P. Sarkar, S. Singh, *"Challenges with Assessing the Impact of NFS
  Advances on the Security of Pairing-based Cryptography"*, IACR ePrint 2016/1102,
  Remark 6 — the 110-bit conservative estimate.
- R. Barbulescu, S. Duquesne, *"Updating Key Size Estimations for Pairings"* — the
  100-bit estimate, and the argument that the former is not precise enough.
- Z. Cheng, *"The SM9 Cryptographic Schemes"*, IACR ePrint 2017/117 — an
  independent technical description; agrees with the standard on `hid = 1` for
  signature and `hid = 3` for both key agreement and encryption.
- `guanzhi/GmSSL-JS` `js/sm9.js` (Apache-2.0) — candidate pairing substrate.
- `guanzhi/GmSSL` (Apache-2.0) and `emmansun/gmsm` (Go, MIT; `internal/sm9/bn256`
  BSD-3-Clause) — independent cross-checks, not runtime dependencies.
