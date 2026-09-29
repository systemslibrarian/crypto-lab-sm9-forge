# SM9 Forge: what would make this a 10/10 demo

Reviewed on 2026-09-29 against commit `a6579eb` plus the current working-tree changes.

## Verdict

**Current demo score: 8.5/10.**

The cryptography, evidence, and accessibility are already at or near 10/10. The remaining gap is the product experience: the app reads like an exceptionally rigorous audit report placed on one long web page, rather than a guided demonstration that makes its central idea inevitable within the first minute.

The highest-leverage direction is simple:

> Do not add more cryptography. Turn the existing evidence into a short guided path, and keep the full audit trail behind progressive disclosure.

## Scorecard

| Area | Score | Why |
| --- | ---: | --- |
| Cryptographic correctness | 10/10 | Real SM9 operations, annex KATs, strict failure paths, and an isolated real nonce-reuse attack. |
| Evidence and testing | 9.5/10 | 419 unit tests, 26 oracle checks, 28 rendered-claim checks, mutation discipline, and unusually honest negative controls. The shared Playwright port is a real reliability defect. |
| Teaching honesty | 10/10 | The page distinguishes success, failure, alarm, and interoperability divergence correctly. It states what round trips do not prove. |
| Narrative and interaction | 7/10 | The headline mechanism is buried, auto-completed, and separated from its most important consequence by thousands of pixels. |
| Progressive disclosure | 7/10 | Some large values are folded, but most parameters, prose, and evidence render before the learner has a reason to inspect them. |
| Visual and mobile polish | 7.5/10 | Clean and coherent, but mobile has a large hero gap, tiny scaled SVG labels, and a 16,601 px default page. |
| Accessibility | 10/10 | The production build passes the custom WCAG gate across driven desktop and mobile states. |
| Ship readiness | 8/10 | Build and gates pass when served, but cold Playwright startup collides on port 4173 and the repo has no `LICENSE`. |

## What is already exceptional

Keep these intact:

1. **The demo computes rather than asserts.** It reproduces Annex A-D values, drives the `t1 = 0` branch, demonstrates silent KEM divergence, and forges through the real verifier.
2. **The page understands visual semantics.** A mathematically valid KGC impersonation is an alarm, not a green success. The `hid` split is information, not an accusation.
3. **The negative controls are real.** The wrong-H1 fixture and deliberately wrong vector prove that a green self-check is not sufficient evidence.
4. **The attack is specific to SM9.** It correctly recovers a G1 point rather than pretending a private scalar exists.
5. **The test suite checks rendered claims.** It compares values the page prints and independently re-derives equations instead of trusting badges.
6. **The caveats in the README are unusually candid.** Single-engine pairing evidence, no constant-time claim, unread sources, and second-hand claims are all named.

## The decisive change: build a guided path

The brief says the five panes are gated left to right, but the app mounts every pane at once in `src/main.ts`, and `src/ui/pane2-extraction.ts` calls `run()` on load. The result is contradictory:

- Pane 1 says `pending - not yet run`.
- Pane 2 already says `ds_A issued`.
- The visitor did not press the button that supposedly performs the headline action.

Make the default experience a five-step guided lab:

1. Show a compact step rail: **SM3 -> Extract -> Protocols -> KGC -> Break**.
2. Expand only the current step. Keep completed steps as a one-line result with a reopen control.
3. Put Pane 1's primer and **Run SM3 checks** action first. Move the parameter dump and vector rows into `Inspect parameters` and `Inspect all vectors` disclosures.
4. Unlock Pane 2 only after the real Pane 1 checks pass, and announce the unlock accessibly.
5. Remove Pane 2's automatic `run()`. The learner must cause the inversion.
6. Add Back/Next navigation and stable anchors so a presenter can jump to an act without scrolling through the audit trail.
7. Offer **Guided** and **Full evidence** views. Guided should be the default; Full evidence preserves the current expert surface.

This would satisfy the original brief and turn the demo from a document into an experience without deleting any rigor.

## Put the whole thesis in one screen

The strongest finding is split between Pane 2 and a nested act in Pane 3. Bring it together as the headline experiment.

Render this symbolic path before any raw hex:

```text
ID || hid -> H1 -> h1
h1 + ks   -> t1
invert    -> t1^-1
ks * t1^-1 -> t2
[t2]P1    -> ds_A
```

Reveal one real computed step at a time when the user presses **Extract the key**. Motion should only mark the operation being performed.

Then add a two-state segmented control:

- **Standard H1**
- **Altered H1**

In the same viewport, show the four facts that make the demo memorable:

1. The altered H1 produces a different private key.
2. `t1 * t2 = ks` still holds under both mappings.
3. A verifier using the same altered map accepts the signature.
4. The pinned annex value fails, and the standard-H1 verifier rejects it.

That is the lab's real aha: a green round trip is weaker evidence than a pinned external value. A visitor should reach it in at most three actions and 90 seconds.

## Reduce default density, not expert depth

Measured before expanding the large result tables:

| Metric | Desktop, 1440 x 900 | Mobile, 390 x 844 |
| --- | ---: | ---: |
| Default document height | 10,497 px | 16,601 px |
| First button position | 2,003 px | 4,081 px |
| Visible page words | about 3,275 | about 3,045 |
| Mounted pane/note sections | 6 | 6 |

The first interaction should be visible in the first viewport on desktop and no later than the second viewport on mobile.

For every act, use three layers:

1. **Result:** one sentence and one status.
2. **Mechanism:** the few symbolic values needed to understand why.
3. **Evidence:** full bytes, annex tables, clauses, and negative cases in disclosures.

Specific reductions:

- Collapse the BN256 constants and identifier table by default.
- After Pane 1 runs, lead with `30/30 real vectors reproduced; negative control correctly mismatched; 0 pairings`, then let experts open the 31-row table.
- Keep the Pane 2 equation flow visible; fold duplicated computed-versus-annex hex after the summary badge.
- Use tabs for Sign, Exchange, and KEM/Encryption so only one protocol act occupies the page at a time.
- Keep Pane 4's two powers side by side on desktop and as two focused acts on mobile.
- In Pane 5, lead with the forged-and-accepted result, then reveal the derivation.

## Fix mobile-specific presentation

The 390 px view has a measured 184 px dead gap between the hero description and the `Why it matters` panel. Reset `.cl-hero-main`'s flex basis to `auto` in the mobile media query.

The two Pane 2 diagrams use 760-780 px SVG view boxes. At phone width their 11-15 px SVG labels scale to roughly 5-7 CSS pixels. Passing contrast does not make that text legible. At narrow widths, either:

- replace each diagram with a stacked semantic HTML flow, or
- keep a readable minimum width and place it in a named, keyboard-focusable horizontal scroller.

Add geometry checks for both issues. The accessibility suite is excellent, but these are visual quality failures rather than axe violations.

## Add navigation and presentation ergonomics

A 10/10 demo should work for a self-directed learner and a live presenter.

- Add a sticky, compact pane rail with completion states and anchors.
- Give each result a `Reset this step` action.
- Preserve no secret material across reloads; progress state can remain in memory.
- Add a single `Reset lab` command near the progress rail.
- Make the current source/annex visible beside each compact result, with the full citation one disclosure away.
- Consider a `Copy run transcript` action that exports inputs, outputs, source labels, and verdicts as JSON. This is useful evidence, not decoration.

## Put evidence limits inside the app

The README carries important limits that the page itself does not surface. Add a concise **Evidence and limits** disclosure near the top or closing note:

- Fp12 pairing agreement currently rests on the standard's printed values and one runtime engine, not two independent pairing engines.
- No constant-time property is claimed or tested.
- `GB/T 41389-2022` has not been read by the authors.
- The ISO clause body has not been independently checked against the domestic standard.
- The Bouncy Castle `hid = 0x02` attribution is second-hand.

For a 10/10 release, verify the Bouncy Castle source directly or remove it from the implementation list. Obtain and read `GB/T 41389-2022`, or continue to state clearly that its convention was not verified. Honest absence is better than inherited certainty.

## Release blockers

### 1. Give Playwright a unique port

`playwright.config.ts` uses the fleet-forbidden default port `4173`. A cold `npm run test:e2e` timed out because `crypto-lab-glass-box` was already serving that port: `/` returned 302 and `/crypto-lab-sm9-forge/` returned 404. The suites passed only after this repo's preview was started manually on that port.

Choose an unused port in the fleet's 4600-4700 range after scanning sibling configs, then update all three locations together:

- `use.baseURL`
- `webServer.command`
- `webServer.url`

Done means both browser commands pass from a cold start while another lab is running on 4173.

### 2. Add the root license

There is no `LICENSE` file. Add the fleet-standard MIT license with the correct copyright holder and year. Without it, this public teaching lab is not actually reusable under an open license.

## Five-minute gold path

A polished live demonstration should need no scrolling hunt:

1. **Run SM3.** Show published vectors passing, the negative control failing as intended, and zero pairings.
2. **Extract Alice.** Step through hash, add, invert, multiply, and point generation.
3. **Alter H1.** Show a different key, unchanged cancellation identity, a green agreeing round trip, and a failed pinned-value check.
4. **Show KGC power.** Derive one user's key and produce one alarming real result.
5. **Reuse the nonce.** Recover the G1 private-key point and forge a third message through the real verifier.
6. **End on interoperability.** Run `hid` 0x02 and 0x03 side by side; show two internally valid session keys without calling either wrong.

The other protocol vectors remain available as evidence, but they do not interrupt this story.

## Acceptance criteria for 10/10

- The first meaningful action is in the first desktop viewport and no later than the second mobile viewport.
- No Pane 2 result exists before Pane 1 succeeds and the user explicitly runs extraction.
- The core wrong-H1 insight is visible in the same screen as the extraction relation.
- A learner can complete the gold path in five minutes without opening a raw 768-character value.
- An expert can reach every current byte, clause, negative case, and caveat within one disclosure from its summary.
- At 390 px, the hero gap is at most 32 px and diagram text is at least 12 CSS pixels or replaced by a stacked layout.
- Changing an upstream input retires dependent results; re-selecting the same value does not.
- `npm test`, `npm run test:oracle`, `npm run build`, `npm run test:e2e`, and `npm run test:a11y` all pass from a cold start.
- Browser gates use a unique committed port and pass while another lab occupies 4173.
- A root MIT `LICENSE` is present.
- Unsupported source attributions are either directly verified or removed.

## Validation performed for this review

- `npm test`: **419/419 unit tests passed**, plus **4/4 CSP guards**.
- `npm run test:oracle`: **26/26 independent checks passed**.
- `npm run build`: passed; production JS was **232.54 kB raw / 71.90 kB gzip**.
- `npm run test:e2e`: **28/28 claims tests passed** against a manually started production preview.
- `npm run test:a11y`: **2/2 viewport suites passed**, each scanning 14 driven states at 1280 px and 380 px.
- Cold automatic Playwright startup: reproducibly timed out because port 4173 was owned by another lab.

## Recommended implementation order

1. Fix the Playwright port and add `LICENSE`.
2. Introduce the guided pane state and remove Pane 2 auto-run.
3. Build the single-screen extraction/wrong-H1 experiment.
4. Collapse audit-heavy material behind progressive disclosure.
5. Add the pane rail, Back/Next, and reset behavior.
6. Fix mobile hero and diagram geometry.
7. Surface evidence limits and close unsupported source claims.
8. Re-run every existing gate and add interaction/geometry tests for the new flow.

Do not add another primitive, pairing tutorial, benchmark panel, decorative animation, backend, or production-security claim. The material is already complete. The 10/10 version is the same lab with much stronger choreography.