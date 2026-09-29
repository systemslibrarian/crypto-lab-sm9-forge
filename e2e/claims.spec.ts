/**
 * THE RENDERED-VERDICT CLAIMS SUITE — template section 4.1b.
 *
 * WHAT THIS FILE IS ALLOWED TO DO, AND WHAT IT IS NOT. Every assertion here
 * either compares TWO VALUES THE PAGE ITSELF PRINTED, or RE-DERIVES a claim
 * from the page's own rendered inputs by a route the source does not take. It
 * does not import a single line of src/, and it hardcodes no expected digest,
 * key or ciphertext.
 *
 * The reason is not style. A test that recomputes the expression the source
 * computes agrees with the source's bugs by construction — it measures nothing
 * and reports a pass. So the arithmetic below is done here, in BigInt, from
 * hex the browser rendered: t1 is re-formed from the h1 and ks on screen, l
 * from the r and h on screen, q and N from the t on screen by the polynomials
 * the page prints beside them, and P1 is put back on y² = x³ + b over F_q.
 * src/sm9/fn.ts is never consulted, so agreeing with it is evidence.
 *
 * INTERNAL CONSISTENCY ALONE IS NOT ENOUGH EITHER — a page can be consistently
 * wrong, which is the exact lesson pane 3's wrong-H1 fixture exists to teach.
 * So the suite mixes three kinds of check and never relies on one:
 *
 *   cross-check      one rendered claim against another rendered value — every
 *                    "+ byte-identical" badge is tested against the two cells
 *                    it sits beside, and every prose figure against the table
 *                    it describes.
 *   re-derivation    the page's raw inputs put through the standard's own
 *                    formulas here, independently of the implementation.
 *   parts-to-whole   C = C1 ‖ C3 ‖ C2; passed + failed = total; published +
 *                    generated = total; the summary's counts against the rows.
 *
 * THE GLYPH CONTRACT IS ASSERTED, NOT ASSUMED. src/ui/dom.ts pairs every status
 * and verdict with a text glyph and a word so that colour never carries state
 * alone (WCAG 1.4.1). `expectStatus` and `expectVerdict` below check the glyph
 * character against the kind class on every state this suite touches, so a
 * refactor that emits a colour with no glyph fails here rather than in an audit.
 */
import { expect, test, type Locator, type Page } from '@playwright/test';

// ---------------------------------------------------------------------------
// reading the page
// ---------------------------------------------------------------------------

type Kind = 'ok' | 'bad' | 'alarm' | 'info' | 'pending';

/** The glyphs src/ui/dom.ts pairs with each kind. Asserted, never assumed. */
const GLYPH: Record<Kind, string> = {
  ok: '+',
  bad: 'x',
  alarm: '!',
  info: 'i',
  pending: '-',
};

const at = (page: Page, testid: string): Locator => page.locator(`[data-testid="${testid}"]`);

/**
 * textContent rather than innerText throughout.
 *
 * Several values this suite compares — the two g1 elements of pane 5, the
 * Fp12 intermediates of pane 3 — are folded behind a `<details>`, and innerText
 * returns an empty string for anything a layout does not display. Reading the
 * text node is what lets a closed disclosure still be checked for equality
 * while `toBeVisible()` stays available for the one claim that is about
 * visibility.
 */
async function text(page: Page, testid: string): Promise<string> {
  const value = await at(page, testid).first().textContent();
  expect(value, `no text rendered at [data-testid="${testid}"]`).not.toBeNull();
  return (value ?? '').trim();
}

/** A rendered hex value as a bigint. The page prints field elements bare. */
const hexToBig = (value: string): bigint => BigInt(`0x${value.trim().replace(/^0x/, '')}`);

async function big(page: Page, testid: string): Promise<bigint> {
  return hexToBig(await text(page, testid));
}

const mod = (value: bigint, m: bigint): bigint => ((value % m) + m) % m;

/**
 * Assert a status pill's kind, its glyph and that it carries a word.
 *
 * The three are checked together on purpose: a pill that kept its colour class
 * and lost its glyph, or kept both and rendered an empty word, would be colour
 * carrying the state on its own.
 */
async function expectStatus(page: Page, testid: string, kind: Kind, word?: RegExp): Promise<string> {
  const pill = at(page, testid).first();
  await expect(pill).toHaveClass(new RegExp(`\\bstatus-${kind}\\b`));
  await expect(pill.locator('.glyph')).toHaveText(GLYPH[kind]);
  const whole = (await pill.textContent()) ?? '';
  const label = whole.slice(GLYPH[kind].length).trim();
  expect(label.length, `status ${testid} rendered a glyph and no word`).toBeGreaterThan(0);
  if (word !== undefined) expect(label).toMatch(word);
  return label;
}

/** The same contract for a verdict block, which nests glyph, text and why. */
async function expectVerdict(page: Page, hostTestid: string, kind: Kind, textMatch?: RegExp): Promise<string> {
  const verdict = at(page, hostTestid).locator('.verdict').first();
  await expect(verdict).toHaveClass(new RegExp(`\\bverdict-${kind}\\b`));
  await expect(verdict.locator('.glyph')).toHaveText(GLYPH[kind]);
  const headline = ((await verdict.locator('.verdict-text').textContent()) ?? '').trim();
  expect(headline.length, `verdict ${hostTestid} rendered no headline`).toBeGreaterThan(0);
  if (textMatch !== undefined) expect(headline).toMatch(textMatch);
  return headline;
}

/**
 * A badge cell is honest when its glyph agrees with the two cells it judges.
 *
 * This is the load-bearing cross-check of the whole suite. Every comparison
 * table on this page prints a computed value, a published value and a badge
 * claiming whether they agree. The badge is a CLAIM about the other two cells,
 * so it is tested against them rather than read as a result — a badge that said
 * "byte-identical" beside two different strings is exactly the failure a
 * screenshot review would miss.
 */
async function expectBadgeAgreesWithCells(
  row: Locator,
  computedIndex: number,
  publishedIndex: number,
  badgeIndex: number,
): Promise<void> {
  const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
  const computed = cells[computedIndex];
  const published = cells[publishedIndex];
  const badge = cells[badgeIndex];
  const saysAgree = badge.startsWith(GLYPH.ok);
  const saysDiffer = badge.startsWith(GLYPH.bad);
  expect(saysAgree !== saysDiffer, `badge "${badge}" carries no +/x glyph`).toBe(true);
  expect(saysAgree, `badge "${badge}" against\n  ${computed}\n  ${published}`).toBe(computed === published);
}

/**
 * Open the lab in the state the value claims below are about.
 *
 * TWO DELIBERATE CHOICES HERE. First, FULL EVIDENCE rather than the guided path:
 * this suite is about what the page CLAIMS, and it needs every exhibit reachable
 * without driving four steps to get to the fifth. The guided sequence is a claim
 * of its own and is tested as one, in its own describe block below. Second, the
 * extraction is PERFORMED rather than assumed — the pane no longer runs on load,
 * which is the whole point of the guided shell, so a suite that still waited for a
 * verdict to appear by itself would be waiting for a bug.
 */
async function openLab(page: Page): Promise<void> {
  await page.goto('./');
  await at(page, 'lab-view-full').check();
  await at(page, 'p2-extract').click();
  await expect(at(page, 'p2-extract-verdict').locator('.verdict-ok')).toHaveCount(1);
  await awaitRelation(page);
}

/**
 * Wait for the staged reveal to finish.
 *
 * The relation's six lines fill one at a time, so a single-shot `textContent`
 * read of an early step can land mid-sequence. The last line carries `is-filled`
 * only once its value has been written, which makes it the honest completion
 * signal — never a timeout.
 */
async function awaitRelation(page: Page): Promise<void> {
  await expect(at(page, 'p2-line-key')).toHaveClass(/is-filled/);
}

/** Several exhibits ship collapsed; a reader opens them by clicking the summary. */
async function openDetails(page: Page, testid: string): Promise<void> {
  const details = at(page, testid);
  if (await details.evaluate((node) => (node as HTMLDetailsElement).open)) return;
  await details.locator('> summary').click();
  await expect(details).toHaveAttribute('open', '');
}

/** Panes 3 and 5 hold their acts in tab sets; a reader selects one by clicking. */
async function openTab(page: Page, id: string): Promise<void> {
  await at(page, `tab-${id}`).click();
  await expect(at(page, `tab-${id}`)).toHaveAttribute('aria-selected', 'true');
}

const WORD_NUMBER: Record<string, number> = {
  one: 1, two: 2, three: 3, four: 4, five: 5, six: 6, seven: 7, eight: 8, nine: 9, ten: 10,
};

/** Pull the first integer out of a rendered string, failing loudly if absent. */
function intIn(source: string, pattern: RegExp): number {
  const found = pattern.exec(source);
  expect(found, `pattern ${pattern} did not match: ${source}`).not.toBeNull();
  return Number((found as RegExpExecArray)[1]);
}

// ---------------------------------------------------------------------------
// PANE 1 — the parameter set, re-derived rather than compared to a constant
// ---------------------------------------------------------------------------

test.describe('pane 1 — the BN256 parameters', () => {
  test('q, N and the trace re-derive from the rendered t by the formulas printed beside them', async ({ page }) => {
    await openLab(page);

    // The only input is t. Everything else on the panel is a claim about it,
    // and the defining polynomials are printed in the page's own row labels:
    //   q = 36t⁴+36t³+24t²+6t+1, N = 36t⁴+36t³+18t²+6t+1, tr(t) = 6t²+1.
    const t = await big(page, 'p1-param-t');
    const q = await big(page, 'p1-param-q');
    const n = await big(page, 'p1-param-n');
    const trace = await big(page, 'p1-param-trace');

    const t2 = t * t;
    const t3 = t2 * t;
    const t4 = t3 * t;
    expect(q).toBe(36n * t4 + 36n * t3 + 24n * t2 + 6n * t + 1n);
    expect(n).toBe(36n * t4 + 36n * t3 + 18n * t2 + 6n * t + 1n);
    expect(trace).toBe(6n * t2 + 1n);

    // Hasse, by a different route than the three polynomials above: the number
    // of points on the curve is q + 1 - tr, and with cofactor 1 that IS N. The
    // page states the cofactor in words, so the words are parsed and used.
    const cofactor = BigInt(intIn(await text(page, 'p1-param-cofactor'), /^(\d+)/));
    expect(cofactor).toBe(1n);
    expect(cofactor * n).toBe(q + 1n - trace);
  });

  test('P1 satisfies the curve equation the page prints, and every coordinate is in F_q', async ({ page }) => {
    await openLab(page);

    const q = await big(page, 'p1-param-q');
    const b = BigInt(intIn(await text(page, 'p1-param-b'), /^(\d+)/));
    const x = await big(page, 'p1-param-p1x');
    const y = await big(page, 'p1-param-p1y');

    // Nothing on the page computes this. y² = x³ + b over F_q is re-derived
    // here from four rendered values, so a transcription slip in any one of
    // them fails this line.
    expect(mod(y * y, q)).toBe(mod(x * x * x + b, q));

    // Both G2 rows print an Fq2 element as "high low"; every component must be
    // a field element, which a mistyped nibble count would break.
    const components = [
      x,
      y,
      ...(await text(page, 'p1-param-p2x')).split(/\s+/).map(hexToBig),
      ...(await text(page, 'p1-param-p2y')).split(/\s+/).map(hexToBig),
    ];
    expect(components).toHaveLength(6);
    for (const component of components) {
      expect(component >= 0n && component < q).toBe(true);
    }
  });
});

// ---------------------------------------------------------------------------
// PANE 1 — the SM3 layer: the summary against its own table
// ---------------------------------------------------------------------------

/** One rendered row of the SM3 vector table, read back as numbers. */
interface VectorRow {
  vector: string;
  fn: string;
  source: string;
  zBytes: number;
  sm3MessageBytes: number;
  blocks: number;
  passed: boolean;
}

async function readVectorRows(page: Page): Promise<VectorRow[]> {
  const rows = await at(page, 'p1-sm3-table').locator('tbody tr').all();
  const parsed: VectorRow[] = [];
  for (const row of rows) {
    const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
    const result = cells[6];
    expect(result.startsWith(GLYPH.ok) || result.startsWith(GLYPH.bad)).toBe(true);
    parsed.push({
      vector: cells[0],
      fn: cells[1],
      source: cells[2],
      zBytes: Number(cells[3]),
      sm3MessageBytes: Number(cells[4]),
      blocks: Number(cells[5]),
      passed: result.startsWith(GLYPH.ok),
    });
  }
  return parsed;
}

/**
 * Run the SM3 layer and return the REAL vector rows.
 *
 * The table also renders a deliberately-wrong negative control, which is excluded
 * here and asserted separately. It exists because every genuine vector passes, and
 * a checker that has only ever been seen agreeing is indistinguishable from one
 * that cannot disagree: a source mutation forcing the comparison true survived the
 * whole suite until this control was added.
 */
async function runSm3(page: Page): Promise<VectorRow[]> {
  await at(page, 'p1-run-sm3').click();
  await expect(at(page, 'p1-sm3-table')).toHaveCount(1);
  const all = await readVectorRows(page);
  const control = all.filter((row) => isControlRow(row));
  expect(control.length, 'the negative control row must be present').toBe(1);
  expect(control[0].passed, 'the negative control MUST be reported as failing').toBe(false);
  return all.filter((row) => !isControlRow(row));
}

function isControlRow(row: VectorRow): boolean {
  return /CONTROL/i.test(row.vector) || /negative control/i.test(row.source);
}

test.describe('pane 1 — the SM3 layer', () => {
  test('the headline counts are the table\'s own rows, and the parts sum to the whole', async ({ page }) => {
    await openLab(page);
    const rows = await runSm3(page);
    expect(rows.length).toBeGreaterThan(0);

    const passed = intIn(await text(page, 'p1-sm3-passed'), /^(\d+) passed/);
    const failed = intIn(await text(page, 'p1-sm3-failed'), /^(\d+) failed/);
    const total = intIn(await text(page, 'p1-sm3-total'), /^(\d+) total/);

    // The headline is a count of rows, so it is checked against the rows.
    expect(total).toBe(rows.length);
    expect(passed).toBe(rows.filter((row) => row.passed).length);
    expect(failed).toBe(rows.filter((row) => !row.passed).length);
    expect(passed + failed).toBe(total);

    // ... and the two provenance counts partition the same rows. The split is
    // re-derived from the Source column rather than from the summary itself.
    const publishedText = await text(page, 'p1-sm3-published');
    const generatedText = await text(page, 'p1-sm3-generated');
    const publishedPass = intIn(publishedText, /^(\d+)\//);
    const publishedTotal = intIn(publishedText, /^\d+\/(\d+)/);
    const generatedPass = intIn(generatedText, /^(\d+)\//);
    const generatedTotal = intIn(generatedText, /^\d+\/(\d+)/);

    const generatedRows = rows.filter((row) => /generated here/.test(row.source));
    const publishedRows = rows.filter((row) => !/generated here/.test(row.source));
    expect(generatedTotal).toBe(generatedRows.length);
    expect(publishedTotal).toBe(publishedRows.length);
    expect(generatedPass).toBe(generatedRows.filter((row) => row.passed).length);
    expect(publishedPass).toBe(publishedRows.filter((row) => row.passed).length);
    expect(publishedTotal + generatedTotal).toBe(total);
    expect(publishedPass + generatedPass).toBe(passed);

    // Every published row cites an annex of the standard by name; a row whose
    // provenance were quietly dropped would land in neither count above.
    for (const row of publishedRows) expect(row.source).toMatch(/GM\/T 0044\.5 Annex [A-D]/);

    await expectStatus(page, 'p1-sm3-status', failed === 0 ? 'ok' : 'bad');
    expect(await text(page, 'p1-sm3-pairings')).toBe('0 pairings');
  });

  test('each row\'s SM3 message length and block count re-derive from its own Z length', async ({ page }) => {
    await openLab(page);
    const rows = await runSm3(page);

    for (const row of rows) {
      // The page's own construction note states the two shapes: H1 and H2 hash
      // one domain byte, then Z, then a four-byte counter; the KDF of GM/T
      // 0044.3 clause 5.4.3 has no domain byte. src/ui/pane1 takes the H1/H2
      // figure from inside hash.ts's returned result — this re-derives it from
      // the Z-bytes column instead, so the two disagree if either is wrong.
      const domainBytes = row.fn === 'KDF' ? 0 : 1;
      expect(row.sm3MessageBytes, `SM3 message length for ${row.vector}`)
        .toBe(domainBytes + row.zBytes + 4);

      // SM3 compresses 64-byte blocks after a 9-byte length-and-padding tail.
      expect(row.blocks, `block count for ${row.vector}`)
        .toBe(Math.ceil((row.sm3MessageBytes + 9) / 64));
    }
  });

  test('the prose about the untested multi-block path matches the table it describes', async ({ page }) => {
    await openLab(page);
    const rows = await runSm3(page);
    const note = await text(page, 'p1-blocks-note');

    // The note is generated from the fixture's inputs; the table is generated
    // from each run. Two code paths, one set of facts — so the sentence is
    // parsed back into numbers and put to the rows it claims to describe.
    const annexH1 = rows.filter((row) => row.fn === 'H1' && !/generated here/.test(row.source));
    const generatedH1 = rows.filter((row) => row.fn === 'H1' && /generated here/.test(row.source));

    const minBytes = intIn(note, /annexes print is (\d+) to \d+ bytes long/);
    const maxBytes = intIn(note, /annexes print is \d+ to (\d+) bytes long/);
    expect(minBytes).toBe(Math.min(...annexH1.map((row) => row.zBytes)));
    expect(maxBytes).toBe(Math.max(...annexH1.map((row) => row.zBytes)));

    const singleBlock = intIn(note, /and (\d+) of those \d+ fit in a single 64-byte SM3 block/);
    const annexTotal = intIn(note, /and \d+ of those (\d+) fit in a single 64-byte SM3 block/);
    expect(annexTotal).toBe(annexH1.length);
    expect(singleBlock).toBe(annexH1.filter((row) => row.blocks === 1).length);

    const generatedCount = intIn(note, /The (\d+) vectors marked "generated here"/);
    const multiBlock = intIn(note, /of which (\d+) span more than one block/);
    expect(generatedCount).toBe(generatedH1.length);
    expect(multiBlock).toBe(generatedH1.filter((row) => row.blocks > 1).length);

    // The claim only means anything if the gap is real: the annex rows must all
    // be single-block and the generated set must actually cross a block.
    expect(singleBlock).toBe(annexTotal);
    expect(multiBlock).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// PANE 2 — the inversion. The lab's headline claim.
// ---------------------------------------------------------------------------

test.describe('pane 2 — extraction and the inversion', () => {
  test('the headline identity t1 · t2 = ks is re-derived from the values on screen', async ({ page }) => {
    await openLab(page);

    const n = await big(page, 'p1-param-n');
    const h1 = await big(page, 'p2-step-h1');
    const master = await big(page, 'p2-step-master');
    const t1 = await big(page, 'p2-step-t1');
    const t1Inverse = await big(page, 'p2-step-t1inv');
    const t2 = await big(page, 'p2-step-t2');

    // Clause 5.3 re-run here in BigInt, from six rendered values and nothing
    // else. src/sm9/fn.ts is not imported, so this is a second opinion rather
    // than a restatement.
    expect(t1).toBe(mod(h1 + master, n));
    expect(mod(t1 * t1Inverse, n)).toBe(1n);
    expect(t2).toBe(mod(master * t1Inverse, n));

    // The headline: the product recovers the master key, which is the fact
    // every other exhibit in this lab rests on.
    expect(mod(t1 * t2, n)).toBe(mod(master, n));

    // And the page's own pill says so, in words, in the row of the decisive
    // experiment that asks exactly this question.
    await expectStatus(page, 'p2-q-cancels', 'info', /it holds for ANY h1/);
    await expectVerdict(page, 'p2-extract-verdict', 'ok', /ds_A issued in G1 for "Alice"/);
  });

  test('every annex badge agrees with the two values printed beside it', async ({ page }) => {
    await openLab(page);

    const rows = await at(page, 'p2-annex-table').locator('tbody tr').all();
    expect(rows.length).toBeGreaterThan(0);
    for (const row of rows) await expectBadgeAgreesWithCells(row, 1, 2, 3);

    // The summary badge is a claim about all of those rows at once, so it is
    // checked against them rather than read.
    const cells = await Promise.all(
      rows.map(async (row) => (await row.locator('td').allTextContents()).map((cell) => cell.trim())),
    );
    const allAgree = cells.every((row) => row[1] === row[2]);
    await expectStatus(page, 'p2-annex-badge', allAgree ? 'ok' : 'bad');

    // The h1 row of that table is the same value the step list prints above it.
    const h1Row = cells.find((row) => row[0].startsWith('h1'));
    expect(h1Row, 'the annex table prints no h1 row').toBeDefined();
    expect((h1Row as string[])[1]).toBe(await text(page, 'p2-step-h1'));
    expect(await text(page, 'p2-annex-source')).toMatch(/GM\/T 0044\.5 Annex A/);
  });

  test('the t1 = 0 branch is reachable, names its outcome, and issues nothing', async ({ page }) => {
    await openLab(page);
    await openDetails(page, 'p2-t1zero-details');
    await at(page, 'p2-force-t1zero').click();
    await expect(at(page, 'p2-rekey-values')).toHaveCount(1);

    const n = await big(page, 'p1-param-n');
    const forced = await big(page, 'p2-rekey-master');
    const h1 = await big(page, 'p2-rekey-h1');
    const t1 = await big(page, 'p2-rekey-t1');

    // The failure path is re-derived, not taken on trust: the forced master key
    // really is -h1, the sum really is zero, and a zero has no inverse — which
    // is the whole content of clause 5.3 step A3.
    expect(mod(h1 + forced, n)).toBe(0n);
    expect(t1).toBe(0n);

    // A value that does not exist is named as absent rather than shown as zero.
    expect(await text(page, 'p2-rekey-t2')).toMatch(/null — there is no inverse/);
    expect(await text(page, 'p2-step-t1inv')).not.toBe(await text(page, 'p2-rekey-t1'));

    const outcome = await text(page, 'p2-rekey-outcome');
    expect(outcome).toBe('MASTER-KEY-REGENERATION-REQUIRED');
    await expectVerdict(page, 'p2-rekey-verdict', 'alarm', new RegExp(outcome));

    // And the page states what the branch costs, in the state that reaches it.
    await expect(at(page, 'p2-rekey-cost')).toBeVisible();
    expect(await text(page, 'p2-rekey-cost')).toMatch(/REGENERATE the master/);
  });
});

// ---------------------------------------------------------------------------
// RETIREMENT, and the no-op guard
// ---------------------------------------------------------------------------

test.describe('retirement of stale verdicts', () => {
  test('changing the identity retires every verdict about the old one', async ({ page }) => {
    await openLab(page);

    // Two verdicts about "Alice": the annex comparison, and the re-key alarm.
    await expectStatus(page, 'p2-annex-badge', 'ok');
    await expect(at(page, 'p2-annex-table')).toHaveCount(1);
    await openDetails(page, 'p2-t1zero-details');
    await at(page, 'p2-force-t1zero').click();
    await expectVerdict(page, 'p2-rekey-verdict', 'alarm');

    const identity = at(page, 'p2-identity');
    await identity.click();
    await page.keyboard.press('ControlOrMeta+a');
    await identity.pressSequentially('Carol');
    await identity.blur();

    // The stale verdicts are GONE, not merely re-coloured. A page that left
    // "every intermediate reproduced" on screen beside a different identity
    // would be publishing a verdict about an input it no longer holds.
    await expect(at(page, 'p2-annex-badge')).toHaveCount(0);
    await expect(at(page, 'p2-annex-table')).toHaveCount(0);
    await expect(at(page, 'p2-rekey-verdict')).toHaveCount(0);
    await expect(at(page, 'p2-rekey-values')).toHaveCount(0);

    // ... and the page says on screen why there is nothing there now, rather
    // than leaving an empty space that reads as "nothing was checked".
    await expect(at(page, 'p2-annex-none')).toBeVisible();
    expect(await text(page, 'p2-annex-none')).toMatch(/Nothing pinned to compare against/);

    // The replacement verdict names the input it belongs to, so it cannot be
    // mistaken for the retired one.
    await expectVerdict(page, 'p2-extract-verdict', 'ok', /for "Carol"/);
    expect(await text(page, 'p2-step-idhid')).not.toMatch(/^416c696365/);
  });

  test('re-typing the same identity does NOT retire a fresh verdict', async ({ page }) => {
    await openLab(page);
    await openDetails(page, 'p2-t1zero-details');
    await at(page, 'p2-force-t1zero').click();
    const headline = await expectVerdict(page, 'p2-rekey-verdict', 'alarm');
    const forcedMaster = await text(page, 'p2-rekey-master');

    // A user who opens the field, selects everything, types the same name and
    // tabs away has changed nothing. Real key events are used rather than
    // fill() or selectOption(), because the guard IS the browser's native
    // change semantics — Playwright's selectOption dispatches `change`
    // unconditionally and would test the harness instead of the page.
    const identity = at(page, 'p2-identity');
    await identity.click();
    await page.keyboard.press('ControlOrMeta+a');
    await identity.pressSequentially('Alice');
    await identity.blur();
    await page.waitForTimeout(300);

    await expect(at(page, 'p2-rekey-verdict')).toHaveCount(1);
    expect(await expectVerdict(page, 'p2-rekey-verdict', 'alarm')).toBe(headline);
    expect(await text(page, 'p2-rekey-master')).toBe(forcedMaster);
    await expect(at(page, 'p2-annex-table')).toHaveCount(1);
    await expect(at(page, 'p2-annex-none')).toHaveCount(0);

    // The guard above proves nothing unless the observable is live. Change the
    // value for real and the same verdict must disappear — otherwise the test
    // would pass just as happily against a page that never retires anything.
    await identity.click();
    await page.keyboard.press('ControlOrMeta+a');
    await identity.pressSequentially('Dave');
    await identity.blur();
    await expect(at(page, 'p2-rekey-verdict')).toHaveCount(0);
    await expect(at(page, 'p2-annex-none')).toBeVisible();
  });
});

// ---------------------------------------------------------------------------
// PANE 3 (a) — signature
// ---------------------------------------------------------------------------

test.describe('pane 3 (a) — sign and verify', () => {
  test('Annex A reproduces, and l = (r − h) mod N re-derives from the rendered values', async ({ page }) => {
    await openLab(page);
    await at(page, 'p3a-run').click();
    await expect(at(page, 'p3a-verify-status')).toHaveCount(1);

    const n = await big(page, 'p1-param-n');
    const r = await big(page, 'p3a-r');
    const h = await big(page, 'p3a-pinned-h');
    const l = await big(page, 'p3a-l');

    // Clause 6.1 step A6, re-derived here from three values on screen.
    expect(l).toBe(mod(r - h, n));
    expect(l).not.toBe(0n);
    expect(h > 0n && h < n).toBe(true);

    // S is the uncompressed encoding 0x04 ‖ x ‖ y, so its length is a fact
    // about the group and not about this run.
    const s = await text(page, 'p3a-pinned-s');
    expect(s.slice(0, 2)).toBe('04');
    expect(s).toHaveLength(2 + 64 + 64);
    expect(await text(page, 'p3a-pinned-h')).toHaveLength(64);

    // Every badge in the pinned table is checked against its own two cells.
    for (const row of await at(page, 'p3a-pinned-table').locator('tbody tr').all()) {
      await expectBadgeAgreesWithCells(row, 1, 2, 3);
    }
    await expectStatus(page, 'p3a-dsa-badge', 'ok', /byte-identical/);
    await expectStatus(page, 'p3a-verify-status', 'ok', /VERIFIED/);
  });

  test('a fresh nonce changes the signature and not the verdict, and differing is marked INFO', async ({ page }) => {
    await openLab(page);
    await at(page, 'p3a-run').click();
    await expect(at(page, 'p3a-verify-status')).toHaveCount(1);
    const pinnedR = await text(page, 'p3a-r');
    const pinnedH = await text(page, 'p3a-pinned-h');
    const pinnedS = await text(page, 'p3a-pinned-s');

    await openDetails(page, 'p3a-fresh-details');
    await at(page, 'p3a-fresh-r').click();
    await expect(at(page, 'p3a-fresh-verify-status')).toHaveCount(1);
    const freshR = await text(page, 'p3a-fresh-r-value');
    const freshH = await text(page, 'p3a-fresh-h');
    const freshS = await text(page, 'p3a-fresh-s');

    // Same key, same message, different nonce: all three values must move.
    expect(freshR).not.toBe(pinnedR);
    expect(freshH).not.toBe(pinnedH);
    expect(freshS).not.toBe(pinnedS);

    // The verdict must NOT move — the verifier recovers w′ from S and h.
    await expectStatus(page, 'p3a-fresh-verify-status', 'ok', /VERIFIED/);

    // Differing from the annex here is the correct outcome, so the page marks
    // it INFO. A green tick would teach that matching a pinned nonce is the
    // thing being checked; a red one would call a correct run a failure.
    await expectStatus(page, 'p3a-fresh-h-badge', 'info', /differs from Annex A, as a fresh nonce must/);
    await expectStatus(page, 'p3a-fresh-s-badge', 'info', /differs from Annex A, as a fresh nonce must/);

    // The pinned run is still on screen beside it, not replaced by it.
    expect(await text(page, 'p3a-pinned-h')).toBe(pinnedH);
  });

  test('every must-reject case names its failure code and clause step, and the prose count matches the table', async ({ page }) => {
    await openLab(page);
    await openDetails(page, 'p3a-negatives-details');
    await at(page, 'p3a-run-negatives').click();
    await expect(at(page, 'p3a-negatives-table')).toHaveCount(1);

    const CODES = ['H-OUT-OF-RANGE', 'S-AT-INFINITY', 'S-NOT-ON-CURVE', 'HASH-MISMATCH'];
    const rows = await at(page, 'p3a-negatives-table').locator('tbody tr').all();
    expect(rows.length).toBeGreaterThan(0);

    const codeToStep = new Map<string, string>();
    for (const row of rows) {
      const cells = (await row.locator('td').allTextContents()).map((cell) => cell.trim());
      const [caseId, , code, step, badge] = cells;

      // A named cause, from the standard's own list — never "failed", never
      // "none — ACCEPTED", and never a blank cell where a cause should be.
      expect(CODES, `case ${caseId} reported "${code}"`).toContain(code);
      expect(step, `case ${caseId} named a code with no clause step`).toMatch(/^S[1-6] — /);
      expect(badge.startsWith(GLYPH.ok)).toBe(true);
      expect(badge).toMatch(/refused/);

      // The same code must always name the same step. A table that mapped one
      // code onto two different steps would be captioning, not reporting.
      const seen = codeToStep.get(code);
      if (seen === undefined) codeToStep.set(code, step);
      else expect(step).toBe(seen);
    }

    const refused = intIn(await text(page, 'p3a-negatives-status'), /all (\d+) refused/);
    expect(refused).toBe(rows.length);
    await expectStatus(page, 'p3a-negatives-status', 'ok');

    // The note below the table says how the cases distribute. That sentence is
    // parsed and put to the table, because a prose figure nobody checks is the
    // kind of number that stays behind when the code moves on.
    const note = await text(page, 'p3a-negatives-note');
    const wordMatch = /(\w+) of the (\w+) reach S6/.exec(note);
    expect(wordMatch, `the note does not state an S6 count: ${note}`).not.toBeNull();
    const claimedS6 = WORD_NUMBER[(wordMatch as RegExpExecArray)[1].toLowerCase()];
    const claimedTotal = WORD_NUMBER[(wordMatch as RegExpExecArray)[2].toLowerCase()];

    const steps = await Promise.all(
      rows.map(async (row) => (await row.locator('td').allTextContents())[3].trim()),
    );
    expect(claimedTotal).toBe(rows.length);
    expect(claimedS6).toBe(steps.filter((step) => step.startsWith('S6')).length);

    // ... and the structural pair it names: exactly one S2 and one S1, the only
    // two refusals reached before any pairing is computed.
    expect(note).toMatch(/\(S2\)/);
    expect(note).toMatch(/\(S1\)/);
    expect(steps.filter((step) => step.startsWith('S2'))).toHaveLength(1);
    expect(steps.filter((step) => step.startsWith('S1'))).toHaveLength(1);
    expect(claimedS6 + 2).toBe(rows.length);
  });
});

// ---------------------------------------------------------------------------
// THE NEGATIVE-CLAIM FIXTURE — template 4.1d. The most important test here.
// ---------------------------------------------------------------------------

test.describe('pane 3 (a) — the wrong-H1 negative-claim fixture', () => {
  test('the round trip is green under a hash that is not SM9\'s, and the limitation is on screen in that state', async ({ page }) => {
    await openLab(page);

    // 1. THE FIXTURE IS REACHED THROUGH THE UI. No flag, no query string, no
    //    test-only hook: the same button a visitor presses.
    await expect(at(page, 'p3a-wrongh1-limitation')).toHaveCount(0);
    await openDetails(page, 'p3a-wrongh1-details');
    await at(page, 'p3a-wrongh1-run').click();
    await expect(at(page, 'p3a-wrongh1-values')).toHaveCount(1);

    // The fixture has to be REAL before "it still verified" means anything:
    // the identity hash, and therefore the issued key, must actually differ.
    expect(await text(page, 'p3a-wrongh1-h1-broken')).not.toBe(await text(page, 'p3a-wrongh1-h1-real'));
    expect(await text(page, 'p3a-wrongh1-dsa')).not.toBe(await text(page, 'p3a-wrongh1-honest-dsa'));

    // 2. EVERYTHING THE ROUND TRIP CAN SEE IS GREEN — asserted against the
    //    RENDERED verdict, not against a flag this test set. The page's own
    //    unmodified verifier accepts a signature under a key extracted with a
    //    hash that is not H1, and says so in the verdict's own words.
    await expectStatus(page, 'p3a-wrongh1-agreeing', 'ok', /^ACCEPTED$/);
    const headline = await expectVerdict(page, 'p3a-wrongh1-verdict', 'alarm', /SIGNATURE ACCEPTED/);
    expect(headline).toMatch(/verify\(\) returned accepted: true/);

    // Every other round-trip verdict on this pane stays green in that state
    // too, which is what makes the fixture worth having: nothing a self-check
    // can reach goes red.
    await at(page, 'p3a-run').click();
    await expectStatus(page, 'p3a-verify-status', 'ok', /VERIFIED/);
    await openDetails(page, 'p3a-negatives-details');
    await at(page, 'p3a-run-negatives').click();
    await expectStatus(page, 'p3a-negatives-status', 'ok', /all \d+ refused/);

    //    The block does render two non-green badges, and they are asserted
    //    rather than glossed: both are checks the round trip does NOT have —
    //    one needs SM9's real H1, the other needs the honest key to compare
    //    against. Claiming "all green" over a block containing a red badge
    //    would be this suite mis-describing the page it is testing, so the
    //    partition is stated exactly: these two, and nothing else.
    const pills = await at(page, 'p3a-wrongh1-values').locator('.status').all();
    const nonGreen: string[] = [];
    for (const pill of pills) {
      const classes = (await pill.getAttribute('class')) ?? '';
      if (!/\bstatus-ok\b/.test(classes)) nonGreen.push((await pill.getAttribute('data-testid')) ?? '?');
    }
    expect(nonGreen.sort()).toEqual(['p3a-wrongh1-keys-differ', 'p3a-wrongh1-realverifier']);
    await expectStatus(page, 'p3a-wrongh1-realverifier', 'bad', /refused at HASH-MISMATCH/);
    await expectStatus(page, 'p3a-wrongh1-keys-differ', 'bad', /DIFFERENT keys/);

    // 3. THE LIMITATION IS ON SCREEN IN THAT STATE. Visible — so not inside a
    //    collapsed disclosure the reader must find — inside the same block as
    //    the verdict it qualifies, and carrying the claim itself rather than a
    //    pointer to a README.
    const limitation = at(page, 'p3a-wrongh1-limitation');
    await expect(limitation).toBeVisible();
    await expect(at(page, 'p3a-wrongh1').locator('[data-testid="p3a-wrongh1-limitation"]')).toHaveCount(1);
    await expect(limitation).toHaveClass(/note-alarm/);

    const stated = await text(page, 'p3a-wrongh1-limitation');
    expect(stated).toMatch(/does NOT prove that H1, the identity encoding, or hid is/);
    expect(stated).toMatch(/H1 CANCELS/);
    expect(stated).toMatch(/provided BOTH sides use the same one/);
    // The SCOPING clause is the part that keeps this claim honest. Without it the
    // sentence reads as "SM9 verification does not check identity", which is false:
    // h1 = H1(ID||hid) really does feed P = [h1]P2 + Ppub-s. Assert the limits are
    // stated in the same breath as the limitation.
    expect(stated).toMatch(/does NOT mean identity goes unchecked/i);
    expect(stated).toMatch(/refused at HASH-MISMATCH/);
    expect(stated).toMatch(/a key for another identity and a key extracted at a different hid/);

    // ... and it names what WOULD catch it, so the limitation is actionable
    // rather than merely admitted.
    expect(await text(page, 'p3a-wrongh1-what-catches')).toMatch(/Only a value somebody else printed/);
  });
});

// ---------------------------------------------------------------------------
// PANE 3 (b) — key exchange
// ---------------------------------------------------------------------------

test.describe('pane 3 (b) — key exchange', () => {
  test('both sides reach one session key, and every annex badge agrees with its cells', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p3b');
    await at(page, 'p3b-run').click();
    await expect(at(page, 'p3b-annex-table')).toHaveCount(1);

    // The two sides run mirrored formulas. The page's agreement badge is a
    // claim about the two SK values it also prints, so it is tested against
    // them rather than read as the answer.
    const skA = await text(page, 'p3b-sk-a');
    const skB = await text(page, 'p3b-sk-b');
    expect(skA).toBe(skB);
    expect(skA).toHaveLength(32);
    await expectStatus(page, 'p3b-agree', 'ok', /SK_A = SK_B/);

    for (const row of await at(page, 'p3b-annex-table').locator('tbody tr').all()) {
      await expectBadgeAgreesWithCells(row, 1, 2, 3);
    }

    // g1, g2 and g3 are computed by different formulas on each side and must
    // still land on the same value; the page prints the formulas, so assert
    // they are in fact different formulas before trusting the equality.
    expect(await text(page, 'p3b-g1-b-formula')).not.toBe(await text(page, 'p3b-g1-a-formula'));
    expect(await text(page, 'p3b-g2-b-formula')).not.toBe(await text(page, 'p3b-g2-a-formula'));
    for (const id of ['p3b-g1-equal', 'p3b-g2-equal', 'p3b-g3-equal']) {
      await expectStatus(page, id, 'ok', /byte-identical/);
    }

    // The two confirmation tags are one construction separated by a leading
    // byte. Same length, different value — if they were equal, B's own tag
    // would verify as A's reply, which is what the note beside them says.
    const tag82 = await text(page, 'p3b-tag82');
    const tag83 = await text(page, 'p3b-tag83');
    expect(tag82).toHaveLength(tag83.length);
    expect(tag82).not.toBe(tag83);
    expect(await text(page, 'p3b-tag-note')).toMatch(/0x82 for B's tag and 0x83 for A's/);

    await expectStatus(page, 'p3b-confirm-bta', 'ok', /confirmed B → A/);
    await expectStatus(page, 'p3b-confirm-atb', 'ok', /confirmed A → B/);
  });
});

// ---------------------------------------------------------------------------
// PANE 3 (c) — the KEM's silence beside public key encryption's named cause
// ---------------------------------------------------------------------------

test.describe('pane 3 (c) — KEM and public key encryption', () => {
  test('the ciphertext is exactly C1 ‖ C3 ‖ C2, and the plaintext is the message the page printed', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p3c');
    await at(page, 'p3c-run-pke').click();
    await expect(at(page, 'p3c-b-values')).toHaveCount(1);

    // The page states the message and its length in bits in one place and the
    // recovered plaintext as hex in another. Decoding the hex HERE, with Node's
    // own UTF-8, is a route the page does not take.
    const inputs = await text(page, 'p3c-pke-inputs');
    const quoted = /message"([^"]+)" \((\d+) bits\)/.exec(inputs);
    expect(quoted, `no message and bit length in: ${inputs}`).not.toBeNull();
    const [, messageAscii, messageBits] = quoted as RegExpExecArray;

    for (const mode of ['a', 'b'] as const) {
      const c1 = await text(page, `p3c-${mode}-c1`);
      const c3 = await text(page, `p3c-${mode}-c3`);
      const c2 = await text(page, `p3c-${mode}-c2`);
      const whole = await text(page, `p3c-${mode}-ciphertext`);

      // Parts sum to whole, in the standard's own order C1 ‖ C3 ‖ C2.
      expect(c1 + c3 + c2, `mode ${mode}: C is not C1 ‖ C3 ‖ C2`).toBe(whole);
      expect(whole).toMatch(/^[0-9a-f]+$/);

      const plaintext = await text(page, `p3c-${mode}-plaintext`);
      expect(Buffer.from(plaintext, 'hex').toString('utf8')).toBe(messageAscii);
      expect(plaintext.length * 4).toBe(Number(messageBits));
      expect(await text(page, `p3c-${mode}-plaintext-text`)).toBe(messageAscii);

      // The plaintext must not be sitting in the ciphertext.
      expect(whole).not.toContain(plaintext);

      await expectStatus(page, `p3c-${mode}-roundtrip`, 'ok', /clause 7\.2\.1 accepted/);
      await expectStatus(page, `p3c-${mode}-badge`, 'ok', /byte-identical/);
    }

    // Mode a is a one-time pad the length of the message, which the page says
    // in its own heading; mode b is SM4-CBC, so its C2 is block-aligned and its
    // padded block starts with the message.
    expect((await text(page, 'p3c-a-c2')).length).toBe((await text(page, 'p3c-a-plaintext')).length);
    const padded = await text(page, 'p3c-b-padded');
    expect(padded.startsWith(await text(page, 'p3c-b-plaintext'))).toBe(true);
    expect(padded.length % 32, 'mode b: M ‖ padding is not a whole number of SM4 blocks').toBe(0);
    expect((await text(page, 'p3c-b-c2')).length).toBe(padded.length);
  });

  test('the KEM diverges silently where public key encryption names a cause', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p3c');
    await at(page, 'p3c-run-kem').click();
    await expect(at(page, 'p3c-kem-wrong')).toHaveCount(1);
    await at(page, 'p3c-run-pke').click();
    await expect(at(page, 'p3c-b-values')).toHaveCount(1);

    // ---- the KEM, handed the wrong private key --------------------------
    const k = await text(page, 'p3c-kem-k');
    const kPrime = await text(page, 'p3c-kem-kprime');
    const wrongK = await text(page, 'p3c-kem-wrong-k');

    // The right key round-trips ...
    expect(kPrime).toBe(k);
    await expectStatus(page, 'p3c-kem-agreed', 'ok', /K = K′/);

    // ... and the wrong key produces a DIFFERENT key of the same shape, with
    // no error anywhere. That is the divergence, and it is silent: the status
    // reports success in words.
    expect(wrongK).not.toBe(k);
    expect(wrongK).toHaveLength(k.length);
    const kemOutcome = await expectStatus(page, 'p3c-kem-wrong-status', 'alarm', /reported SUCCESS/);
    expect(kemOutcome).not.toMatch(/refused/);
    await expectStatus(page, 'p3c-kem-divergence', 'alarm', /a different key, reported as success/);
    await expectStatus(page, 'p3c-kem-integrity', 'alarm', /integrityChecked: false/);
    expect(await text(page, 'p3c-kem-divergence-note')).toMatch(/produced a DIFFERENT key/);

    // ---- public key encryption, handed a tampered ciphertext ------------
    const refusals: string[] = [];
    for (const mode of ['a', 'b'] as const) {
      const tampered = await expectStatus(page, `p3c-${mode}-tampered`, 'ok', /^refused at /);

      // The page names the step and the cause, rather than reporting a bare
      // failure: "refused at B4: MAC_MISMATCH".
      const named = /^refused at (B[1-5]): ([A-Z0-9_]+)$/.exec(tampered);
      expect(named, `mode ${mode} did not name a step and cause: ${tampered}`).not.toBeNull();
      expect((named as RegExpExecArray)[1]).toBe('B4');
      expect((named as RegExpExecArray)[2]).toBe('MAC_MISMATCH');
      refusals.push(tampered);
    }

    // ---- and the two outcomes are asserted as DIFFERENT ------------------
    // One mechanism returns a key and reports success; the other returns no
    // plaintext and names the comparison that refused. The page's own note
    // says that single MAC comparison is the entire difference between them.
    const kemGaveAKey = /^[0-9a-f]+$/.test(wrongK);
    expect(kemGaveAKey).toBe(true);
    expect(refusals).toHaveLength(2);
    for (const refusal of refusals) expect(refusal).not.toBe(kemOutcome);
    expect(await text(page, 'p3c-mac-note')).toMatch(/tamper with a KEM ciphertext and you get a key/);
    expect(await text(page, 'p3c-kem-no-integrity')).toMatch(/no integrity check of any kind/);
  });
});

// ---------------------------------------------------------------------------
// PANE 4 — what the KGC can do. Two alarms, one of them a successful signature.
// ---------------------------------------------------------------------------

test.describe('pane 4 — the KGC\'s two powers', () => {
  test('the recovered plaintext is re-derived from the message field, not echoed from it', async ({ page }) => {
    await openLab(page);

    // A message with a multi-byte character, so the comparison is at the byte
    // level: an echo of the input box would pass a string comparison and fail
    // this one if the page's encoder and Node's disagreed.
    const message = 'Nine at the usual place — bring the €5 note.';
    await at(page, 'p4-message').fill(message);
    await at(page, 'p4-run-read').click();
    await expect(at(page, 'p4-read-values')).toHaveCount(1);

    // The expected hex is computed HERE, from the field's own value, with
    // Node's UTF-8 encoder. Nothing from src/ is involved.
    const expected = Buffer.from(await at(page, 'p4-message').inputValue(), 'utf8').toString('hex');
    const recovered = await text(page, 'p4-read-recovered');
    expect(recovered).toBe(expected);
    expect(await text(page, 'p4-read-recovered-text')).toBe(message);
    await expectStatus(page, 'p4-read-match', 'ok', /byte-identical/);

    // The plaintext is not sitting in the ciphertext, so what came back came
    // out of decrypt() rather than off the wire.
    const ciphertext = await text(page, 'p4-read-ciphertext');
    expect(ciphertext).not.toContain(recovered);
    expect(ciphertext.length).toBeGreaterThan(recovered.length);

    // The KGC's derived key is re-derived here from the same relation pane 2
    // publishes: t1 · t2 = ke. h1 is not printed on this panel, so the check
    // available from these two values is that neither is degenerate and that
    // t2 really is a reduction mod N.
    const n = await big(page, 'p1-param-n');
    const t1 = await big(page, 'p4-read-t1');
    const t2 = await big(page, 'p4-read-t2');
    expect(t1 > 0n && t1 < n).toBe(true);
    expect(t2 > 0n && t2 < n).toBe(true);

    await expectVerdict(page, 'p4-read-verdict', 'alarm', /THE KGC READ THE MESSAGE/);
    expect(await text(page, 'p4-read-not-echo')).toMatch(/came out of/);
  });

  test('the KGC signs as another identity, and that is rendered as an ALARM and not a success', async ({ page }) => {
    await openLab(page);
    await at(page, 'p4-run-sign').click();
    await expect(at(page, 'p4-sign-values')).toHaveCount(1);

    // The signature is cryptographically correct — the page's own verifier
    // accepts it, and the h2 it recomputed equals the signature's h.
    const h = await text(page, 'p4-sign-h');
    const h2 = await text(page, 'p4-sign-h2');
    expect(h2).toBe(h);
    await expectStatus(page, 'p4-sign-h2-match', 'ok', /clause 7\.1 step S6 passes/);
    expect(await text(page, 'p4-sign-s')).toMatch(/^04[0-9a-f]{128}$/);
    expect(await text(page, 'p4-sign-identity')).toBe(await at(page, 'p4-identity').inputValue());

    // ... and correct is exactly what is wrong with it. The acceptance is
    // rendered ALARM, not OK: a green tick here would be the page agreeing
    // with the attacker. Both the pill and the verdict are checked, because
    // the two are rendered by different call sites.
    await expectStatus(page, 'p4-sign-accepted', 'alarm', /ACCEPTED as a signature by this identity/);
    await expectVerdict(page, 'p4-sign-verdict', 'alarm', /THE KGC SIGNED AS THIS IDENTITY/);
    await expect(at(page, 'p4-sign-verdict').locator('.verdict-ok')).toHaveCount(0);
    await expect(at(page, 'p4-sign-verdict').locator('.verdict-bad')).toHaveCount(0);

    // The page says in words why a correct result is the alarming one.
    const why = await text(page, 'p4-sign-not-forgery');
    expect(why).toMatch(/Nothing here is a forgery in the cryptographic sense/);
    expect(why).toMatch(/The signature is genuine/);
    expect(why).toMatch(/no verifier anywhere can tell the difference/);
  });
});

// ---------------------------------------------------------------------------
// PANE 5 (a) — the break
// ---------------------------------------------------------------------------

test.describe('pane 5 (a) — the reused nonce', () => {
  test('the forged signature is accepted, and the acceptance is rendered as an ALARM', async ({ page }) => {
    await openLab(page);
    await at(page, 'p5a-run').click();
    await expect(at(page, 'p5a-forged')).toHaveCount(1);

    // Two genuine signatures under one nonce: both accepted, different h.
    await expectStatus(page, 'p5a-sig1-verify', 'ok', /ACCEPTED/);
    await expectStatus(page, 'p5a-sig2-verify', 'ok', /ACCEPTED/);
    const h1 = await text(page, 'p5a-sig1-h');
    const h2 = await text(page, 'p5a-sig2-h');
    expect(h1).not.toBe(h2);
    await expectStatus(page, 'p5a-same-nonce', 'ok', /this is the mistake/);

    // The recovered key is the key that was issued, and the forged message is
    // a third message neither signature covered.
    await expectStatus(page, 'p5a-recovered-matches', 'ok', /the same point in G1/);
    expect(await text(page, 'p5a-method')).toBe('two-signatures-reused-nonce');
    const forgedH = await text(page, 'p5a-forged-h');
    expect(forgedH).not.toBe(h1);
    expect(forgedH).not.toBe(h2);
    expect(await text(page, 'p5a-forged-s')).toMatch(/^04[0-9a-f]{128}$/);

    // What was recovered is a POINT and there is no scalar, which is the fact
    // that makes this an SM9 exhibit rather than a generic ECDSA one. The
    // recovery is a G1 point, so its two rendered coordinates are field
    // elements — checked against the q this page prints in pane 1.
    const q = await big(page, 'p1-param-q');
    const x = await big(page, 'p5a-recovered-x');
    const y = await big(page, 'p5a-recovered-y');
    expect(x < q && y < q).toBe(true);
    expect(await text(page, 'p5a-no-scalar')).toMatch(/there is none\. The result type has no field for one/);

    // The alarm: a signature the key's owner never made, accepted by the
    // page's own unmodified verifier, and rendered as an alarm rather than a
    // green success.
    await expectStatus(page, 'p5a-forged-accepted', 'alarm', /ACCEPTED as a signature by Alice/);
    await expectVerdict(page, 'p5a-forged-verdict', 'alarm', /FORGED AND ACCEPTED/);
    await expect(at(page, 'p5a-forged-verdict').locator('.verdict-ok')).toHaveCount(0);
  });

  test('the singular system is refused by name, and nothing key-shaped comes back', async ({ page }) => {
    await openLab(page);
    await at(page, 'p5a-refusal-run').click();
    await expect(at(page, 'p5a-refusal-values')).toHaveCount(1);

    // Signing one message twice under one nonce gives one equation twice.
    const h1 = await text(page, 'p5a-refusal-h1');
    const h2 = await text(page, 'p5a-refusal-h2');
    expect(h1).toBe(h2);
    await expectStatus(page, 'p5a-refusal-equal', 'ok', /one equation twice/);

    // The refusal is a NAMED result, and the failure path says which one.
    const reason = await text(page, 'p5a-refusal-reason');
    expect(reason).toBe('IDENTICAL-HASHES-NO-SECOND-EQUATION');
    expect(await text(page, 'p5a-refusal-detail')).toMatch(/has no inverse mod N/);

    // Refusing is the correct behaviour, so the verdict is OK and it names the
    // reason. No recovered key is rendered in this state at all.
    await expectVerdict(page, 'p5a-refusal', 'ok', new RegExp(`REFUSED — ${reason}`));
    await expect(at(page, 'p5a-refusal').locator('[data-testid="p5a-recovered-x"]')).toHaveCount(0);
    await expect(at(page, 'p5a-refusal').locator('.verdict-alarm')).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// PANE 5 (b) — the hid divergence: two keys, neither an error
// ---------------------------------------------------------------------------

test.describe('pane 5 (b) — the hid divergence', () => {
  test('both session keys are rendered, they DIFFER, each is labelled by source, and neither is an error', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p5b');
    await at(page, 'p5b-run').click();
    await expect(at(page, 'p5b-literal-values')).toHaveCount(1);

    // Two conforming runs, two different session keys.
    const sk03 = await text(page, 'p5b-sk-0x03');
    const sk02 = await text(page, 'p5b-sk-0x02');
    expect(sk03).not.toBe(sk02);
    expect(sk03).toHaveLength(sk02.length);

    // Each labelled by the source that declares its hid, and the two sources
    // are distinct kinds of authority — one an informative annex of the
    // standard, one an implementation convention.
    const source03 = await text(page, 'p5b-source-0x03');
    const source02 = await text(page, 'p5b-source-0x02');
    expect(source03.length).toBeGreaterThan(0);
    expect(source02.length).toBeGreaterThan(0);
    expect(source03).not.toBe(source02);
    expect(await text(page, 'p5b-instandard-0x03')).toMatch(/^yes/);
    expect(await text(page, 'p5b-instandard-0x02')).toMatch(/^no/);

    // NEITHER is marked as an error. Both are INFO, both internally agree, and
    // both reproduce the key their own source publishes — which is what makes
    // this an interoperability fact rather than a verdict.
    await expectStatus(page, 'p5b-status-0x03', 'info', /a conforming run under a declared convention/);
    await expectStatus(page, 'p5b-status-0x02', 'info', /a conforming run under a declared convention/);
    for (const hid of ['0x03', '0x02']) {
      await expectStatus(page, `p5b-agree-${hid}`, 'ok', /SK_A = SK_B/);
      await expectStatus(page, `p5b-published-${hid}`, 'ok', /byte-identical/);
      // Nothing anywhere inside either box carries a failure state.
      await expect(at(page, `p5b-box-${hid}`).locator('.status-bad')).toHaveCount(0);
      await expect(at(page, `p5b-box-${hid}`).locator('.status-alarm')).toHaveCount(0);
      await expect(at(page, `p5b-box-${hid}`).locator('.verdict-bad')).toHaveCount(0);
    }
    expect(await text(page, 'p5b-neither-wrong')).toMatch(/Neither of those is wrong, and neither is rendered red/);

    // And the page declines the third claim it has no evidence for.
    expect(await text(page, 'p5b-no-causation')).toMatch(/does not claim the misprint caused/);
  });

  test('the group elements are byte-identical across the two hid values, and only R_A moves', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p5b');
    await at(page, 'p5b-run').click();
    await expect(at(page, 'p5b-g-values')).toHaveCount(1);

    // The deepest claim on the page: hid cancels out of the pairings. Its
    // badge is checked against the two g1 values the page also prints.
    const g103 = await text(page, 'p5b-g1-03');
    const g102 = await text(page, 'p5b-g1-02');
    expect(g103).toBe(g102);
    expect(g103.length).toBeGreaterThan(0);
    await expectStatus(page, 'p5b-g-identical', 'ok', /byte-identical at 0x02 and 0x03/);

    // ... while R_A, the one place hid survives into the KDF input, differs.
    // It is rendered INFO rather than BAD, because it differing is the
    // mechanism of the divergence and not a defect in either run.
    const ra03 = await text(page, 'p5b-ra-03');
    const ra02 = await text(page, 'p5b-ra-02');
    expect(ra03).not.toBe(ra02);
    await expectStatus(page, 'p5b-ra-differ', 'info', /DIFFERENT — and this is the only thing that changes/);
    expect(await text(page, 'p5b-cancellation')).toMatch(/t3 is gone/);
  });

  test('the misprint diagnosis is settled against the annex\'s own printed digest', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p5b');
    await at(page, 'p5b-run').click();
    await expect(at(page, 'p5b-misprint-table')).toHaveCount(1);

    const rows = await at(page, 'p5b-misprint-table').locator('tbody tr').all();
    expect(rows.length).toBeGreaterThan(0);
    expect(rows.length % 2).toBe(0); // one "as printed" and one corrected row per line

    // Column 2 is H1 recomputed here from the bytes in column 1; column 3 is
    // the digest the annex prints beside those bytes. The badge in column 4 is
    // a claim about that pair, so it is checked against the pair.
    for (const row of rows) await expectBadgeAgreesWithCells(row, 2, 3, 4);

    for (const line of ['638-638', '659-659']) {
      const printedBytes = await text(page, `p5b-misprint-${line}-printed`);
      const correctedBytes = await text(page, `p5b-misprint-${line}-corrected`);
      const h1OfPrinted = await text(page, `p5b-misprint-${line}-h1-printed`);
      const h1OfCorrected = await text(page, `p5b-misprint-${line}-h1-corrected`);

      // The two readings differ in exactly the last byte — the hid.
      expect(printedBytes).toHaveLength(correctedBytes.length);
      expect(printedBytes.slice(0, -2)).toBe(correctedBytes.slice(0, -2));
      expect(printedBytes.slice(-2)).not.toBe(correctedBytes.slice(-2));

      // SM3 is not a constant function, so the two readings must give two
      // digests — without that, the diagnosis below would prove nothing.
      expect(h1OfPrinted).not.toBe(h1OfCorrected);

      // The diagnosis: the corrected reading agrees with the annex's own
      // printed digest, the literal one does not.
      await expectStatus(page, `p5b-misprint-${line}-corrected-match`, 'ok', /agree/);
      await expectStatus(page, `p5b-misprint-${line}-printed-match`, 'bad', /DISAGREE/);
    }
  });

  test('the literal reading does not complete, and that is rendered INFO rather than a failure', async ({ page }) => {
    await openLab(page);
    await openTab(page, 'p5b');
    await at(page, 'p5b-run').click();
    await expect(at(page, 'p5b-literal-values')).toHaveCount(1);

    // The third leg of the diagnosis needs no digest: take the misprinted
    // bytes literally, run the protocol, and the two sides disagree.
    const literalA = await text(page, 'p5b-literal-ska');
    const literalB = await text(page, 'p5b-literal-skb');
    expect(literalA).not.toBe(literalB);
    await expectStatus(page, 'p5b-literal-agree', 'bad', /they DISAGREE/);

    // Neither literal key is the one Annex B publishes, which is the argument.
    const published = await text(page, 'p5b-literal-published');
    expect(published).not.toBe(literalA);
    expect(published).not.toBe(literalB);

    // The correct reading DOES reproduce that published key — the same value
    // pane 3 (b) reproduces, cross-checked across two panes of the page.
    expect(await text(page, 'p5b-sk-0x03')).toBe(published);

    // A ruled-out reading is a finding about the annex, not a fault in this
    // lab, so the verdict is INFO and says what it rules out.
    await expectVerdict(page, 'p5b-literal-verdict', 'info', /DOES NOT COMPLETE/);
    await expect(at(page, 'p5b-literal-verdict').locator('.verdict-bad')).toHaveCount(0);
  });
});

// ---------------------------------------------------------------------------
// The closing note — a range with two attributions, and no number of its own
// ---------------------------------------------------------------------------

test('the security level is published as a range, both figures attributed, neither averaged', async ({ page }) => {
  await openLab(page);

  const mss = intIn(await text(page, 'security-mss-figure'), /^(\d+) bits/);
  const bd = intIn(await text(page, 'security-bd-figure'), /^(\d+) bits/);
  expect(mss).not.toBe(bd);

  // Each figure carries a quotation and a citation; a bare number would be
  // this page making an estimate of its own.
  for (const id of ['security-mss-quote', 'security-bd-quote', 'security-mss-source', 'security-bd-source']) {
    expect((await text(page, id)).length).toBeGreaterThan(0);
  }

  // No mean of the two is anywhere on the panel, and the page says outright
  // that it does not choose between them.
  const table = await text(page, 'security-table');
  expect(table).not.toContain(String((mss + bd) / 2));
  expect(await text(page, 'security-range')).toMatch(/Read it as a range/);
  expect(await text(page, 'security-scope')).toMatch(/does not\s+transfer to BN256/);
});

/**
 * A mutation that survived, and the test written to stop it surviving again.
 *
 * Forcing pane 1's per-vector `passed` flag unconditionally true left every claims
 * test green: the suite checked passed + failed = total, which still holds when
 * everything "passes", and the row printed its expected/actual pair only on the
 * FAILING path, so on the mutated build there was nothing on screen to contradict
 * the tick. The page has been changed to print both values on every row, and this
 * test cross-checks the badge against them -- two values the page itself printed,
 * which is the rule the whole suite is built on.
 */
test('every SM3 vector badge agrees with the two values printed beside it', async ({ page }) => {
  await page.goto('./');
  await page.getByTestId('p1-run-sm3').click();
  await expect(page.getByTestId('p1-sm3-results')).toBeVisible();

  const rows = await page.locator('[data-testid^="p1-vec-"][data-testid$="-actual"]').all();
  expect(rows.length).toBeGreaterThan(20);

  let agreeing = 0;
  for (const actualCell of rows) {
    const testid = await actualCell.getAttribute('data-testid');
    const id = testid!.replace(/-actual$/, '');
    const actual = ((await actualCell.textContent()) ?? '').trim();
    const expectedText = ((await page.getByTestId(`${id}-expected`).textContent()) ?? '').trim();
    const badge = page.getByTestId(id);
    const badgeClass = (await badge.getAttribute('class')) ?? '';

    if (/CONTROL/i.test(id)) {
      // The control is the one row whose values MUST differ and whose badge MUST
      // say so. Asserted here rather than skipped.
      expect(actual, `${id}: the control's computed and expected values must differ`).not.toBe(
        expectedText,
      );
      expect(badgeClass).not.toMatch(/status-ok/);
      continue;
    }
    const claimsMatch = /status-ok|match/.test(badgeClass);
    const reallyMatches = actual.length > 0 && actual === expectedText;
    expect(
      claimsMatch,
      `${id}: badge says ${claimsMatch ? 'match' : 'mismatch'} but the printed values ` +
        `${reallyMatches ? 'agree' : 'differ'}\n  expected ${expectedText}\n  actual   ${actual}`,
    ).toBe(reallyMatches);
    if (reallyMatches) agreeing++;
  }

  // The totals the page prints must equal what the rows actually show.
  const passedText = ((await page.getByTestId('p1-sm3-passed').textContent()) ?? '').trim();
  expect(Number(passedText.replace(/\D+/g, ''))).toBe(agreeing);
});

/**
 * The negative control must be reported as failing.
 *
 * This is the assertion that gives every other badge in pane 1 its meaning: if a
 * deliberately-wrong vector is reported as matching, the comparison is not
 * comparing, and the 30 green ticks beside it are worth nothing.
 */
test('pane 1 runs a deliberately wrong vector and reports it as a mismatch', async ({ page }) => {
  await page.goto('./');
  await page.getByTestId('p1-run-sm3').click();
  const control = page.getByTestId('p1-sm3-control');
  await expect(control).toBeVisible();
  await expect(control).toHaveClass(/status-ok/);
  await expect(control).toContainText(/correctly reported as a mismatch/i);

  // And the control is not silently counted among the real vectors.
  const passed = Number(((await page.getByTestId('p1-sm3-passed').textContent()) ?? '').replace(/\D+/g, ''));
  const total = Number(((await page.getByTestId('p1-sm3-total').textContent()) ?? '').replace(/\D+/g, ''));
  expect(passed).toBe(total);
});

// ---------------------------------------------------------------------------
// THE GUIDED PATH — the shell's own claims, tested as claims
// ---------------------------------------------------------------------------

test.describe('the guided lab', () => {
  test('nothing is computed before the reader causes it, and the symbolic path is still on screen', async ({ page }) => {
    await page.goto('./');

    // THE CONTRADICTION THIS REPLACES. The page used to open with pane 1 saying
    // "pending — not yet run" directly above pane 2 saying "ds_A issued": the
    // headline act had already happened and nobody had pressed anything.
    await expect(at(page, 'p1-sm3-summary')).toContainText('pending');
    await expect(at(page, 'p2-extract-verdict').locator('.verdict-pending')).toHaveCount(1);
    await expect(at(page, 'p2-extract-verdict').locator('.verdict-ok')).toHaveCount(0);
    await expect(at(page, 'p2-annex-table')).toHaveCount(0);
    await expect(at(page, 'p2-questions-table')).toHaveCount(0);

    // ... and every value slot in the relation says so rather than showing a
    // placeholder number or the annex's own figure standing in for a measured one.
    for (const key of ['idhid', 'h1', 'master', 't1', 't1inv', 't2', 'key']) {
      expect(await text(page, `p2-step-${key}`), `p2-step-${key} is not pending`).toBe('—');
    }

    // The path itself IS painted, with its operations named, so a reader can see
    // what the button is going to do before pressing it.
    for (const key of ['idhid', 'h1', 't1', 't1inv', 't2', 'key']) {
      await expect(at(page, `p2-line-${key}`)).toHaveCount(1);
    }
    expect(await text(page, 'p2-line-t1inv')).toMatch(/INVERT MOD N|invert mod N/i);
  });

  test('step 2 unlocks on step 1 succeeding, not on its button being pressed, and the unlock is announced', async ({ page }) => {
    await page.goto('./');
    await expectStatus(page, 'rail-state-sm3', 'info', /^ready$/);
    await expectStatus(page, 'rail-state-extract', 'pending', /^locked$/);
    await expect(at(page, 'lock-extract')).toBeVisible();
    await expect(at(page, 'p2-extract')).not.toBeVisible();

    await at(page, 'p1-run-sm3').click();
    await expect(at(page, 'p1-sm3-status')).toBeVisible();

    // The gate is the RESULT: zero failures and a negative control that was
    // correctly reported as a mismatch. Both are asserted from the page.
    await expect(at(page, 'p1-sm3-failed')).toHaveText(/^0 failed$/);
    await expectStatus(page, 'p1-sm3-control', 'ok', /negative control correctly/);

    await expectStatus(page, 'rail-state-extract', 'info', /^ready$/);
    await expect(at(page, 'lab-live')).toContainText(/Step 2, extract an identity key/);

    // The collapsed line a completed step leaves behind is the step's own
    // measured totals, not a constant: it has to agree with the counts the
    // summary printed.
    await at(page, 'next-sm3').click();
    const published = await text(page, 'p1-sm3-published');
    expect(await text(page, 'summary-sm3')).toContain(published.replace(' published in the annexes', ''));
    await expect(at(page, 'p2-extract')).toBeVisible();
  });

  test('resetting a step clears it and relocks every step after it', async ({ page }) => {
    await page.goto('./');
    await at(page, 'p1-run-sm3').click();
    await expect(at(page, 'p1-sm3-status')).toBeVisible();
    await at(page, 'next-sm3').click();
    await at(page, 'p2-extract').click();
    await awaitRelation(page);
    await expectStatus(page, 'rail-state-protocols', 'info', /^ready$/);

    // Back/Reset/Next belong to the step you are in, so a collapsed step is
    // reopened through the control on its own line first — which is also the
    // control a reader uses to go back and look at what they did.
    await at(page, 'reopen-sm3').click();
    await expect(at(page, 'p1-run-sm3')).toBeVisible();
    await at(page, 'reset-sm3').click();

    // Step 1's own result is gone, and so is everything it unlocked. A page that
    // relocked the rail and left "ds_A issued" on screen underneath would be
    // publishing a verdict about a run it no longer holds.
    await expect(at(page, 'p1-sm3-summary')).toContainText('pending');
    await expect(at(page, 'p1-sm3-table')).toHaveCount(0);
    await expectStatus(page, 'rail-state-extract', 'pending', /^locked$/);
    await expectStatus(page, 'rail-state-protocols', 'pending', /^locked$/);
    await expect(at(page, 'p2-extract-verdict').locator('.verdict-ok')).toHaveCount(0);
    await expect(at(page, 'p2-questions-table')).toHaveCount(0);
    expect(await text(page, 'p2-step-t1inv')).toBe('—');
  });

  test('Full evidence unlocks every step, and the rail stops saying locked', async ({ page }) => {
    await page.goto('./');
    await expect(at(page, 'p5b-run')).not.toBeVisible();

    await at(page, 'lab-view-full').check();

    for (const id of ['sm3', 'extract', 'protocols', 'kgc', 'break']) {
      await expect(at(page, `lock-${id}`), `${id} is still locked`).not.toBeVisible();
      // The rail is a claim about the page beside it. A rail still reading
      // "locked" next to an expanded pane would be the rail contradicting it.
      expect(await text(page, `rail-state-${id}`)).not.toMatch(/locked/);
    }
    await expect(at(page, 'p1-run-sm3')).toBeVisible();
    await expect(at(page, 'p5a-run')).toBeVisible();
  });

  test('the run transcript is read off the rendered page, and agrees with it', async ({ page }) => {
    await openLab(page);
    await at(page, 'lab-transcript').click();
    await expect(at(page, 'lab-transcript-json')).toHaveCount(1);

    const json = await at(page, 'lab-transcript-json').inputValue();
    const transcript = JSON.parse(json) as {
      steps: {
        step: string;
        values: { testid: string; value: string }[];
        verdicts: { testid: string; kind: string; headline: string }[];
        inputs: { testid: string; value: string }[];
      }[];
    };

    const extract = transcript.steps.find((step) => step.step === 'extract');
    expect(extract, 'the transcript has no extraction step').toBeDefined();

    // THE POINT OF THE EXPORT IS THAT IT CANNOT DISAGREE WITH THE SCREEN. Every
    // value is checked against the element it was read from, so a transcript
    // assembled from a parallel copy of the state would fail here.
    const t2 = extract?.values.find((entry) => entry.testid === 'p2-step-t2');
    expect(t2?.value).toBe(await text(page, 'p2-step-t2'));

    const verdict = extract?.verdicts.find((entry) => entry.testid === 'p2-extract-verdict');
    expect(verdict?.kind).toBe('ok');
    expect(verdict?.headline).toBe(await expectVerdict(page, 'p2-extract-verdict', 'ok'));

    expect(extract?.inputs.find((entry) => entry.testid === 'p2-identity')?.value).toBe('Alice');
    // The map is a radio group; only the CHECKED option is a state of this run.
    expect(extract?.inputs.filter((entry) => /^p2-map-/.test(entry.testid)).map((e) => e.testid))
      .toEqual(['p2-map-standard']);
  });

  test('the decisive experiment changes exactly three of its five answers, and names which', async ({ page }) => {
    await openLab(page);

    // Under SM9's own H1 every row agrees.
    await expectStatus(page, 'p2-q-samekey', 'ok');
    await expectStatus(page, 'p2-q-cancels', 'info');
    await expectStatus(page, 'p2-q-agreeing', 'ok', /^ACCEPTED$/);
    await expectStatus(page, 'p2-q-realverifier', 'ok', /^ACCEPTED$/);
    await expectStatus(page, 'p2-q-pinned', 'ok', /Annex A/);

    await at(page, 'p2-map-altered').check();
    await awaitRelation(page);

    // THE WHOLE THESIS, AS A PARTITION. The two that still say yes are exactly
    // the two a round trip performs on itself; the three that go red each need
    // something the run does not contain.
    await expectStatus(page, 'p2-q-cancels', 'info', /holds for ANY h1/);
    await expectStatus(page, 'p2-q-agreeing', 'alarm', /ACCEPTED/);
    await expectStatus(page, 'p2-q-samekey', 'bad', /DIFFERENT key/);
    await expectStatus(page, 'p2-q-realverifier', 'bad', /refused at HASH-MISMATCH/);
    await expectStatus(page, 'p2-q-pinned', 'bad', /DIFFERS/);

    // The two keys really are different keys, so the fixture is real rather than
    // a relabelling: assert it from the values, not from the badge.
    const alteredT2 = await text(page, 'p2-step-t2');
    await at(page, 'p2-map-standard').check();
    await awaitRelation(page);
    expect(await text(page, 'p2-step-t2')).not.toBe(alteredT2);
    await expectStatus(page, 'p2-q-pinned', 'ok', /Annex A/);
  });

  test('the evidence limits are in the page, not only in the README', async ({ page }) => {
    await page.goto('./');
    await openDetails(page, 'lab-limits');
    const limits = await text(page, 'lab-limits');
    expect(limits).toMatch(/Fp12 pairing values rest on one engine/);
    expect(limits).toMatch(/No constant-time property is claimed or tested/);
    expect(limits).toMatch(/GB\/T 41389-2022 has not been read/);
    expect(limits).toMatch(/paywalled/);
    // The one attribution that used to be second-hand now names the file it was
    // read in, which is the difference between a citation and a rumour.
    expect(limits).toMatch(/SM9EncMasterPrivateKeyParameters\.java/);
  });
});
