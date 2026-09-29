/**
 * THE GEOMETRY GATE — the quality failures no accessibility rule reports.
 *
 * WHY THIS EXISTS SEPARATELY FROM e2e/a11y.spec.ts. That suite is a WCAG gate and
 * it is a good one: it measures contrast arithmetically, boundaries for 1.4.11,
 * reflow for 1.4.10, and it passed this page in states that were genuinely bad to
 * use. Three of them, specifically:
 *
 *  1. The two SVG diagrams in pane 2 scaled a fixed viewBox to the viewport, so
 *     their 11- and 12-unit labels rendered at roughly 5 to 7 CSS pixels on a
 *     phone. The contrast oracle measured those labels CORRECTLY and passed them.
 *     Contrast is not legibility, and there is no axe rule for text that is
 *     physically too small to read.
 *
 *  2. `.cl-hero-main` kept `flex-basis: 22rem` inside the column-direction mobile
 *     media query, which sizes the MAIN axis — height — so the hero reserved 352px
 *     for a 168px block and left a measured 184px of nothing below it. Perfectly
 *     accessible, and wrong.
 *
 *  3. The landing page was 10,497px on a desktop and 16,601px on a phone with the
 *     first button 2,003px and 4,081px down. Nothing in WCAG says a page may not
 *     be a mile long.
 *
 * Every number below is a measurement of the production build in a real viewport,
 * and every one of them names what to fix when it fails.
 */
import { expect, test } from '@playwright/test';
import type { Page } from '@playwright/test';

const DESKTOP = { width: 1440, height: 900 };
const PHONE = { width: 390, height: 844 };

const at = (page: Page, testid: string) => page.locator(`[data-testid="${testid}"]`);

/**
 * Text allowed below the 12 CSS pixel floor, each with the reason it is allowed.
 *
 * An allowlist rather than a lower floor, because the distinction that matters is
 * not the number: it is whether the run is CONTENT a reader has to take in, or a
 * tracked label that names the thing beside it. A citation is content — that is
 * why `.source-tag` is not on this list any more. A pane's "PANE 1" eyebrow is
 * not.
 */
const SMALL_LABEL_ALLOWANCES: { selector: string; why: string }[] = [
  { selector: '.cl-hero-why-label', why: 'the tracked "WHY IT MATTERS" eyebrow, which labels the panel below it' },
  { selector: '.pane-num', why: 'the tracked "PANE 1" eyebrow beside a pane title that is 1.12rem' },
  { selector: '.rail-num', why: 'the step digit in the rail, aria-hidden, repeated as a word beside it' },
];

interface TooSmall {
  what: string;
  size: number;
  declared: number;
  text: string;
}

/**
 * Every visible text run, measured at the size it is actually PAINTED.
 *
 * Painted, not declared: vector text inside a scaled `<svg>` renders at
 * `declared × (painted width / viewBox width)`, and judging it at the declared
 * size is how a diagram whose labels are five pixels tall passes a review. There
 * is no SVG left on this page — both diagrams are HTML now — so this arm is a
 * regression guard rather than a live measurement, and it is kept for exactly
 * that reason.
 */
async function auditTextSize(page: Page): Promise<{ tooSmall: TooSmall[]; measured: number }> {
  return page.evaluate((allowances) => {
    const tooSmall: TooSmall[] = [];
    let measured = 0;

    function ownText(node: Element): string {
      return Array.from(node.childNodes)
        .filter((child) => child.nodeType === Node.TEXT_NODE)
        .map((child) => child.textContent ?? '')
        .join('')
        .trim();
    }

    function describe(node: Element): string {
      const id = node.getAttribute('data-testid');
      const cls = node.className && typeof node.className === 'string' ? `.${node.className.split(' ').join('.')}` : '';
      return `${node.tagName.toLowerCase()}${cls}${id === null ? '' : `[${id}]`}`;
    }

    for (const node of Array.from(document.querySelectorAll('body *'))) {
      const text = ownText(node);
      if (text === '') continue;
      const withCheck = node as Element & { checkVisibility?: (o?: { checkVisibilityCSS?: boolean }) => boolean };
      if (typeof withCheck.checkVisibility === 'function' && !withCheck.checkVisibility({ checkVisibilityCSS: true })) {
        continue;
      }
      if (node.closest('[aria-hidden="true"]') !== null) continue;

      const style = getComputedStyle(node);
      const declared = parseFloat(style.fontSize);

      // Vector text scales with its viewBox; HTML text does not.
      let painted = declared;
      const svg = node.closest('svg');
      if (svg !== null) {
        const box = svg.viewBox?.baseVal;
        const width = svg.getBoundingClientRect().width;
        if (box !== undefined && box !== null && box.width > 0 && width > 0) {
          painted = declared * (width / box.width);
        }
      }

      measured += 1;
      if (painted >= 12) continue;
      if (allowances.some((allowance) => node.matches(allowance.selector))) continue;
      tooSmall.push({
        what: describe(node),
        size: Math.round(painted * 100) / 100,
        declared: Math.round(declared * 100) / 100,
        text: text.slice(0, 60),
      });
    }
    return { tooSmall, measured };
  }, SMALL_LABEL_ALLOWANCES);
}

/** Open the lab with every exhibit expanded, which is the densest state it has. */
async function openEverything(page: Page): Promise<void> {
  await page.goto('./', { waitUntil: 'load' });
  await at(page, 'lab-view-full').check();
  await at(page, 'p1-run-sm3').click();
  await expect(at(page, 'p1-sm3-table')).toHaveCount(1);
  await at(page, 'p2-extract').click();
  await expect(at(page, 'p2-line-key')).toHaveClass(/is-filled/);
  await at(page, 'p3a-run').click();
  await expect(at(page, 'p3a-verify-status')).toHaveCount(1);
}

test.describe('the landing page is a lab, not a document', () => {
  test('desktop: the first action is in the first viewport, and the page is not a mile long', async ({ page }) => {
    await page.setViewportSize(DESKTOP);
    await page.goto('./', { waitUntil: 'load' });

    const run = await at(page, 'p1-run-sm3').boundingBox();
    expect(run, 'the SM3 control did not render').not.toBeNull();
    const bottom = (run?.y ?? 0) + (run?.height ?? 0);
    expect(
      bottom,
      `the first meaningful action ends ${Math.round(bottom)}px down a ${DESKTOP.height}px viewport, `
        + 'so a visitor has to scroll before the lab offers them anything to do',
    ).toBeLessThanOrEqual(DESKTOP.height);

    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    // The landing state was 10,497px here. This is not a style rule: a default
    // page that long means the audit trail is rendering before anybody has asked
    // for it, which is the specific thing progressive disclosure fixed.
    expect(height, `the default desktop page is ${height}px tall`).toBeLessThanOrEqual(5000);
  });

  test('phone: the first action is no later than the second viewport, and the hero has no dead gap', async ({ page }) => {
    await page.setViewportSize(PHONE);
    await page.goto('./', { waitUntil: 'load' });

    const run = await at(page, 'p1-run-sm3').boundingBox();
    const bottom = (run?.y ?? 0) + (run?.height ?? 0);
    expect(
      bottom,
      `the first meaningful action ends ${Math.round(bottom)}px down, past the second ${PHONE.height}px viewport`,
    ).toBeLessThanOrEqual(PHONE.height * 2);

    // The hero stacks below 640px. `.cl-hero-main` used to keep a 22rem
    // flex-basis, which in a column direction is a HEIGHT, and the gap measured
    // 184px.
    const gap = await page.evaluate(() => {
      const main = document.querySelector('.cl-hero-main');
      const why = document.querySelector('.cl-hero-why');
      if (main === null || why === null) return null;
      return Math.round(why.getBoundingClientRect().top - main.getBoundingClientRect().bottom);
    });
    expect(gap, 'the hero did not render both halves').not.toBeNull();
    expect(gap ?? 0, `the hero leaves a ${gap}px gap below its description`).toBeLessThanOrEqual(32);

    const height = await page.evaluate(() => document.documentElement.scrollHeight);
    // 16,601px before.
    expect(height, `the default phone page is ${height}px tall`).toBeLessThanOrEqual(8000);
  });
});

test.describe('every text run is large enough to read, in the state that has the most of them', () => {
  for (const viewport of [DESKTOP, PHONE]) {
    test(`${viewport.width}px, every exhibit expanded`, async ({ page }) => {
      test.setTimeout(120_000);
      await page.setViewportSize(viewport);
      await openEverything(page);

      const { tooSmall, measured } = await auditTextSize(page);
      expect(measured, 'the size oracle measured almost nothing').toBeGreaterThan(200);
      expect(
        tooSmall,
        `text below the 12 CSS pixel floor at ${viewport.width}px:\n`
          + tooSmall.map((t) => `  ${t.what} painted ${t.size}px (declared ${t.declared}px): "${t.text}"`).join('\n')
          + `\nAllowed below the floor, and why:\n`
          + SMALL_LABEL_ALLOWANCES.map((a) => `  ${a.selector} — ${a.why}`).join('\n'),
      ).toEqual([]);

      // eslint-disable-next-line no-console
      console.log(`[geometry ${viewport.width}px] ${measured} text runs measured, ${tooSmall.length} below 12px`);
    });
  }
});

test('no scaled vector text anywhere, at any width', async ({ page }) => {
  await page.setViewportSize(PHONE);
  await openEverything(page);

  // The rule the two pane-2 diagrams broke, stated as a rule. If an SVG returns,
  // it must either be painted at least as wide as its own viewBox or carry no
  // text at all — a diagram whose labels shrink with the viewport is a diagram
  // that stops being readable exactly where it is needed most.
  const scaled = await page.evaluate(() =>
    Array.from(document.querySelectorAll('svg'))
      .filter((svg) => svg.querySelector('text') !== null)
      .map((svg) => {
        const box = svg.viewBox?.baseVal;
        const width = svg.getBoundingClientRect().width;
        const declared = box === undefined || box === null ? 0 : box.width;
        return { declared, painted: Math.round(width), scale: declared === 0 ? 1 : width / declared };
      })
      .filter((entry) => entry.scale < 1),
  );
  expect(scaled, `vector text is being scaled down: ${JSON.stringify(scaled)}`).toEqual([]);
});
