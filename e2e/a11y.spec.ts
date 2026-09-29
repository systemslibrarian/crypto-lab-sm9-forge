import AxeBuilder from '@axe-core/playwright';
import { expect, test, type Locator, type Page } from '@playwright/test';

/**
 * The WCAG 2.1 A/AA gate, run against the PRODUCTION BUILD.
 *
 * `playwright.config.ts` builds before it serves, so what this judges is what
 * `dist/` would publish. `deploy.yml` runs it before `actions/deploy-pages`, and
 * the deploy job `needs: build`, so a violation here blocks the publish rather
 * than being noticed afterwards.
 *
 * WHAT THIS GATE REFUSES TO DO, and why each refusal is here.
 *
 *  1. NOTHING IS INJECTED INTO THE PAGE. No `addStyleTag` motion kill: that
 *     bypasses this lab's own `@media (prefers-reduced-motion: reduce)` block
 *     instead of exercising it, so the rendering a reduced-motion reader gets is
 *     never the rendering that gets scanned. The preference is set through
 *     `emulateMedia` BEFORE navigation and asserted from inside the page,
 *     because `test.use({ reducedMotion })` and the config key are measured
 *     no-ops on some Playwright builds. It would also be refused here: the page
 *     ships `style-src 'self'` with no `'unsafe-inline'`, so an injected
 *     `<style>` is dropped by the browser with no visible error and the gate
 *     would scan an unstyled page believing it had suppressed motion.
 *
 *  2. NOTHING IS REVEALED FROM SCRIPT. Every `<details>` is opened by clicking
 *     its `<summary>`, which is the route a reader has. Forcing `open` from JS
 *     scans a state the page never renders, and — worse — hides the `[hidden]`
 *     cascade trap, where a class rule setting `display` outranks the UA
 *     `[hidden]` rule so an element paints while the code believes it is hidden.
 *
 *  3. NOTHING IS WAITED ON BY CLOCK. Every exhibit on this page computes through
 *     `defer()` (a rAF plus a task), so a fixed `waitForTimeout` would scan an
 *     empty container and pass having checked nothing. Each step names the
 *     testid its own completion writes, and waits for that.
 *
 *  4. `violations` IS NOT THE WHOLE ORACLE. axe files every contrast decision it
 *     declines under `incomplete`, and on this page it declines all of them for
 *     the two SVG diagrams in pane 2 — axe has no contrast oracle for SVG
 *     `<text>`. A gate reading `violations` alone would report a clean AA pass
 *     over the exhibit it never judged. `auditTextContrast` computes those
 *     ratios arithmetically, in the page, over resolved colours — including the
 *     `oklab(... / 0.08)` fill the hero's aside computes to, and the
 *     `fill-opacity` the diagram labels carry.
 *
 *  5. axe HAS NO RULE FOR WCAG 1.4.11 (non-text contrast) AND NONE FOR 1.4.10
 *     (reflow). Both are checked here directly: `auditControlBoundaries` over
 *     every form control, and `expectNoHorizontalOverflow` at 380px.
 *
 *  6. A COLOUR THIS GATE CANNOT PARSE IS REPORTED, NEVER SKIPPED. Every oracle
 *     below returns `unreadable` entries alongside its failures and the run
 *     fails on either. A checker that could not look must say so; it is never
 *     permitted to express the gap as a clean result.
 *
 * WHAT IT DRIVES. The landing state is a small fraction of this lab, and since
 * the shell gates the exhibits left to right the gate walks the SAME PATH A
 * VISITOR WALKS rather than reaching past it: it runs the SM3 layer and watches
 * step 2 unlock, extracts a key, switches the identity map to the altered one and
 * back, re-extracts for a different identity, hid and master key pair, forces the
 * t1 = 0 branch that refuses to issue a key, signs and verifies Annex A on its
 * pinned nonce and again on a fresh one, runs the eight must-reject cases,
 * extracts under a deliberately wrong H1, runs the key exchange at hid 0x03 and
 * then at BOTH hid values side by side, runs the KEM and both encryption modes,
 * exercises the KGC's two powers, recovers a private key from a reused nonce and
 * drives the recovery's refusal path, and finally switches to Full evidence and
 * opens every disclosure in every tab. Every one of those states is scanned, at
 * 1280px and at 380px.
 *
 * THE LOCKED AND COLLAPSED STATES ARE SCANNED TOO. A lock panel, a collapsed
 * one-line result and a rail full of status pills are rendering this page did not
 * have before, and they are exactly the kind of chrome that ships unmeasured.
 */

/** WCAG 2.0/2.1 level A and AA. Best-practice rules are deliberately not here. */
const TAGS = ['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'];

const DESKTOP = { width: 1280, height: 900 };

/**
 * The narrow viewport, at the width WCAG 1.4.10 is written around (320 CSS px
 * at 400% zoom ~ 1280/4). 380 is the fleet's figure and is the harder case for
 * this page specifically: it paints 64- and 768-nibble hex strings and two
 * side-by-side panels, which are exactly what widens a phone viewport.
 */
const NARROW = { width: 380, height: 900 };

/**
 * Console messages this gate does not fail on, each named with the reason.
 *
 * There is exactly one, and it is a browser advisory about the DELIVERY of the
 * page's CSP rather than anything the page does: `frame-ancestors` has no effect
 * in a `<meta>` CSP and Chromium says so on every load. GitHub Pages serves no
 * custom response headers, so the meta element is the only delivery this lab
 * has and the directive is simply inert in it. Recorded here rather than
 * filtered silently, because an unexplained filter is how a real error gets
 * swallowed later.
 */
const CONSOLE_ALLOWANCES: { pattern: RegExp; why: string }[] = [
  {
    pattern: /Content Security Policy directive 'frame-ancestors' is ignored/i,
    why: 'frame-ancestors cannot be delivered by <meta>; Pages serves no headers, so it is inert, not broken.',
  },
];

// ---------------------------------------------------------------------------
// page error collection
// ---------------------------------------------------------------------------

/**
 * Collect uncaught exceptions and console errors.
 *
 * An exhibit that throws mid-render leaves a half-built pane behind, and a
 * half-built pane is often ACCESSIBLE — there is nothing there to violate a
 * rule. Without this, the gate's cleanest run would be the one where the
 * cryptography died.
 */
function watchPageErrors(page: Page): string[] {
  const errors: string[] = [];
  page.on('pageerror', (error) => errors.push(`pageerror: ${error.message}`));
  page.on('console', (message) => {
    if (message.type() !== 'error') return;
    const text = message.text();
    if (CONSOLE_ALLOWANCES.some((allowance) => allowance.pattern.test(text))) return;
    errors.push(`console.error: ${text}`);
  });
  return errors;
}

// ---------------------------------------------------------------------------
// quiescence
// ---------------------------------------------------------------------------

/**
 * Wait until no animation or transition is running.
 *
 * A transition sampled mid-flight has a colour that exists in no state of the
 * page, and both axe and the arithmetic oracle below will happily report it.
 * Transitions also drain in waves, so a single "nothing running right now" poll
 * can exit through a gap between two of them — hence six consecutive quiet
 * frames. Infinite animations are excluded rather than waited on, and an
 * in-page wall-clock budget gives up and proceeds, because a gate that can hang
 * is a gate nobody runs.
 *
 * Under the reduced motion this gate asserts, `styles.css` cancels every
 * transition, so this normally returns on the sixth frame.
 */
async function settle(page: Page, budgetMs = 3000): Promise<void> {
  await page.waitForFunction(
    (budget: number) => {
      const w = window as unknown as { __quiet?: number; __start?: number };
      if (w.__start === undefined) w.__start = performance.now();
      const finish = (): boolean => {
        w.__quiet = 0;
        w.__start = undefined;
        return true;
      };
      const running = document.getAnimations().filter((animation) => {
        if (animation.playState !== 'running') return false;
        return animation.effect?.getComputedTiming?.().iterations !== Infinity;
      });
      w.__quiet = running.length === 0 ? (w.__quiet ?? 0) + 1 : 0;
      if ((w.__quiet ?? 0) >= 6) return finish();
      if (performance.now() - (w.__start ?? 0) > budget) return finish();
      return false;
    },
    budgetMs,
    { timeout: 20_000, polling: 'raf' },
  );
}

// ---------------------------------------------------------------------------
// boot
// ---------------------------------------------------------------------------

/**
 * Navigate, then assert the page actually arrived in the state this gate claims
 * to be scanning.
 *
 * The shipped defaults are asserted BEFORE anything is measured, so a build that
 * rendered nothing — the scan race, or a throwing module — cannot pass by having
 * no content to violate a rule.
 */
async function boot(page: Page): Promise<void> {
  // Before navigation: the stylesheet's own reduced-motion block must be the one
  // exercised, which means the preference has to be set on the first paint.
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.goto('./', { waitUntil: 'load' });

  const effective = await page.evaluate(() => ({
    reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
    dark: matchMedia('(prefers-color-scheme: dark)').matches,
  }));
  expect(effective.reduced, 'emulateMedia did not take effect in the page').toBe(true);
  expect(effective.dark, 'the context is not being served as a dark-scheme client').toBe(true);

  // The five exhibits and the closing note must all have MOUNTED. Only step 1 is
  // expanded — the rest are behind the guided shell's locks — so presence is
  // asserted by count and the landing state's own visibility is asserted below.
  for (const testid of ['p1-pane', 'p2-pane', 'p3-pane', 'p4-pane', 'p5-pane', 'security-note']) {
    await expect(page.locator(`[data-testid="${testid}"]`), `${testid} did not mount`).toHaveCount(1);
  }
  await expect(page.locator('[data-testid="p1-pane"]')).toBeVisible();
  await expect(page.locator('[data-testid="lab-rail"]')).toBeVisible();
  await expect(page.locator('[data-testid="lab-rail-steps"] > li')).toHaveCount(5);

  // THE SHIPPED DEFAULT IS THAT NOTHING HAS BEEN COMPUTED. Asserted, because it
  // is the property the guided shell exists to produce: the page used to run an
  // extraction on load, and a gate that still waited for one would be waiting for
  // the bug. The parameter set is painted statically and folded, so it is checked
  // for content rather than for visibility.
  await expect(page.locator('[data-testid="p1-param-q"]')).not.toBeEmpty();
  await expect(page.locator('[data-testid="p1-sm3-summary"]')).toContainText('pending');
  await expect(page.locator('[data-testid="p2-extract-verdict"] .verdict-pending')).toHaveCount(1);
  await expect(page.locator('[data-testid="p2-extract"]')).not.toBeVisible();

  await settle(page);
}

// ---------------------------------------------------------------------------
// oracle 1 — axe
// ---------------------------------------------------------------------------

interface AxeFinding {
  rule: string;
  impact: string;
  help: string;
  targets: string[];
}

/**
 * Run axe once over the whole page.
 *
 * `.withTags(TAGS)` is called ONCE and never chained with `.withRules(...)` —
 * both write `options.runOnly`, so a chained pair silently discards the first
 * and a gate can end up running four best-practice rules and zero WCAG ones
 * while reading as a full A/AA pass.
 *
 * Both buckets are returned. `incomplete` is where axe puts every decision it
 * declined, and it is judged by the caller against what the arithmetic oracles
 * below actually cover.
 */
async function runAxe(page: Page): Promise<{ violations: AxeFinding[]; incomplete: AxeFinding[]; passed: number }> {
  const results = await new AxeBuilder({ page }).withTags(TAGS).analyze();
  const shape = (list: typeof results.violations): AxeFinding[] =>
    list.map((entry) => ({
      rule: entry.id,
      impact: entry.impact ?? 'unknown',
      help: entry.help,
      targets: entry.nodes.map((node) => node.target.join(' ')),
    }));
  return { violations: shape(results.violations), incomplete: shape(results.incomplete), passed: results.passes.length };
}

/**
 * The only axe rule this gate accepts an `incomplete` verdict for.
 *
 * axe has no contrast oracle for SVG `<text>`, so every label in pane 2's two
 * diagrams lands here. That is safe ONLY because `auditTextContrast` measures
 * SVG text itself, over the resolved `fill`, its `fill-opacity`, and the
 * composited background behind it. Any other rule arriving in this bucket means
 * axe declined something nothing else is checking, and fails the run by name.
 */
const INCOMPLETE_COVERED_BY_OUR_OWN_ORACLE = new Set(['color-contrast']);

// ---------------------------------------------------------------------------
// oracle 2 — text contrast, computed rather than deferred to
// ---------------------------------------------------------------------------

interface ContrastFinding {
  what: string;
  ratio: number;
  required: number;
  foreground: string;
  background: string;
  text: string;
}

interface ContrastReport {
  failures: ContrastFinding[];
  unreadable: { what: string; value: string; text: string }[];
  measured: number;
}

/**
 * Measure the contrast of every visible run of text on the page, HTML and SVG
 * alike, and fail on anything under its WCAG 1.4.3 threshold.
 *
 * Everything happens inside the page because the browser is the only thing that
 * knows what it painted: `color-mix()` resolves to `oklab()` in the computed
 * style, `currentColor` on an SVG fill resolves to an inherited `rgb()`, and an
 * alpha background has to be composited against whatever is actually behind it.
 *
 * Two refusals are encoded here. A colour function this parser does not know is
 * reported as `unreadable` and fails the run rather than being skipped — a
 * skipped element is indistinguishable from a passing one in the total. And an
 * element painting a `background-image` is also reported as unreadable, because
 * a ratio computed against its `background-color` alone would be a number about
 * a background the reader never sees.
 */
async function auditTextContrast(page: Page): Promise<ContrastReport> {
  return page.evaluate(() => {
    type Rgba = [number, number, number, number];

    const failures: ContrastFinding[] = [];
    const unreadable: { what: string; value: string; text: string }[] = [];
    let measured = 0;

    /** oklab -> linear sRGB -> gamma-encoded sRGB. Chrome computes color-mix() to oklab. */
    function oklabToRgb(L: number, a: number, b: number, alpha: number): Rgba {
      const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
      const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
      const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
      const lin = [
        4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
        -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
        -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
      ];
      const encode = (c: number): number => {
        const clamped = Math.min(1, Math.max(0, c));
        const v = clamped <= 0.0031308 ? 12.92 * clamped : 1.055 * clamped ** (1 / 2.4) - 0.055;
        return Math.round(v * 255);
      };
      return [encode(lin[0]), encode(lin[1]), encode(lin[2]), alpha];
    }

    const num = (token: string): number =>
      token.endsWith('%') ? Number(token.slice(0, -1)) / 100 : Number(token);

    /** Returns null for a syntax this parser does not know — the caller must not treat that as clean. */
    function parseColor(input: string): Rgba | null {
      const value = (input || '').trim().toLowerCase();
      if (value === '' || value === 'transparent' || value === 'none') return [0, 0, 0, 0];

      const parts = (inner: string): string[] => inner.split(/[\s,/]+/).filter((p) => p !== '');

      let m = /^rgba?\(([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        const channel = (t: string): number => (t.endsWith('%') ? (Number(t.slice(0, -1)) * 255) / 100 : Number(t));
        return [channel(p[0]), channel(p[1]), channel(p[2]), p.length > 3 ? num(p[3]) : 1];
      }
      m = /^color\(srgb\s+([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        return [num(p[0]) * 255, num(p[1]) * 255, num(p[2]) * 255, p.length > 3 ? num(p[3]) : 1];
      }
      m = /^oklab\(([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        return oklabToRgb(num(p[0]), Number(p[1]), Number(p[2]), p.length > 3 ? num(p[3]) : 1);
      }
      m = /^#([0-9a-f]{3,8})$/.exec(value);
      if (m) {
        const hex = m[1];
        const expand = (h: string): number[] =>
          h.length <= 4
            ? h.split('').map((c) => parseInt(c + c, 16))
            : (h.match(/../g) ?? []).map((c) => parseInt(c, 16));
        const c = expand(hex);
        if (c.length < 3) return null;
        return [c[0], c[1], c[2], c.length > 3 ? c[3] / 255 : 1];
      }
      return null;
    }

    function over(top: Rgba, bottom: Rgba): Rgba {
      const a = top[3] + bottom[3] * (1 - top[3]);
      if (a === 0) return [0, 0, 0, 0];
      const mix = (i: number): number => (top[i] * top[3] + bottom[i] * bottom[3] * (1 - top[3])) / a;
      return [mix(0), mix(1), mix(2), a];
    }

    function luminance(c: Rgba): number {
      const channel = (v: number): number => {
        const s = Math.min(1, Math.max(0, v / 255));
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]);
    }

    function ratio(a: Rgba, b: Rgba): number {
      const la = luminance(a);
      const lb = luminance(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    function describe(node: Element): string {
      const testid = node.closest('[data-testid]')?.getAttribute('data-testid');
      const cls = typeof node.className === 'string' && node.className !== '' ? `.${node.className.trim().split(/\s+/).join('.')}` : '';
      return `${node.tagName.toLowerCase()}${cls}${testid ? ` [in ${testid}]` : ''}`;
    }

    /**
     * Composite everything painted behind this text down to the first opaque
     * layer, STARTING AT THE ELEMENT ITSELF.
     *
     * Starting at the parent instead is a real bug and this gate shipped it for
     * one run: every `<button>` on this page paints `var(--accent)` under dark
     * label text, and a walk that began one level up measured that text against
     * the pane behind the button and reported nine 1.08:1 failures on a control
     * whose actual ratio is 6.8:1. An element with no background of its own has
     * alpha 0 and the walk continues to its parent anyway, so starting here is
     * correct in both cases.
     *
     * Walks out of an SVG into its HTML ancestors, which is what the diagrams need.
     */
    function backgroundBehind(node: Element): { colour: Rgba } | { unreadableValue: string } {
      const layers: Rgba[] = [];
      let current: Element | null = node;
      while (current !== null) {
        const style = getComputedStyle(current);
        if (style.backgroundImage !== 'none') {
          return { unreadableValue: `background-image ${style.backgroundImage} on ${describe(current)}` };
        }
        const parsed = parseColor(style.backgroundColor);
        if (parsed === null) return { unreadableValue: style.backgroundColor };
        if (parsed[3] > 0) {
          layers.push(parsed);
          if (parsed[3] >= 0.999) break;
        }
        current = current.parentElement;
      }
      // Nothing opaque anywhere: the canvas is whatever the UA paints. This page
      // gives <html> an explicit opaque background-color, so this is a guard
      // rather than a path, and it is white because that is the UA default.
      let result: Rgba = [255, 255, 255, 1];
      for (let i = layers.length - 1; i >= 0; i -= 1) result = over(layers[i], result);
      return { colour: result };
    }

    function ariaHidden(node: Element): boolean {
      return node.closest('[aria-hidden="true"]') !== null;
    }

    function cumulativeOpacity(node: Element): number {
      let total = 1;
      let current: Element | null = node;
      while (current !== null) {
        const value = Number(getComputedStyle(current).opacity);
        if (!Number.isNaN(value)) total *= value;
        current = current.parentElement;
      }
      return total;
    }

    function visible(node: Element): boolean {
      const withCheck = node as Element & {
        checkVisibility?: (options?: { checkVisibilityCSS?: boolean; checkOpacity?: boolean }) => boolean;
      };
      if (typeof withCheck.checkVisibility === 'function') {
        return withCheck.checkVisibility({ checkVisibilityCSS: true, checkOpacity: true });
      }
      const rect = node.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    }

    function ownText(node: Element): string {
      return Array.from(node.childNodes)
        .filter((child) => child.nodeType === Node.TEXT_NODE)
        .map((child) => child.textContent ?? '')
        .join('')
        .trim();
    }

    /**
     * The rendered pixel size of SVG text, not its user-unit `font-size`.
     *
     * Both diagrams are `width: 100%` over a fixed `viewBox`, so at 380px their
     * labels render at well under half their declared size. Judging them at the
     * declared size would apply the large-text threshold to text that is
     * physically tiny — an oracle grading the page on a rendering nobody sees.
     */
    function renderedFontSize(node: Element, declared: number): number {
      const svg = node.closest('svg');
      if (svg === null) return declared;
      const box = svg.viewBox?.baseVal;
      if (box === undefined || box === null || box.width === 0) return declared;
      const painted = svg.getBoundingClientRect().width;
      if (painted === 0) return declared;
      return declared * (painted / box.width);
    }

    const candidates = Array.from(document.querySelectorAll('body *'));
    for (const node of candidates) {
      const text = ownText(node);
      if (text === '') continue;
      if (ariaHidden(node)) continue;
      if (!visible(node)) continue;

      const style = getComputedStyle(node);
      const isSvgText = node.namespaceURI === 'http://www.w3.org/2000/svg';

      const rawForeground = isSvgText ? style.fill : style.color;
      const parsedForeground = parseColor(rawForeground);
      if (parsedForeground === null) {
        unreadable.push({ what: describe(node), value: rawForeground, text: text.slice(0, 60) });
        continue;
      }

      const behind = backgroundBehind(node);
      if ('unreadableValue' in behind) {
        unreadable.push({ what: describe(node), value: behind.unreadableValue, text: text.slice(0, 60) });
        continue;
      }

      // SVG text carries its own fill-opacity on top of any inherited opacity.
      const fillOpacity = isSvgText ? Number(style.fillOpacity || '1') : 1;
      const alpha = parsedForeground[3] * fillOpacity * cumulativeOpacity(node);
      const foreground: Rgba = [parsedForeground[0], parsedForeground[1], parsedForeground[2], alpha];
      const composited = over(foreground, behind.colour);

      const declaredSize = parseFloat(style.fontSize);
      const size = isSvgText ? renderedFontSize(node, declaredSize) : declaredSize;
      const weight = Number(style.fontWeight) || 400;
      const large = size >= 24 || (size >= 18.66 && weight >= 700);
      const required = large ? 3 : 4.5;

      const value = ratio(composited, behind.colour);
      measured += 1;
      if (value + 0.005 < required) {
        failures.push({
          what: describe(node),
          ratio: Math.round(value * 100) / 100,
          required,
          foreground: rawForeground,
          background: `rgb(${behind.colour.slice(0, 3).map((c) => Math.round(c)).join(' ')})`,
          text: text.slice(0, 60),
        });
      }
    }

    return { failures, unreadable, measured };
  });
}

// ---------------------------------------------------------------------------
// oracle 3 — non-text contrast (WCAG 1.4.11), which axe does not implement
// ---------------------------------------------------------------------------

interface BoundaryReport {
  failures: { what: string; best: number; from: string; against: string }[];
  unreadable: { what: string; value: string }[];
  measured: number;
}

/**
 * Judge the visual boundary of every form control against what sits behind it.
 *
 * WCAG 1.4.11 wants 3:1 for the visual information needed to IDENTIFY a control.
 * For this page that is a control's own fill or its border: a `button.secondary`
 * is body-coloured text with a one-pixel rule around it, and if that rule is not
 * discernible the control is indistinguishable from the prose beside it.
 *
 * Two things this deliberately gets right, both of which have gone wrong
 * elsewhere in this fleet:
 *
 *  - A BORDER IS MEASURED PER SIDE. Deriving "has a border" from
 *    `borderTopStyle` while measuring all four widths mis-reads a control
 *    bordered on one side only. Each side is tested for its own width, style and
 *    colour alpha, and only sides that actually paint are considered.
 *
 *  - ONLY CONTROLS ARE JUDGED. An oracle pointed at every bordered box on the
 *    page manufactures findings about decoration — a `.hex` block's hairline is
 *    not an affordance and is not required to reach 3:1. The set here is the
 *    form controls, where the requirement is unambiguous.
 */
async function auditControlBoundaries(page: Page): Promise<BoundaryReport> {
  return page.evaluate(() => {
    type Rgba = [number, number, number, number];
    const failures: { what: string; best: number; from: string; against: string }[] = [];
    const unreadable: { what: string; value: string }[] = [];
    let measured = 0;

    function oklabToRgb(L: number, a: number, b: number, alpha: number): Rgba {
      const l = (L + 0.3963377774 * a + 0.2158037573 * b) ** 3;
      const m = (L - 0.1055613458 * a - 0.0638541728 * b) ** 3;
      const s = (L - 0.0894841775 * a - 1.291485548 * b) ** 3;
      const lin = [
        4.0767416621 * l - 3.3077115913 * m + 0.2309699292 * s,
        -1.2684380046 * l + 2.6097574011 * m - 0.3413193965 * s,
        -0.0041960863 * l - 0.7034186147 * m + 1.707614701 * s,
      ];
      const encode = (c: number): number => {
        const clamped = Math.min(1, Math.max(0, c));
        const v = clamped <= 0.0031308 ? 12.92 * clamped : 1.055 * clamped ** (1 / 2.4) - 0.055;
        return Math.round(v * 255);
      };
      return [encode(lin[0]), encode(lin[1]), encode(lin[2]), alpha];
    }

    const num = (token: string): number =>
      token.endsWith('%') ? Number(token.slice(0, -1)) / 100 : Number(token);

    function parseColor(input: string): Rgba | null {
      const value = (input || '').trim().toLowerCase();
      if (value === '' || value === 'transparent' || value === 'none') return [0, 0, 0, 0];
      const parts = (inner: string): string[] => inner.split(/[\s,/]+/).filter((p) => p !== '');
      let m = /^rgba?\(([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        const channel = (t: string): number => (t.endsWith('%') ? (Number(t.slice(0, -1)) * 255) / 100 : Number(t));
        return [channel(p[0]), channel(p[1]), channel(p[2]), p.length > 3 ? num(p[3]) : 1];
      }
      m = /^color\(srgb\s+([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        return [num(p[0]) * 255, num(p[1]) * 255, num(p[2]) * 255, p.length > 3 ? num(p[3]) : 1];
      }
      m = /^oklab\(([^)]*)\)$/.exec(value);
      if (m) {
        const p = parts(m[1]);
        if (p.length < 3) return null;
        return oklabToRgb(num(p[0]), Number(p[1]), Number(p[2]), p.length > 3 ? num(p[3]) : 1);
      }
      return null;
    }

    function over(top: Rgba, bottom: Rgba): Rgba {
      const a = top[3] + bottom[3] * (1 - top[3]);
      if (a === 0) return [0, 0, 0, 0];
      const mix = (i: number): number => (top[i] * top[3] + bottom[i] * bottom[3] * (1 - top[3])) / a;
      return [mix(0), mix(1), mix(2), a];
    }

    function luminance(c: Rgba): number {
      const channel = (v: number): number => {
        const s = Math.min(1, Math.max(0, v / 255));
        return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
      };
      return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]);
    }

    function ratio(a: Rgba, b: Rgba): number {
      const la = luminance(a);
      const lb = luminance(b);
      return (Math.max(la, lb) + 0.05) / (Math.min(la, lb) + 0.05);
    }

    function describe(node: Element): string {
      const testid = node.getAttribute('data-testid') ?? node.closest('[data-testid]')?.getAttribute('data-testid');
      const cls = typeof node.className === 'string' && node.className !== '' ? `.${node.className.trim().split(/\s+/).join('.')}` : '';
      return `${node.tagName.toLowerCase()}${cls}${testid ? ` [${testid}]` : ''}`;
    }

    function backgroundBehind(node: Element): Rgba | null {
      const layers: Rgba[] = [];
      let current: Element | null = node;
      while (current !== null) {
        const style = getComputedStyle(current);
        if (style.backgroundImage !== 'none') return null;
        const parsed = parseColor(style.backgroundColor);
        if (parsed === null) return null;
        if (parsed[3] > 0) {
          layers.push(parsed);
          if (parsed[3] >= 0.999) break;
        }
        current = current.parentElement;
      }
      let result: Rgba = [255, 255, 255, 1];
      for (let i = layers.length - 1; i >= 0; i -= 1) result = over(layers[i], result);
      return result;
    }

    const controls = Array.from(document.querySelectorAll('button, input, select, textarea'));
    for (const control of controls) {
      const withCheck = control as Element & {
        checkVisibility?: (options?: { checkVisibilityCSS?: boolean; checkOpacity?: boolean }) => boolean;
      };
      if (typeof withCheck.checkVisibility === 'function' && !withCheck.checkVisibility({ checkVisibilityCSS: true, checkOpacity: true })) {
        continue;
      }
      const style = getComputedStyle(control);
      const behind = backgroundBehind(control.parentElement ?? control);
      if (behind === null) {
        unreadable.push({ what: describe(control), value: 'background behind this control could not be resolved' });
        continue;
      }

      const candidates: { ratio: number; from: string }[] = [];

      const own = parseColor(style.backgroundColor);
      if (own === null) {
        unreadable.push({ what: describe(control), value: style.backgroundColor });
        continue;
      }
      if (own[3] > 0) candidates.push({ ratio: ratio(over(own, behind), behind), from: `fill ${style.backgroundColor}` });

      // Per side: a control bordered on one edge only is still bordered, and a
      // control whose top border is invisible is not excused by its left one.
      const sides: [string, string, string, string][] = [
        ['top', style.borderTopWidth, style.borderTopStyle, style.borderTopColor],
        ['right', style.borderRightWidth, style.borderRightStyle, style.borderRightColor],
        ['bottom', style.borderBottomWidth, style.borderBottomStyle, style.borderBottomColor],
        ['left', style.borderLeftWidth, style.borderLeftStyle, style.borderLeftColor],
      ];
      for (const [side, width, lineStyle, colour] of sides) {
        if (parseFloat(width) <= 0 || lineStyle === 'none' || lineStyle === 'hidden') continue;
        const parsed = parseColor(colour);
        if (parsed === null) {
          unreadable.push({ what: `${describe(control)} border-${side}`, value: colour });
          continue;
        }
        if (parsed[3] <= 0) continue;
        candidates.push({ ratio: ratio(over(parsed, behind), behind), from: `border-${side} ${colour}` });
      }

      if (candidates.length === 0) {
        // No fill and no painted border: nothing identifies this control visually.
        failures.push({ what: describe(control), best: 1, from: 'no fill and no painted border', against: `rgb(${behind.slice(0, 3).map((c) => Math.round(c)).join(' ')})` });
        continue;
      }

      measured += 1;
      const best = candidates.reduce((a, b) => (a.ratio >= b.ratio ? a : b));
      if (best.ratio + 0.005 < 3) {
        failures.push({
          what: describe(control),
          best: Math.round(best.ratio * 100) / 100,
          from: best.from,
          against: `rgb(${behind.slice(0, 3).map((c) => Math.round(c)).join(' ')})`,
        });
      }
    }

    return { failures, unreadable, measured };
  });
}

// ---------------------------------------------------------------------------
// oracle 4 — reflow (WCAG 1.4.10), which axe also does not implement
// ---------------------------------------------------------------------------

/**
 * Assert the document does not scroll sideways, and name what widened it when
 * it does.
 *
 * This is the check this page most needs. It paints 64-nibble field elements and
 * 768-nibble Fp12 elements, seven-column vector tables and side-by-side panels,
 * and every one of those is a way to push a 380px viewport wider than itself.
 * `.hex` wraps with `word-break: break-all` and every table sits in its own
 * `.table-wrap` scroller for exactly that reason; this is what makes those
 * measurements rather than intentions.
 *
 * The offenders are reported by element so a failure says what to fix, not just
 * that something is wrong.
 */
async function expectNoHorizontalOverflow(page: Page, label: string): Promise<void> {
  const result = await page.evaluate(() => {
    const viewport = document.documentElement.clientWidth;
    const offenders: { what: string; right: number; width: number }[] = [];
    for (const node of Array.from(document.querySelectorAll('body *'))) {
      const rect = node.getBoundingClientRect();
      if (rect.width === 0 && rect.height === 0) continue;
      // Only elements that are themselves too wide, or that stick out past the
      // right edge. An element inside a .table-wrap scroller is allowed to be
      // wider than the viewport — that is what the scroller is for — so it is
      // excluded here and asserted separately by expectTablesAreScrollable.
      const scroller = node.parentElement?.closest('.table-wrap');
      if (scroller !== null && scroller !== undefined) continue;
      if (rect.right > viewport + 1 || rect.width > viewport + 1) {
        const testid = node.closest('[data-testid]')?.getAttribute('data-testid') ?? '';
        offenders.push({
          what: `${node.tagName.toLowerCase()}${testid ? ` [${testid}]` : ''}`,
          right: Math.round(rect.right),
          width: Math.round(rect.width),
        });
      }
    }
    return {
      viewport,
      documentScrollWidth: document.documentElement.scrollWidth,
      bodyScrollWidth: document.body.scrollWidth,
      offenders: offenders.slice(0, 12),
    };
  });

  const detail =
    `${label}: viewport ${result.viewport}px, documentElement.scrollWidth ${result.documentScrollWidth}px, `
    + `body.scrollWidth ${result.bodyScrollWidth}px\n`
    + result.offenders.map((o) => `  ${o.what} right=${o.right} width=${o.width}`).join('\n');

  expect(result.documentScrollWidth, detail).toBeLessThanOrEqual(result.viewport);
  expect(result.bodyScrollWidth, detail).toBeLessThanOrEqual(result.viewport);
  expect(result.offenders, detail).toEqual([]);
}

/**
 * Every table must live inside its own scrollable, keyboard-reachable wrapper.
 *
 * A table that is merely allowed to overflow widens the page; one inside an
 * `overflow-x: auto` box does not. And a scrollable box a keyboard cannot reach
 * is a WCAG 2.1.1 failure in its own right — axe reports it as
 * `scrollable-region-focusable`, which is how `.table-wrap` came to carry
 * `tabindex="0"` and a name. Asserted here so a wrapper that loses either one
 * fails on the structure rather than waiting for the scroller to be needed.
 */
async function expectTablesAreScrollable(page: Page): Promise<void> {
  const bad = await page.evaluate(() =>
    Array.from(document.querySelectorAll('table'))
      .map((table) => {
        const wrap = table.closest('.table-wrap');
        const testid = table.getAttribute('data-testid') ?? '(unnamed table)';
        if (wrap === null) return `${testid}: not inside a .table-wrap`;
        const style = getComputedStyle(wrap);
        if (!['auto', 'scroll'].includes(style.overflowX)) return `${testid}: wrapper overflow-x is ${style.overflowX}`;
        if (wrap.getAttribute('tabindex') !== '0') return `${testid}: wrapper is not keyboard reachable`;
        const named = wrap.getAttribute('aria-label') ?? wrap.getAttribute('aria-labelledby');
        if (named === null || named.trim() === '') return `${testid}: scrollable wrapper has no accessible name`;
        return null;
      })
      .filter((entry): entry is string => entry !== null),
  );
  expect(bad, bad.join('\n')).toEqual([]);
}

// ---------------------------------------------------------------------------
// oracle 5 — document structure and theme
// ---------------------------------------------------------------------------

/**
 * Exactly one `h1`, and no level skipped on the way down.
 *
 * axe's `heading-order` is a best-practice rule and is NOT in the WCAG tag set
 * this gate runs, so without this the outline would go unchecked. The page's
 * intended shape is h1 (the lab) > h2 (each pane) > h3 (each section of a pane)
 * > h4 (each box inside a section), and a skip is what happens when a pane grows
 * a box before it grows the heading above it.
 */
async function expectHeadingOutline(page: Page): Promise<void> {
  const outline = await page.evaluate(() =>
    Array.from(document.querySelectorAll('h1, h2, h3, h4, h5, h6'))
      .filter((heading) => {
        const withCheck = heading as Element & { checkVisibility?: (o?: { checkVisibilityCSS?: boolean }) => boolean };
        return typeof withCheck.checkVisibility === 'function'
          ? withCheck.checkVisibility({ checkVisibilityCSS: true })
          : true;
      })
      .map((heading) => ({ level: Number(heading.tagName.slice(1)), text: (heading.textContent ?? '').trim().slice(0, 50) })),
  );

  const h1s = outline.filter((entry) => entry.level === 1);
  expect(h1s.map((entry) => entry.text), `expected exactly one h1, found ${h1s.length}`).toHaveLength(1);
  expect(outline[0]?.level, 'the first heading on the page is not the h1').toBe(1);

  const skips: string[] = [];
  for (let i = 1; i < outline.length; i += 1) {
    if (outline[i].level > outline[i - 1].level + 1) {
      skips.push(`h${outline[i - 1].level} "${outline[i - 1].text}" -> h${outline[i].level} "${outline[i].text}"`);
    }
  }
  expect(skips, `heading levels skip:\n${skips.join('\n')}`).toEqual([]);
}

/**
 * The theme resolves dark and no theme control renders anywhere.
 *
 * The fleet removed its toggle because the stored choice pinned returning
 * visitors to a light palette this lab does not have. Two things are asserted,
 * because they fail separately: the RESOLVED theme (a `data-theme` that
 * disagrees with the stylesheet is not caught by reading the attribute alone,
 * so the painted background is checked too), and the absence of any control that
 * would change it.
 *
 * The control check looks past the known ids as well: `styles.css` carries a
 * `display: none !important` suppression rule for legacy toggles, so a toggle
 * that came back would be present but unrendered, and a check that only queried
 * the selectors would report it either way. Here a matching element fails if it
 * exists at all, and any button whose accessible name is about the theme fails
 * if it renders.
 */
async function expectDarkAndNoThemeControl(page: Page): Promise<void> {
  const state = await page.evaluate(() => {
    const known = '#cl-theme-toggle, #theme-toggle, #themeToggle, .theme-toggle, .theme-toggle-btn, [data-theme-toggle]';
    const nameLooksLikeTheme = /theme|dark mode|light mode/i;
    const rendered = Array.from(document.querySelectorAll('button, a, input, select, [role="switch"], [role="button"]'))
      .filter((node) => {
        const name = `${node.getAttribute('aria-label') ?? ''} ${node.textContent ?? ''} ${node.getAttribute('title') ?? ''}`;
        if (!nameLooksLikeTheme.test(name)) return false;
        const withCheck = node as Element & { checkVisibility?: (o?: { checkVisibilityCSS?: boolean }) => boolean };
        return typeof withCheck.checkVisibility === 'function' ? withCheck.checkVisibility({ checkVisibilityCSS: true }) : true;
      })
      .map((node) => `${node.tagName.toLowerCase()}: ${(node.textContent ?? '').trim().slice(0, 40)}`);
    return {
      attribute: document.documentElement.getAttribute('data-theme'),
      colorScheme: getComputedStyle(document.documentElement).colorScheme,
      htmlBackground: getComputedStyle(document.documentElement).backgroundColor,
      bodyBackground: getComputedStyle(document.body).backgroundColor,
      knownToggles: document.querySelectorAll(known).length,
      rendered,
    };
  });

  expect(state.attribute, 'the theme is not pinned dark on <html>').toBe('dark');
  expect(state.colorScheme, 'the resolved color-scheme is not dark').toContain('dark');

  // The resolved paint, not just the attribute: a data-theme that disagrees with
  // the stylesheet would still read "dark" above.
  const darkEnough = (value: string): boolean => {
    const channels = (/rgba?\(([^)]*)\)/.exec(value)?.[1] ?? '')
      .split(/[\s,/]+/)
      .filter((part) => part !== '')
      .slice(0, 3)
      .map(Number);
    if (channels.length < 3) return false;
    return (channels[0] + channels[1] + channels[2]) / 3 < 96;
  };
  expect(darkEnough(state.htmlBackground), `<html> paints ${state.htmlBackground}, which is not a dark ground`).toBe(true);
  expect(darkEnough(state.bodyBackground), `<body> paints ${state.bodyBackground}, which is not a dark ground`).toBe(true);

  expect(state.knownToggles, 'a legacy theme toggle element is back in the DOM').toBe(0);
  expect(state.rendered, `a theme control renders: ${state.rendered.join(', ')}`).toEqual([]);
}

// ---------------------------------------------------------------------------
// the composite scan
// ---------------------------------------------------------------------------

/**
 * What one run of the gate measured.
 *
 * Counted per run rather than in a module-level variable, because two tests
 * sharing one counter would let the second inherit the first's total and an
 * assertion on it would be satisfied by work the second test never did.
 */
interface RunTally {
  scans: number;
  textMeasured: number;
  controlsMeasured: number;
  axeChecksPassed: number;
}

function newTally(): RunTally {
  return { scans: 0, textMeasured: 0, controlsMeasured: 0, axeChecksPassed: 0 };
}

/** Everything above, over whatever state the page is currently in. */
async function scan(page: Page, label: string, tally: RunTally): Promise<void> {
  await settle(page);

  const axe = await runAxe(page);
  const formatted = axe.violations
    .map((finding) => `  [${finding.impact}] ${finding.rule}: ${finding.help}\n    ${finding.targets.slice(0, 6).join('\n    ')}`)
    .join('\n');
  expect(axe.violations, `axe WCAG A/AA violations at ${label}:\n${formatted}`).toEqual([]);

  const undecidedElsewhere = axe.incomplete.filter((finding) => !INCOMPLETE_COVERED_BY_OUR_OWN_ORACLE.has(finding.rule));
  expect(
    undecidedElsewhere,
    `axe returned "incomplete" at ${label} for rules nothing else in this gate judges: `
      + `${undecidedElsewhere.map((f) => f.rule).join(', ')}. Either judge them or fail.`,
  ).toEqual([]);

  const contrast = await auditTextContrast(page);
  expect(
    contrast.unreadable,
    `${label}: this gate could not read a colour, so it cannot report the page clean:\n`
      + contrast.unreadable.map((u) => `  ${u.what}: ${u.value} ("${u.text}")`).join('\n'),
  ).toEqual([]);
  expect(
    contrast.failures,
    `${label}: WCAG 1.4.3 text contrast failures:\n`
      + contrast.failures
        .map((f) => `  ${f.what} ${f.ratio}:1 (needs ${f.required}:1) ${f.foreground} on ${f.background} — "${f.text}"`)
        .join('\n'),
  ).toEqual([]);
  // A scan that measured nothing would satisfy every assertion above.
  expect(contrast.measured, `${label}: the contrast oracle measured no text at all`).toBeGreaterThan(50);

  const boundaries = await auditControlBoundaries(page);
  expect(
    boundaries.unreadable,
    `${label}: control boundary colours this gate could not read:\n`
      + boundaries.unreadable.map((u) => `  ${u.what}: ${u.value}`).join('\n'),
  ).toEqual([]);
  expect(
    boundaries.failures,
    `${label}: WCAG 1.4.11 non-text contrast failures:\n`
      + boundaries.failures.map((f) => `  ${f.what} ${f.best}:1 (needs 3:1) from ${f.from} against ${f.against}`).join('\n'),
  ).toEqual([]);
  expect(boundaries.measured, `${label}: the boundary oracle measured no controls at all`).toBeGreaterThan(0);

  await expectNoHorizontalOverflow(page, label);
  await expectTablesAreScrollable(page);
  await expectHeadingOutline(page);
  await expectDarkAndNoThemeControl(page);

  tally.scans += 1;
  tally.axeChecksPassed += axe.passed;
  tally.textMeasured += contrast.measured;
  tally.controlsMeasured += boundaries.measured;
}

// ---------------------------------------------------------------------------
// driving the lab
// ---------------------------------------------------------------------------

function byTestId(page: Page, testid: string): Locator {
  return page.locator(`[data-testid="${testid}"]`);
}

/**
 * Press a named control and wait for the testid its own completion writes.
 *
 * Never a timeout: every exhibit computes through `defer()`, so the only honest
 * completion signal is the content the run produces. A step that names the wrong
 * signal fails loudly here rather than scanning a half-built pane.
 */
async function press(page: Page, control: string, ready: string): Promise<void> {
  await byTestId(page, control).click();
  await expect(byTestId(page, ready), `${control} did not produce ${ready}`).toBeVisible({ timeout: 60_000 });
}

/** Open one disclosure the way a reader does — through its summary. */
async function openDisclosure(page: Page, testid: string): Promise<void> {
  const details = byTestId(page, testid);
  if (await details.evaluate((node) => (node as HTMLDetailsElement).open)) return;
  await details.locator('summary').first().click();
  await expect(details).toHaveAttribute('open', '');
}

/** Select one tab of a tab set, the way a reader does. */
async function selectTab(page: Page, id: string): Promise<void> {
  await byTestId(page, `tab-${id}`).click();
  await expect(byTestId(page, `tab-${id}`)).toHaveAttribute('aria-selected', 'true');
}

/**
 * Open every disclosure in every tab of every tab set.
 *
 * A `<details>` inside an unselected tab panel cannot be clicked, so a single
 * sweep would leave two thirds of pane 3 and half of pane 5 unscanned while
 * reporting that it had opened everything. Each tab is selected in turn and swept.
 */
async function openEveryDisclosureInEveryTab(page: Page): Promise<number> {
  let opened = 0;
  for (const id of ['p3a', 'p3b', 'p3c', 'p5a', 'p5b']) {
    await selectTab(page, id);
    opened += await openEveryDisclosure(page);
  }
  opened += await openEveryDisclosure(page);
  return opened;
}

/**
 * Open every remaining disclosure, by clicking summaries.
 *
 * Looped rather than done in one pass, because several disclosures are nested
 * inside others and a summary inside a closed `<details>` cannot be clicked —
 * which is the point: that is also true of a reader.
 */
async function openEveryDisclosure(page: Page): Promise<number> {
  let opened = 0;
  for (let pass = 0; pass < 6; pass += 1) {
    const shut = page.locator('details:not([open]) > summary');
    const count = await shut.count();
    if (count === 0) break;
    for (let i = count - 1; i >= 0; i -= 1) {
      const summary = shut.nth(i);
      if (!(await summary.isVisible())) continue;
      await summary.click();
      opened += 1;
    }
  }
  return opened;
}

/**
 * Drive the lab through the states it teaches, scanning after each.
 *
 * Scanned in groups rather than after every single click: each scan is a full
 * axe pass plus four arithmetic oracles over the whole document, and a group
 * boundary is drawn where the page's rendering actually changes shape — a new
 * table, a new verdict tone, a newly revealed panel — rather than every time a
 * value inside an existing shape is rewritten.
 */
async function driveAllStates(page: Page, label: string, tally: RunTally): Promise<void> {
  await scan(page, `${label} / arrival — step 1 open, four steps locked`, tally);

  // --- step 1: the SM3 layer, and the seven-column vector table it folds -----
  // The ready signal is the summary PILL, not the table: the table now ships one
  // disclosure away, so a step that waited for it to be visible would be waiting
  // for a click nobody made.
  await press(page, 'p1-run-sm3', 'p1-sm3-status');
  await expect(byTestId(page, 'p1-sm3-failed')).toHaveText(/^0 failed$/);
  await expect(byTestId(page, 'rail-state-extract')).toContainText('ready');
  await scan(page, `${label} / step 1 run, step 2 unlocked`, tally);

  await openDisclosure(page, 'p1-sm3-rows');
  await openDisclosure(page, 'p1-parameter-details');
  await openDisclosure(page, 'p1-identifier-details');
  await scan(page, `${label} / step 1 evidence expanded`, tally);

  // --- step 2: the relation, then the decisive experiment --------------------
  await byTestId(page, 'next-sm3').click();
  await expect(byTestId(page, 'p2-extract')).toBeVisible();
  await expect(byTestId(page, 'done-line-sm3')).toBeVisible();
  await scan(page, `${label} / step 1 collapsed to its one line, step 2 open`, tally);

  await press(page, 'p2-extract', 'p2-questions-table');
  await expect(byTestId(page, 'p2-line-key')).toHaveClass(/is-filled/);
  await expect(byTestId(page, 'p2-extract-verdict')).toContainText('ds_A issued in G1');
  await scan(page, `${label} / step 2 extracted under SM9's own H1`, tally);

  // The altered map: an ALARM verdict beside a table whose rows disagree with
  // each other on purpose, which is a tone this page renders nowhere else.
  await byTestId(page, 'p2-map-altered').check();
  await expect(byTestId(page, 'p2-q-samekey')).toContainText('DIFFERENT key');
  await expect(byTestId(page, 'p2-line-key')).toHaveClass(/is-filled/);
  await scan(page, `${label} / step 2 under an altered identity map`, tally);
  await byTestId(page, 'p2-map-standard').check();
  await expect(byTestId(page, 'p2-line-key')).toHaveClass(/is-filled/);

  // A second extraction, on the other side of the mirror.
  await byTestId(page, 'p2-identity').fill('Bob');
  await byTestId(page, 'p2-hid').selectOption('3');
  await byTestId(page, 'p2-master').selectOption('encryption');
  await press(page, 'p2-extract', 'p2-questions-table');
  await expect(byTestId(page, 'p2-extract-verdict')).toContainText('de_B issued in G2');
  await scan(page, `${label} / step 2 encryption key for Bob at hid 0x03`, tally);

  // The t1 = 0 refusal: an alarm verdict, which is a rendering no other state
  // on this page produces.
  await openDisclosure(page, 'p2-t1zero-details');
  await press(page, 'p2-force-t1zero', 'p2-rekey-outcome');
  await expect(byTestId(page, 'p2-rekey-outcome')).toHaveText('MASTER-KEY-REGENERATION-REQUIRED');
  await scan(page, `${label} / step 2 t1 = 0 refusal`, tally);

  // Re-extract so step 2 is complete again: the refusal issues no key, so it
  // retires the step and step 3 goes back behind its lock.
  await byTestId(page, 'p2-identity').fill('Alice');
  await byTestId(page, 'p2-hid').selectOption('1');
  await byTestId(page, 'p2-master').selectOption('signature');
  await press(page, 'p2-extract', 'p2-questions-table');
  await expect(byTestId(page, 'rail-state-protocols')).toContainText('ready');

  // --- step 3 act (a): sign, verify, the negatives, and the wrong-H1 case -----
  await byTestId(page, 'next-extract').click();
  await expect(byTestId(page, 'p3a-run')).toBeVisible();
  await press(page, 'p3a-run', 'p3a-verify-status');
  await openDisclosure(page, 'p3a-fresh-details');
  await press(page, 'p3a-fresh-r', 'p3a-fresh-verify-status');
  await scan(page, `${label} / step 3a signed on the pinned r and on a fresh r`, tally);

  await openDisclosure(page, 'p3a-negatives-details');
  await press(page, 'p3a-run-negatives', 'p3a-negatives-table');
  await openDisclosure(page, 'p3a-wrongh1-details');
  await press(page, 'p3a-wrongh1-run', 'p3a-wrongh1-verdict');
  await scan(page, `${label} / step 3a eight must-reject cases and the wrong-H1 acceptance`, tally);

  // --- step 3 act (b): the key exchange, at the annex's hid -------------------
  await selectTab(page, 'p3b');
  await press(page, 'p3b-run', 'p3b-agree');
  await expect(byTestId(page, 'p3b-confirm-bta')).toContainText('confirmed B');
  await scan(page, `${label} / step 3b key exchange at hid 0x03`, tally);

  // --- step 3 act (c): the KEM, then both encryption modes -------------------
  await selectTab(page, 'p3c');
  await press(page, 'p3c-run-kem', 'p3c-kem-badge');
  await scan(page, `${label} / step 3c key encapsulation`, tally);

  await press(page, 'p3c-run-pke', 'p3c-pke-inputs');
  await scan(page, `${label} / step 3c encryption in both modes`, tally);

  // --- step 4: the KGC's two powers, both rendered as alarms ------------------
  await byTestId(page, 'next-protocols').click();
  await expect(byTestId(page, 'p4-run-read')).toBeVisible();
  await press(page, 'p4-run-read', 'p4-read-match');
  await press(page, 'p4-run-sign', 'p4-sign-accepted');
  await scan(page, `${label} / step 4 the KGC reads and signs`, tally);

  // --- step 5 (a): the reused-nonce recovery, then its refusal path -----------
  await byTestId(page, 'next-kgc').click();
  await expect(byTestId(page, 'p5a-run')).toBeVisible();
  // The RESULT is what this act now leads with; the recovery that produced it is
  // one disclosure down. Waiting on a signal inside that disclosure would be
  // waiting for a click nobody made.
  await press(page, 'p5a-run', 'p5a-forged-accepted');
  await scan(page, `${label} / step 5a a forged signature the real verifier accepted`, tally);

  await openDisclosure(page, 'p5a-derivation');
  await expect(byTestId(page, 'p5a-recovered-matches')).toBeVisible();
  await scan(page, `${label} / step 5a the recovery that produced it`, tally);

  await press(page, 'p5a-refusal-run', 'p5a-refusal-reason');
  await scan(page, `${label} / step 5a the recovery refusing a singular system`, tally);

  // --- step 5 (b): the key exchange at BOTH hid values ------------------------
  await selectTab(page, 'p5b');
  await press(page, 'p5b-run', 'p5b-g-identical');
  await expect(byTestId(page, 'p5b-sk-0x03')).toBeVisible();
  await expect(byTestId(page, 'p5b-sk-0x02')).toBeVisible();
  await expect(byTestId(page, 'p5b-literal-verdict')).toBeVisible();
  await scan(page, `${label} / step 5b key exchange at hid 0x03 and hid 0x02`, tally);

  // --- everything open, in the expert surface --------------------------------
  await byTestId(page, 'lab-view-full').check();
  // Two panes with no tab set of their own, so their controls being on screen is
  // evidence the LOCKS are gone rather than evidence about which tab is selected.
  await expect(byTestId(page, 'p1-run-sm3')).toBeVisible();
  await expect(byTestId(page, 'p4-run-read')).toBeVisible();
  const opened = await openEveryDisclosureInEveryTab(page);
  expect(opened, 'no disclosure was opened, so the expanded state was never scanned').toBeGreaterThan(0);
  // Only VISIBLE disclosures can be judged: a `<details>` inside an unselected
  // tab panel is not reachable by a reader either, which is the same fact.
  await expect(page.locator('details:not([open]) > summary:visible')).toHaveCount(0);
  await scan(page, `${label} / full evidence, every disclosure open (${opened} opened)`, tally);

  // And the transcript, which renders a textarea nothing else on the page does.
  await byTestId(page, 'lab-transcript').click();
  await expect(byTestId(page, 'lab-transcript-json')).toBeVisible();
  await scan(page, `${label} / the run transcript rendered`, tally);
}

// ---------------------------------------------------------------------------
// the two runs
// ---------------------------------------------------------------------------

/**
 * Report what the run actually measured, and refuse a run that measured too
 * little.
 *
 * The totals are printed because "0 violations" is the same sentence whether
 * the gate judged fourteen states or scanned an empty container once, and the
 * floors below are what stop the second from reading like the first.
 */
function reportTally(label: string, tally: RunTally): void {
  // eslint-disable-next-line no-console
  console.log(
    `[a11y ${label}] ${tally.scans} states scanned · ${tally.axeChecksPassed} axe rule-checks passed · `
      + `${tally.textMeasured} text runs measured for 1.4.3 · ${tally.controlsMeasured} controls measured for 1.4.11`,
  );
  expect(tally.scans, `${label}: the gate scanned too few states to be judging this lab`).toBeGreaterThanOrEqual(14);
  expect(tally.textMeasured, `${label}: the contrast oracle measured almost nothing`).toBeGreaterThan(1000);
  expect(tally.controlsMeasured, `${label}: the boundary oracle measured almost no controls`).toBeGreaterThan(50);
}

test.describe('WCAG 2.1 A/AA gate over the production build', () => {
  test('desktop width, every driven state', async ({ page }) => {
    test.setTimeout(900_000);
    const tally = newTally();
    const errors = watchPageErrors(page);
    await page.setViewportSize(DESKTOP);
    await boot(page);
    await driveAllStates(page, `dark @${DESKTOP.width}px`, tally);
    expect(errors, `the page reported errors while being scanned:\n${errors.join('\n')}`).toEqual([]);
    reportTally(`dark @${DESKTOP.width}px`, tally);
  });

  test('380px width, every driven state, and no sideways scroll', async ({ page }) => {
    test.setTimeout(900_000);
    const tally = newTally();
    const errors = watchPageErrors(page);
    await page.setViewportSize(NARROW);
    await boot(page);

    // Asserted before anything is driven as well as inside every scan, so a
    // landing page that already overflows is named at the landing page rather
    // than blamed on the first exhibit that runs.
    await expectNoHorizontalOverflow(page, 'dark @380px / before any interaction');

    await driveAllStates(page, `dark @${NARROW.width}px`, tally);
    expect(errors, `the page reported errors while being scanned:\n${errors.join('\n')}`).toEqual([]);
    reportTally(`dark @${NARROW.width}px`, tally);
  });
});
