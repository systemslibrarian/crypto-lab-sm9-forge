/**
 * Shared DOM helpers for the five exhibits.
 *
 * WHY THESE EXIST RATHER THAN innerHTML. The page ships a strict CSP with
 * `style-src 'self'` and no `'unsafe-inline'`, so an inline `style` attribute or
 * an injected `<style>` element is refused by the browser with no visible error
 * — the pane simply renders unstyled and nothing says why. Building every node
 * through these helpers means no string of markup is ever assembled, so there is
 * no place for a style attribute to be written by accident, and every visual
 * decision goes through a class that already exists in src/styles.css.
 *
 * THE STATE RULE, encoded here rather than remembered. Colour never carries
 * state alone (WCAG 1.4.1): `statusPill` and `verdict` both take a KIND and a
 * WORD, and each emits a text glyph, the word and the colour class together.
 * There is no way to call them that produces colour on its own. The glyphs are
 * ASCII on purpose — this lab ships no emoji, and a glyph that is a text
 * character is also what a screen reader can read out.
 *
 * `pending` is a first-class kind for the same reason: a value that has not been
 * computed must say so, never show a placeholder number and never show the
 * standard's own figure standing in for a measured one.
 */

/** The five states the stylesheet defines, and the only five anything here uses. */
export type Kind = 'ok' | 'bad' | 'alarm' | 'info' | 'pending';

/** Text glyphs, never emoji. Paired with a word by `statusPill` and `verdict`. */
const GLYPH: Record<Kind, string> = {
  ok: '+',
  bad: 'x',
  alarm: '!',
  info: 'i',
  pending: '-',
};

export type Child = Node | string | null | undefined;

export interface ElOptions {
  /** A class from src/styles.css. Never a style attribute — the CSP refuses those. */
  class?: string;
  text?: string;
  /** Stable hook for the e2e claims suite. */
  testid?: string;
  attrs?: Record<string, string>;
}

export function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  options: ElOptions = {},
  children: Child[] = [],
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (options.class !== undefined) node.className = options.class;
  if (options.text !== undefined) node.textContent = options.text;
  if (options.testid !== undefined) node.setAttribute('data-testid', options.testid);
  if (options.attrs) {
    for (const [name, value] of Object.entries(options.attrs)) node.setAttribute(name, value);
  }
  append(node, children);
  return node;
}

export function append(host: Node, children: Child[]): void {
  for (const child of children) {
    if (child === null || child === undefined) continue;
    host.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
}

/** Empty a node so a re-run replaces its contents rather than appending beside them. */
export function clear(node: Node): void {
  while (node.firstChild) node.removeChild(node.firstChild);
}

export function replace(host: Node, children: Child[]): void {
  clear(host);
  append(host, children);
}

/**
 * WHY THERE IS NO SVG HELPER HERE ANY MORE.
 *
 * The two diagrams in pane 2 were inline SVG over a fixed `viewBox` at
 * `width: 100%`. That is legible on a desktop and illegible on a phone: a
 * 780-unit viewBox painted into 358 CSS pixels scales every label by 0.46, so
 * the 11- and 12-unit labels rendered at roughly 5 to 7 CSS pixels. The
 * accessibility gate measured their CONTRAST correctly and passed them, which is
 * the trap — contrast is not legibility, and text nobody can read is a quality
 * failure no axe rule reports.
 *
 * Both are now HTML, built from `flow` and `tableEl` below. Real text reflows,
 * honours the reader's font size, can be selected, translated and zoomed, and
 * needs no scale arithmetic to stay above 12 pixels. A picture was not what
 * either diagram was carrying; a sequence and a two-by-two were.
 */

/**
 * A pipeline, as an ordered list of the operations that produce each value.
 *
 * Each step names the operation that PRODUCED it rather than the one that
 * follows, so the list reads correctly when it is read out: "ID and hid",
 * "via H1, h1 — a scalar, not a point". The arrow is decoration on top of that
 * sentence, not the thing carrying it.
 */
export interface FlowStep {
  /** The operation that produced this node. Omitted on the first step. */
  op?: string;
  term: string;
  hint?: string;
  testid?: string;
  /** Emit an empty value slot under the term, for a computed value written later. */
  slot?: boolean;
}

export function flow(steps: FlowStep[], testid?: string): HTMLElement {
  const list = el('ol', { class: 'flow', testid });
  for (const step of steps) {
    list.appendChild(
      el('li', { class: 'flow-step', testid: step.testid === undefined ? undefined : `${step.testid}-step` }, [
        step.op === undefined
          ? null
          : el('span', { class: 'flow-op' }, [
              el('span', { class: 'flow-op-glyph', text: '→', attrs: { 'aria-hidden': 'true' } }),
              el('span', { text: step.op }),
            ]),
        el('span', { class: 'flow-term', text: step.term }),
        step.hint === undefined ? null : el('span', { class: 'flow-hint', text: step.hint }),
        step.slot === true ? el('span', { class: 'flow-slot', testid: step.testid }) : null,
      ]),
    );
  }
  return list;
}

/** A figure with its caption below it, so a diagram always says what it shows. */
export function figureEl(caption: string, children: Child[], testid?: string): HTMLElement {
  return el('figure', { class: 'fig', testid }, [...children, el('figcaption', { text: caption })]);
}

/**
 * A one-of-N control as real radio inputs inside a fieldset.
 *
 * Radios rather than toggle buttons because this IS a one-of-N choice, and the
 * browser already implements arrow-key movement, the roving tab stop and the
 * group name for it. The inputs carry `appearance: none` and an explicit border
 * in src/styles.css for a reason the accessibility gate enforces: a UA-painted
 * radio computes to no background and no border, and WCAG 1.4.11 wants 3:1 for
 * the boundary of every control.
 */
export interface Segment {
  value: string;
  label: string;
  hint?: string;
}

let segmentedGroups = 0;

export interface SegmentedControl {
  root: HTMLElement;
  get: () => string;
  set: (value: string) => void;
}

export function segmented(
  legend: string,
  segments: Segment[],
  value: string,
  onChange: (value: string) => void,
  testid?: string,
): SegmentedControl {
  segmentedGroups += 1;
  const name = `seg-${segmentedGroups}`;
  const inputs: HTMLInputElement[] = [];
  const options = segments.map((segment) => {
    const input = el('input', {
      testid: `${testid ?? name}-${segment.value}`,
      attrs: { type: 'radio', name, value: segment.value },
    });
    if (segment.value === value) input.checked = true;
    input.addEventListener('change', () => {
      if (input.checked) onChange(segment.value);
    });
    inputs.push(input);
    return el('label', { class: 'seg-option' }, [
      input,
      el('span', { class: 'seg-body' }, [
        el('span', { class: 'seg-label', text: segment.label }),
        segment.hint === undefined ? null : el('span', { class: 'seg-hint', text: segment.hint }),
      ]),
    ]);
  });

  const root = el('fieldset', { class: 'segmented', testid }, [
    el('legend', { text: legend }),
    el('div', { class: 'seg-options' }, options),
  ]);

  return {
    root,
    get: () => inputs.find((input) => input.checked)?.value ?? value,
    set: (next: string) => {
      for (const input of inputs) input.checked = input.value === next;
    },
  };
}

/**
 * A polite live region, for announcing something the reader did not cause to
 * appear on screen where they are looking — a step unlocking, a reset.
 *
 * `role="status"` plus `aria-live="polite"` rather than an alert: none of these
 * are interruptions, and an assertive region that fires on every completed step
 * is worse than silence.
 */
export function liveRegion(testid: string): { root: HTMLElement; say: (message: string) => void } {
  const root = el('div', {
    class: 'lab-live',
    testid,
    attrs: { role: 'status', 'aria-live': 'polite', 'aria-atomic': 'true' },
  });
  return {
    root,
    say: (message: string) => {
      root.textContent = message;
    },
  };
}

export interface PaneParts {
  root: HTMLElement;
  body: HTMLElement;
}

export function pane(num: string, title: string, sub: string, testid: string): PaneParts {
  const body = el('div', { class: 'pane-body' });
  const root = el('section', { class: 'pane', testid }, [
    el('div', { class: 'pane-head' }, [
      el('span', { class: 'pane-num', text: num }),
      el('h2', { class: 'pane-title', text: title }),
      el('p', { class: 'pane-sub', text: sub }),
    ]),
    body,
  ]);
  return { root, body };
}

/** Glyph + word + colour. There is no call that yields colour alone. */
export function statusPill(kind: Kind, word: string, testid?: string): HTMLElement {
  return el('span', { class: `status status-${kind}`, testid }, [
    el('span', { class: 'glyph', text: GLYPH[kind] }),
    el('span', { text: word }),
  ]);
}

export function verdict(kind: Kind, text: string, why?: string, testid?: string): HTMLElement {
  return el('div', { class: `verdict verdict-${kind}`, testid }, [
    el('span', { class: 'glyph', text: GLYPH[kind] }),
    el('div', {}, [
      el('span', { class: 'verdict-text', text }),
      why === undefined ? null : el('span', { class: 'verdict-why', text: why }),
    ]),
  ]);
}

/** A slot that starts PENDING and is replaced when a real value has been computed. */
export function verdictSlot(testid: string, pendingText = 'pending — nothing has been computed yet'): HTMLElement {
  const host = el('div', { testid });
  host.appendChild(verdict('pending', pendingText));
  return host;
}

export function setVerdict(host: HTMLElement, kind: Kind, text: string, why?: string): void {
  replace(host, [verdict(kind, text, why)]);
}

export type KvEntry = [string, Child];

export function kv(entries: KvEntry[], testid?: string): HTMLElement {
  const list = el('dl', { class: 'kv', testid });
  for (const [term, value] of entries) {
    list.appendChild(el('dt', { text: term }));
    list.appendChild(el('dd', {}, [value]));
  }
  return list;
}

/** A monospace value block. Long values wrap; they are never silently truncated. */
export function hexBlock(value: string, testid?: string): HTMLElement {
  return el('code', { class: 'hex', text: value, testid });
}

/**
 * A 768-hex-character Fp12 element folded behind a disclosure.
 *
 * Only values of that order are hidden. Everything a reader is being asked to
 * compare — h, S, SK, K, a confirmation tag — stays visible, because a claim the
 * page makes should not need a click to check.
 */
export function hexDetails(summaryText: string, value: string, testid?: string): HTMLElement {
  return el('details', {}, [
    el('summary', { text: `${summaryText} (${value.length} hex characters)` }),
    hexBlock(value, testid),
  ]);
}

export function detailsEl(
  summaryText: string,
  children: Child[],
  testid?: string,
  open = false,
): HTMLElement {
  return el(
    'details',
    { testid, attrs: open ? { open: '' } : {} },
    [el('summary', { text: summaryText }), ...children],
  );
}

export function note(children: Child[], alarm = false, testid?: string): HTMLElement {
  return el('p', { class: alarm ? 'note note-alarm' : 'note', testid }, children);
}

export function sourceTag(text: string, testid?: string): HTMLElement {
  return el('span', { class: 'source-tag', text, testid });
}

export function box(title: string, children: Child[], testid?: string): HTMLElement {
  return el('div', { class: 'box', testid }, [el('h4', { text: title }), ...children]);
}

export function sideBySide(children: Child[], testid?: string): HTMLElement {
  return el('div', { class: 'side-by-side', testid }, children);
}

export function controls(children: Child[], testid?: string): HTMLElement {
  return el('div', { class: 'controls', testid }, children);
}

export function para(text: string, testid?: string): HTMLElement {
  return el('p', { text, testid });
}

export function heading(text: string, testid?: string): HTMLElement {
  return el('h3', { text, testid });
}

export type Row = Child[];

/**
 * A table inside its own horizontally scrollable wrapper.
 *
 * The wrapper is FOCUSABLE and NAMED, which is not decoration. `.table-wrap`
 * carries `overflow-x: auto`, so at phone width these become scrollable regions,
 * and a scrollable region a keyboard cannot reach is a WCAG 2.1.1 failure — axe
 * reports it as `scrollable-region-focusable`, which is exactly how it was found
 * here. `tabindex="0"` makes it reachable and the label says what the reader has
 * arrived at; a `role="group"` rather than `role="region"` keeps a page with a
 * dozen tables from filling the landmark list.
 */
export function tableEl(headers: string[], rows: Row[], testid?: string, label = 'data table'): HTMLElement {
  const head = el('tr', {}, headers.map((h) => el('th', { text: h, attrs: { scope: 'col' } })));
  const bodyRows = rows.map((cells) => el('tr', {}, cells.map((cell) => el('td', {}, [cell]))));
  return el(
    'div',
    { class: 'table-wrap', attrs: { tabindex: '0', role: 'group', 'aria-label': label } },
    [el('table', { testid }, [el('thead', {}, [head]), el('tbody', {}, bodyRows)])],
  );
}

/** A byte-equality badge: glyph, word and colour, never colour alone. */
export function equality(
  equal: boolean,
  okWord = 'byte-identical',
  badWord = 'differs',
  testid?: string,
): HTMLElement {
  return statusPill(equal ? 'ok' : 'bad', equal ? `${okWord}` : `${badWord}`, testid);
}

/** An inline match mark for use inside a table cell, where a pill is too heavy. */
export function matchMark(equal: boolean, testid?: string): HTMLElement {
  return el('span', {
    class: equal ? 'match' : 'nomatch',
    text: equal ? '+ match' : 'x differs',
    testid,
  });
}

export function labelled(text: string, control: HTMLElement): HTMLElement {
  return el('label', {}, [el('span', { text }), control]);
}

export function textInput(value: string, testid: string, size = 24): HTMLInputElement {
  const input = el('input', { testid, attrs: { type: 'text', value, size: String(size) } });
  input.value = value;
  return input;
}

export interface SelectOption {
  value: string;
  label: string;
}

export function selectInput(options: SelectOption[], value: string, testid: string): HTMLSelectElement {
  const select = el('select', { testid });
  for (const option of options) {
    select.appendChild(el('option', { text: option.label, attrs: { value: option.value } }));
  }
  select.value = value;
  return select;
}

export function button(text: string, testid: string, variant?: 'secondary' | 'danger'): HTMLButtonElement {
  return el('button', {
    text,
    testid,
    class: variant === undefined ? '' : variant,
    attrs: { type: 'button' },
  });
}

/**
 * Show a "computing" state, then do the work after the browser has painted it.
 *
 * Every run on this page is synchronous elliptic-curve and pairing arithmetic on
 * the main thread. A pairing is roughly 9 ms here, so the longest exhibit is
 * well under a second — but it still blocks paint, and a button that appears to
 * do nothing for half a second is indistinguishable from a broken one. Two
 * frames of delay is the cheapest way to make the pending-to-computing-to-result
 * sequence actually visible.
 */
export function defer(work: () => void): void {
  requestAnimationFrame(() => {
    setTimeout(work, 0);
  });
}

/** Render a UTF-8 identity or message from BYTES, so nothing is echoed from an input. */
export function decodeUtf8(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

export function encodeUtf8(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

/** A one-byte hid as the standard writes it. */
export function hidHex(hid: number): string {
  return `0x${hid.toString(16).padStart(2, '0')}`;
}

/**
 * A tab set, implementing the ARIA tabs pattern by hand.
 *
 * WHY TABS RATHER THAN THREE DISCLOSURES. Pane 3's three acts are peers — one
 * signature, one key exchange, one KEM — and as stacked `<details>` the second
 * and third read as appendices to the first, reachable only by scrolling past two
 * kilobytes of Fp12. As tabs they are three equals, each one click away, and only
 * one occupies the page at a time.
 *
 * The keyboard contract is the pattern's, not the browser's, because a
 * `role="tab"` is not a button any more as far as assistive technology is
 * concerned: exactly one tab is in the tab order at a time (`tabindex`), and
 * left/right/home/end move between them and move focus with the selection. A tab
 * set that leaves every tab tabbable is a very common and very wrong
 * implementation of this pattern.
 */
export interface TabSpec {
  id: string;
  label: string;
  panel: HTMLElement;
}

export interface TabSet {
  root: HTMLElement;
  select: (id: string) => void;
  ids: string[];
}

export function tabs(label: string, specs: TabSpec[], testid?: string): TabSet {
  const buttons: HTMLButtonElement[] = [];
  const panels: HTMLElement[] = [];

  function select(id: string, moveFocus = false): void {
    specs.forEach((spec, index) => {
      const chosen = spec.id === id;
      buttons[index].setAttribute('aria-selected', String(chosen));
      buttons[index].setAttribute('tabindex', chosen ? '0' : '-1');
      buttons[index].classList.toggle('is-selected', chosen);
      panels[index].hidden = !chosen;
      if (chosen && moveFocus) buttons[index].focus();
    });
  }

  specs.forEach((spec, index) => {
    const tab = el('button', {
      class: 'tab',
      testid: `tab-${spec.id}`,
      text: spec.label,
      attrs: {
        type: 'button',
        role: 'tab',
        id: `tab-${spec.id}`,
        'aria-controls': `tabpanel-${spec.id}`,
        'aria-selected': 'false',
        tabindex: '-1',
      },
    });
    tab.addEventListener('click', () => select(spec.id));
    tab.addEventListener('keydown', (event) => {
      const step = event.key === 'ArrowRight' ? 1 : event.key === 'ArrowLeft' ? -1 : 0;
      if (step !== 0) {
        event.preventDefault();
        select(specs[(index + step + specs.length) % specs.length].id, true);
        return;
      }
      if (event.key === 'Home') {
        event.preventDefault();
        select(specs[0].id, true);
      }
      if (event.key === 'End') {
        event.preventDefault();
        select(specs[specs.length - 1].id, true);
      }
    });
    buttons.push(tab);

    spec.panel.setAttribute('role', 'tabpanel');
    spec.panel.setAttribute('id', `tabpanel-${spec.id}`);
    spec.panel.setAttribute('aria-labelledby', `tab-${spec.id}`);
    // A tab panel holding focusable content needs to be reachable itself, so a
    // keyboard reader arriving from the tab lands in the panel rather than past it.
    spec.panel.setAttribute('tabindex', '0');
    spec.panel.classList.add('tabpanel');
    panels.push(spec.panel);
  });

  const root = el('div', { class: 'tabset', testid }, [
    el('div', { class: 'tablist', attrs: { role: 'tablist', 'aria-label': label } }, buttons),
    ...panels,
  ]);

  select(specs[0].id);
  return { root, select, ids: specs.map((spec) => spec.id) };
}
