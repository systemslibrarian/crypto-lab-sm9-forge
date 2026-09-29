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

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * An SVG element built with PRESENTATION attributes (`fill`, `stroke`,
 * `font-size`), which the CSP permits, rather than a `style` attribute, which it
 * does not. Colours are `currentColor` throughout so the diagrams inherit the
 * theme tokens from whatever class wraps them instead of hard-coding a palette
 * this file does not own.
 */
export function svgEl(
  tag: string,
  attrs: Record<string, string> = {},
  children: (Element | string)[] = [],
): SVGElement {
  const node = document.createElementNS(SVG_NS, tag);
  for (const [name, value] of Object.entries(attrs)) node.setAttribute(name, value);
  for (const child of children) {
    node.appendChild(typeof child === 'string' ? document.createTextNode(child) : child);
  }
  return node;
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

export interface StepItem {
  label: string;
  value: Child;
  testid?: string;
}

export function stepList(items: StepItem[], testid?: string): HTMLElement {
  const list = el('ul', { class: 'steps', testid });
  for (const item of items) {
    list.appendChild(
      el('li', {}, [
        el('span', { class: 'step-label', text: item.label }),
        el('span', { class: 'step-val', testid: item.testid }, [item.value]),
      ]),
    );
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
