/**
 * The Content-Security-Policy hash guard.
 *
 * This page ships `script-src 'self' 'sha256-...'` with no 'unsafe-inline', and the
 * theme pin in <head> is an inline script. Under that policy the browser runs the pin
 * only if its hash is declared. Change ONE byte of that script — a reindent, a reworded
 * comment, a trailing space — and the hash stops matching, the browser silently refuses
 * the script, the theme pin is dead, and nothing else in the suite notices: a checker
 * that verifies the script is PRESENT cannot see that it is not PERMITTED.
 *
 * So this test recomputes every inline script's hash from the file's own bytes on every
 * run, rather than comparing against a constant. It is the check that makes the hash
 * safe to use at all.
 *
 * Adapted from crypto-lab-covert-channel-studio/test/csp.test.js. One deliberate
 * difference: that lab asserts the CSP contains no 'unsafe-inline' anywhere. Here the
 * assertion is scoped to script-src, because a lab whose style-src legitimately needs it
 * would fail the broader form for no reason.
 *
 * Node's built-in test runner and crypto, so it needs no dependency.
 * Run: node --test test/csp.test.js   (wired into `npm test`)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const html = readFileSync(join(here, '..', 'index.html'), 'utf8');

function cspContent() {
  const m = html.match(/<meta\s+http-equiv="Content-Security-Policy"\s+content="([^"]*)"/i);
  assert.ok(m, 'index.html must carry a Content-Security-Policy meta tag');
  return m[1];
}

/** Inline <script> elements only — those with a src attribute are governed by 'self'. */
function inlineScripts() {
  const out = [];
  const re = /<script\b([^>]*)>([\s\S]*?)<\/script>/gi;
  let m;
  while ((m = re.exec(html)) !== null) {
    if (/\bsrc\s*=/i.test(m[1])) continue;
    out.push(m[2]);
  }
  return out;
}

test('every inline script has a matching sha256 declared in script-src', () => {
  const csp = cspContent();
  const scripts = inlineScripts();
  assert.ok(scripts.length > 0, 'expected at least the theme pin to be inline');
  for (const body of scripts) {
    const digest = createHash('sha256').update(body, 'utf8').digest('base64');
    assert.ok(
      csp.includes(`'sha256-${digest}'`),
      `inline script has no declared hash.\n` +
        `  computed: 'sha256-${digest}'\n` +
        `  If you edited the theme pin, put this value in the CSP.\n` +
        `  Until you do, the browser silently refuses to run it and the theme pin is dead.`,
    );
  }
});

test("script-src does not carry 'unsafe-inline'", () => {
  const csp = cspContent();
  const scriptSrc = csp.split(';').find((d) => d.trim().startsWith('script-src')) ?? '';
  assert.ok(
    !scriptSrc.includes('unsafe-inline'),
    "script-src must not use 'unsafe-inline' — that would defeat the hash entirely",
  );
});

test('no inline event handlers anywhere (a hash cannot authorise one)', () => {
  const m = html.match(/<[^>]+\son[a-z]+\s*=/i);
  assert.equal(m, null, `inline event handler found: ${m && m[0]}`);
});

test('the theme pin is present, pins dark, and reads no stored preference', () => {
  const scripts = inlineScripts().join('\n');
  assert.match(scripts, /setAttribute\(\s*'data-theme'\s*,\s*'dark'\s*\)/);
  assert.match(scripts, /localStorage\.setItem\(\s*'theme'\s*,\s*'dark'\s*\)/);
  assert.doesNotMatch(scripts, /getItem|prefers-color-scheme|matchMedia/);
  assert.match(html, /<html[^>]*\sdata-theme="dark"/);
});
