import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';
import ts from 'typescript';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const require = createRequire(path.join(root, 'package.json'));
const compiler = path.join(root, 'node_modules/@typescript/native/bin/tsc');

function compile(source) {
  const directory = mkdtempSync(path.join(tmpdir(), 'sm9-forge-ts7-'));
  try {
    const input = path.join(directory, 'control.ts');
    writeFileSync(input, source);
    return spawnSync(process.execPath, [compiler,
      '--ignoreConfig', '--noEmit', '--strict', '--skipLibCheck', '--target', 'ES2022', input,
    ], { cwd: root, encoding: 'utf8', env: { ...process.env, FORCE_COLOR: '0' } });
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('the build compiler is native 7 while ShangMi peers receive TypeScript 5', () => {
  const native = require('@typescript/native/package.json');
  const api = require('typescript/package.json');
  const sm3 = require('@li0ard/sm3/package.json');
  const sm4 = require('@li0ard/sm4/package.json');
  assert.equal(native.name, 'typescript');
  assert.equal(native.version, '7.0.2');
  assert.equal(api.name, 'typescript');
  assert.equal(api.version, '5.9.3');
  assert.equal(sm3.peerDependencies.typescript, '^5');
  assert.equal(sm4.peerDependencies.typescript, '^5');
  assert.match(execFileSync(process.execPath, [compiler, '--version'], { encoding: 'utf8' }), /^Version 7\.0\.2\s*$/);
  assert.equal(ts.version, '5.9.3');
});

test('the native compiler accepts valid strict TypeScript', () => {
  const result = compile('export const identity = (input: number): number => input;\n');
  assert.equal(result.status, 0, result.stdout + result.stderr);
});

test('the native compiler rejects implicit any and invalid null assignment', () => {
  const result = compile('export function identity(input) { return input; }\nexport const invalid: string = null;\n');
  assert.notEqual(result.status, 0);
  assert.match(result.stdout + result.stderr, /TS7006/);
  assert.match(result.stdout + result.stderr, /TS2322/);
});
