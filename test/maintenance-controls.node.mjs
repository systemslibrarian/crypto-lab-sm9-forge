import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const root = new URL('../', import.meta.url);
const workflow = readFileSync(new URL('.github/workflows/deploy.yml', root), 'utf8');
const packageJson = JSON.parse(readFileSync(new URL('package.json', root), 'utf8'));

function job(name) {
  const match = workflow.match(new RegExp(`\\n  ${name}:\\n[\\s\\S]*?(?=\\n  [a-z][a-z0-9-]*:\\n|$)`));
  assert.ok(match, `missing ${name} job`);
  return match[0];
}

test('pull-request builds cannot mint Pages credentials', () => {
  const workflowHeader = workflow.slice(0, workflow.indexOf('\njobs:'));
  assert.match(workflowHeader, /permissions:\n  contents: read\n/);
  assert.doesNotMatch(workflowHeader, /pages: write|id-token: write/);

  const build = job('build');
  assert.doesNotMatch(build, /pages: write|id-token: write/);

  const deploy = job('deploy');
  assert.match(deploy, /permissions:\n      contents: read\n      pages: write\n      id-token: write\n/);
});

test('Pages-only steps cannot run for pull requests', () => {
  assert.doesNotMatch(workflow, /actions\/configure-pages/);
  assert.match(
    workflow,
    /- name: Upload Pages artifact\n        if: github\.event_name != 'pull_request'\n        uses:/,
  );
  assert.match(job('deploy'), /if: github\.event_name != 'pull_request'/);
});

test('every action is pinned to an immutable commit', () => {
  const actions = [...workflow.matchAll(/^\s*-\s+uses:\s+([^@\s]+)@([^\s]+)/gm)];
  assert.ok(actions.length > 0, 'workflow has no actions');
  for (const [, action, reference] of actions) {
    assert.match(reference, /^[0-9a-f]{40}$/, `${action} is not commit-pinned`);
  }
});

test('the post-merge deployment dispatch stays direct and fail-closed', () => {
  const autoMerge = job('dependabot-auto-merge');
  assert.doesNotMatch(autoMerge, /dependabot\/fetch-metadata/);
  assert.match(autoMerge, /gh workflow run deploy\.yml --repo "\$GITHUB_REPOSITORY" --ref main/);
  assert.doesNotMatch(autoMerge, /gh workflow run[^\n]*(?:\|\|\s*true|continue-on-error)/);
});

test('the build path runs this maintenance gate', () => {
  assert.equal(packageJson.scripts['test:maintenance'], 'node --test test/maintenance-controls.node.mjs');
  assert.match(packageJson.scripts.build, /npm run test:maintenance/);
});
