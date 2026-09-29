/**
 * THE GUIDED SHELL — what turns five exhibits into one lab.
 *
 * WHAT WAS WRONG BEFORE. All five panes mounted at once and pane 2 ran its own
 * extraction on load. The page therefore opened with pane 1 saying
 * "pending — not yet run" directly above pane 2 saying "ds_A issued", which is a
 * contradiction the reader has to resolve for themselves, and the headline act —
 * the inversion — had already happened without anybody pressing anything. The
 * first button was 2,003 px down on a desktop and 4,081 px down on a phone.
 *
 * WHAT THIS DOES. One step is expanded at a time. A step unlocks when the step
 * before it has produced a REAL result — not when its button was clicked, which
 * is a different claim — and each pane reports that itself through
 * `ExhibitHost.onComplete`. Completed steps collapse to the one line they
 * earned, with the control to reopen them. Nothing is computed that the reader
 * did not cause.
 *
 * WHY THERE IS AN ESCAPE HATCH. A gated path is right for a first visit and
 * wrong for an expert, a presenter jumping to act four, or anybody who arrived
 * from a link. "Full evidence" unlocks and expands everything at once, and it is
 * one control away at the top of the page. Progressive disclosure that cannot be
 * switched off is just material hidden from the people most likely to check it.
 *
 * WHAT IS NOT PERSISTED. Nothing. No progress, no input, no result reaches
 * localStorage or a URL — the only thing index.html stores is the theme pin.
 * Reloading is a full reset, deliberately: a lab that restored a half-finished
 * run would be restoring verdicts about inputs the reader can no longer see.
 */
import type { Exhibit, ExhibitHost } from './exhibit';
import {
  button,
  detailsEl,
  el,
  liveRegion,
  para,
  replace,
  segmented,
  statusPill,
} from './dom';

export interface StepSpec {
  /** Stable anchor id fragment: `#step-extract`. Presenters link to these. */
  id: string;
  /** The rail's own short word. Five of these have to fit on a phone. */
  short: string;
  /** What the step asks the reader to do, in the imperative. */
  action: string;
  /** Why this step comes before the next one. Shown on the lock panel. */
  unlocks: string;
  build: (host: ExhibitHost) => Exhibit;
}

type StepState = 'locked' | 'ready' | 'done';

interface Step {
  spec: StepSpec;
  index: number;
  exhibit: Exhibit;
  state: StepState;
  /** The one line this step earned, written by the pane when it completed. */
  summary: string;
  section: HTMLElement;
  lockPanel: HTMLElement;
  doneLine: HTMLElement;
  bodyHost: HTMLElement;
  nav: HTMLElement;
  railItem: HTMLElement;
  railState: HTMLElement;
  nextButton: HTMLButtonElement;
}

type View = 'guided' | 'full';

const RAIL_WORD: Record<StepState, { kind: 'ok' | 'info' | 'pending'; word: string }> = {
  done: { kind: 'ok', word: 'done' },
  ready: { kind: 'info', word: 'ready' },
  locked: { kind: 'pending', word: 'locked' },
};

/**
 * Everything the transcript records about one rendered element.
 *
 * The transcript is read off the DOM rather than out of the panes' internals on
 * purpose: what it exports is then exactly what the page claimed, in the state
 * the reader is looking at. A transcript assembled from a parallel copy of the
 * state could disagree with the screen, and the whole reason to export one is to
 * have evidence that cannot.
 */
interface TranscriptEntry {
  testid: string;
  value: string;
}

interface TranscriptStep {
  step: string;
  action: string;
  state: StepState;
  summary: string;
  inputs: TranscriptEntry[];
  verdicts: { testid: string; kind: string; headline: string; why: string }[];
  statuses: { testid: string; kind: string; word: string }[];
  sources: string[];
  values: TranscriptEntry[];
}

function kindOf(node: Element, prefix: string): string {
  for (const name of Array.from(node.classList)) {
    if (name.startsWith(`${prefix}-`)) return name.slice(prefix.length + 1);
  }
  return 'unknown';
}

function testidOf(node: Element): string {
  return node.getAttribute('data-testid') ?? '(untagged)';
}

function trimmed(node: Element | null): string {
  return (node?.textContent ?? '').trim();
}

function transcribeStep(step: Step): TranscriptStep {
  const root = step.exhibit.root;
  const inputs: TranscriptEntry[] = [];
  for (const control of Array.from(root.querySelectorAll('input, select'))) {
    const id = control.getAttribute('data-testid');
    if (id === null) continue;
    const field = control as HTMLInputElement | HTMLSelectElement;
    if (field instanceof HTMLInputElement && field.type === 'radio') {
      if (!field.checked) continue;
    }
    inputs.push({ testid: id, value: field.value });
  }

  return {
    step: step.spec.id,
    action: step.spec.action,
    state: step.state,
    summary: step.summary,
    inputs,
    verdicts: Array.from(root.querySelectorAll('.verdict')).map((node) => ({
      testid: testidOf(node.parentElement ?? node),
      kind: kindOf(node, 'verdict'),
      headline: trimmed(node.querySelector('.verdict-text')),
      why: trimmed(node.querySelector('.verdict-why')),
    })),
    statuses: Array.from(root.querySelectorAll('.status[data-testid]')).map((node) => ({
      testid: testidOf(node),
      kind: kindOf(node, 'status'),
      word: trimmed(node).replace(/^[+x!i-]\s*/, ''),
    })),
    sources: Array.from(new Set(Array.from(root.querySelectorAll('.source-tag')).map((node) => trimmed(node)))),
    // `.relation-slot` as well as `.hex`: the extraction relation tags the SLOT
    // rather than the value inside it, because the slot has to exist and say
    // "pending" before anything has been computed into it.
    values: Array.from(root.querySelectorAll('.hex[data-testid], .relation-slot[data-testid]')).map((node) => ({
      testid: testidOf(node),
      value: trimmed(node),
    })),
  };
}

export function buildLab(
  specs: StepSpec[],
  evidenceLimits: HTMLElement,
  /** The closing note. Mounted after the steps because it is not an act. */
  closing: HTMLElement,
): HTMLElement {
  const live = liveRegion('lab-live');
  const steps: Step[] = [];
  let view: View = 'guided';
  let current = 0;

  const railList = el('ol', { class: 'rail-steps', testid: 'lab-rail-steps' });
  const stepsHost = el('div', { class: 'lab-steps' });

  // ---- the view switch, the reset, and the transcript ---------------------

  const transcriptHost = el('div', { class: 'lab-transcript', testid: 'lab-transcript-host' });

  function jumpTo(index: number, announce: boolean): void {
    current = Math.min(Math.max(index, 0), steps.length - 1);
    paint();
    const target = steps[current];
    target.section.scrollIntoView({ block: 'start', behavior: 'auto' });
    if (announce) live.say(`Step ${current + 1} of ${steps.length}: ${target.spec.action}`);
  }

  /**
   * Write the whole shell's state onto the DOM.
   *
   * One function rather than a mutation per event: the rail, the locks, the
   * collapsed lines and the Back/Next buttons are four views of the same two
   * variables, and four places updating them independently is how a rail ends up
   * claiming a step is locked while its body is on screen.
   */
  function paint(): void {
    for (const step of steps) {
      const expanded = view === 'full' || step.index === current;
      const locked = view === 'guided' && step.state === 'locked';

      step.bodyHost.hidden = locked || !expanded;
      step.lockPanel.hidden = !locked;
      step.doneLine.hidden = locked || expanded;
      // Back/Reset/Next belong to the step you are IN. A locked step's only action
      // is on its lock panel, and a collapsed one's is the Reopen control on its
      // own line — a row of navigation under every step would just be the rail
      // again, five times.
      step.nav.hidden = !expanded || locked;
      // Rewritten on every paint rather than only when a step completes. Written
      // once at completion, the line for a step that became READY but had not been
      // opened still carried the contents it was built with — a "done" pill above
      // an empty summary, which is a step claiming a result it does not have.
      replace(step.doneLine, [collapsedLine(step)]);

      step.section.classList.toggle('is-current', view === 'guided' && step.index === current);
      step.section.classList.toggle('is-locked', locked);
      step.section.classList.toggle('is-done', step.state === 'done');
      step.section.setAttribute('data-state', locked ? 'locked' : step.state);

      // In full-evidence view nothing is locked, so a rail that still read
      // "locked" beside an expanded pane would be the rail contradicting the page.
      const shown: StepState = locked ? 'locked' : step.state === 'locked' ? 'ready' : step.state;
      const word = RAIL_WORD[shown];
      replace(step.railState, [statusPill(word.kind, word.word, `rail-state-${step.spec.id}`)]);
      step.railItem.classList.toggle('is-current', view === 'guided' && step.index === current);
      step.railItem.classList.toggle('is-done', step.state === 'done');
      if (view === 'guided' && step.index === current) {
        step.railItem.setAttribute('aria-current', 'step');
      } else {
        step.railItem.removeAttribute('aria-current');
      }

      // In the guided view Next is a gate: it opens only once this step has a
      // result. In Full evidence nothing is gated and it is pure navigation.
      step.nextButton.disabled = step.index === steps.length - 1
        || (view === 'guided' && step.state !== 'done');
      step.nextButton.textContent = step.index === steps.length - 1
        ? 'This is the last step'
        : `Next — ${steps[step.index + 1].spec.short}`;
    }
  }

  /** Clear this step and every step after it, and relock what it unlocked. */
  function resetFrom(index: number): void {
    for (const step of steps) {
      if (step.index < index) continue;
      step.exhibit.reset();
      step.state = step.index === 0 || steps[step.index - 1].state === 'done' ? 'ready' : 'locked';
      step.summary = '';
    }
    // Walked in order, so `steps[i - 1].state` above is already the post-reset
    // state for every step this loop has reached: only the first cleared step
    // can be `ready`, and everything after it is locked again.
    if (current > index) current = index;
    paint();
  }

  const viewSwitch = segmented(
    'View',
    [
      { value: 'guided', label: 'Guided', hint: 'one step at a time' },
      { value: 'full', label: 'Full evidence', hint: 'everything, unlocked' },
    ],
    'guided',
    (next) => {
      view = next as View;
      paint();
      live.say(
        view === 'full'
          ? 'Full evidence view. Every step is expanded and nothing is locked.'
          : `Guided view. Step ${current + 1} of ${steps.length} is open.`,
      );
    },
    'lab-view',
  );

  const resetLab = button('Reset lab', 'lab-reset', 'secondary');
  resetLab.addEventListener('click', () => {
    resetFrom(0);
    current = 0;
    replace(transcriptHost, []);
    paint();
    steps[0].section.scrollIntoView({ block: 'start', behavior: 'auto' });
    live.say('Lab reset. Every result is cleared and step 1 is the only step open.');
  });

  const copyTranscript = button('Copy run transcript', 'lab-transcript', 'secondary');
  copyTranscript.addEventListener('click', () => {
    const transcript = {
      lab: 'crypto-lab-sm9-forge',
      capturedAt: new Date().toISOString(),
      view,
      note:
        'Read off the rendered page, so every line here is what the page claimed in the state '
        + 'captured. Master private keys appearing below are the ones GM/T 0044.5\'s annexes print; '
        + 'this lab generates no secret of its own.',
      steps: steps.map(transcribeStep),
    };
    const json = JSON.stringify(transcript, null, 2);
    const status = el('div', { testid: 'lab-transcript-status' }, [
      statusPill('info', 'transcript captured — printed below'),
    ]);
    const output = el('textarea', {
      class: 'transcript-json',
      testid: 'lab-transcript-json',
      attrs: { readonly: '', rows: '14', spellcheck: 'false', 'aria-label': 'Run transcript, as JSON' },
    });
    output.value = json;
    replace(transcriptHost, [
      status,
      detailsEl(
        `The transcript for this run (${json.length.toLocaleString('en')} characters of JSON)`,
        [output],
        'lab-transcript-details',
        true,
      ),
    ]);
    // The clipboard is a bonus, never the deliverable. It is unavailable over
    // plain http on a LAN address and refused in some embedded views, and a
    // button whose only outcome is an invisible copy has no way to say it
    // failed — so the JSON is on the page first and the clipboard is attempted
    // second.
    void navigator.clipboard?.writeText(json).then(
      () => replace(status, [statusPill('ok', 'transcript copied to the clipboard, and printed below', 'lab-transcript-copied')]),
      () => replace(status, [statusPill('info', 'the clipboard refused — the transcript is printed below', 'lab-transcript-copied')]),
    );
    live.say('Run transcript captured.');
  });

  // ---- build each step ----------------------------------------------------

  /**
   * The one line a collapsed step shows.
   *
   * A step that is DONE shows the result it earned, in its own measured words. A
   * step that is merely READY shows what it is going to ask you to do — never a
   * completion pill, which would be the rail and the line disagreeing about
   * whether anything has been computed.
   */
  function collapsedLine(step: Step): HTMLElement {
    const done = step.state === 'done';
    const open = button(
      `${done ? 'Reopen' : 'Open'} — ${step.spec.short}`,
      `reopen-${step.spec.id}`,
      'secondary',
    );
    open.addEventListener('click', () => jumpTo(step.index, true));
    // All three states, not two. A locked step's line is hidden behind its lock
    // panel, but it is still IN the document — read by the run transcript and by
    // anything that walks the page — and a hidden element claiming "ready" about a
    // step that is locked is a wrong claim whether or not it is painted.
    const word = RAIL_WORD[step.state];
    return el('div', { class: 'step-done-line' }, [
      statusPill(word.kind, word.word, `collapsed-state-${step.spec.id}`),
      el('span', {
        class: 'step-done-text',
        text: done ? step.summary : step.spec.action,
        testid: `summary-${step.spec.id}`,
      }),
      open,
    ]);
  }

  specs.forEach((spec, index) => {
    const railState = el('span', { class: 'rail-state' });
    const railItem = el('a', {
      class: 'rail-step',
      testid: `rail-${spec.id}`,
      attrs: { href: `#step-${spec.id}` },
    }, [
      el('span', { class: 'rail-num', text: String(index + 1), attrs: { 'aria-hidden': 'true' } }),
      el('span', { class: 'rail-name', text: spec.short }),
      railState,
    ]);
    railItem.addEventListener('click', (event) => {
      event.preventDefault();
      jumpTo(index, true);
    });
    railList.appendChild(el('li', {}, [railItem]));

    const lockPanel = el('div', { class: 'step-lock', testid: `lock-${spec.id}` });
    const doneLine = el('div', { class: 'step-done', testid: `done-line-${spec.id}` });
    const bodyHost = el('div', { class: 'step-body' });
    const nav = el('div', { class: 'step-nav', testid: `nav-${spec.id}` });

    const backButton = button('Back', `back-${spec.id}`, 'secondary');
    backButton.addEventListener('click', () => jumpTo(index - 1, true));
    backButton.disabled = index === 0;
    const resetStep = button('Reset this step', `reset-${spec.id}`, 'secondary');
    resetStep.addEventListener('click', () => {
      resetFrom(index);
      live.say(`Step ${index + 1} reset, and every step after it.`);
    });
    const nextButton = button('Next', `next-${spec.id}`);
    nextButton.addEventListener('click', () => jumpTo(index + 1, true));

    nav.appendChild(el('div', { class: 'step-nav-inner' }, [backButton, resetStep, nextButton]));

    const section = el('section', {
      class: 'lab-step',
      testid: `step-${spec.id}`,
      attrs: { id: `step-${spec.id}`, 'aria-label': `Step ${index + 1} of ${specs.length}: ${spec.action}` },
    }, [lockPanel, doneLine, bodyHost, nav]);

    const step: Step = {
      spec,
      index,
      state: index === 0 ? 'ready' : 'locked',
      summary: '',
      section,
      lockPanel,
      doneLine,
      bodyHost,
      nav,
      railItem,
      railState,
      nextButton,
      // Replaced immediately below; a Step cannot be built before its exhibit
      // and the exhibit's host needs the Step to report into.
      exhibit: { root: el('div'), reset: () => {} },
    };

    const host: ExhibitHost = {
      onComplete: (summary: string) => {
        step.state = 'done';
        step.summary = summary;
        const next = steps[index + 1];
        if (next !== undefined && next.state === 'locked') {
          next.state = 'ready';
          live.say(`Step ${index + 1} complete. Step ${index + 2}, ${next.spec.action}, is now unlocked.`);
        }
        paint();
      },
      onStale: () => {
        // An upstream input changed, so this step's own result no longer
        // describes what is on screen, and neither does anything downstream.
        step.state = index === 0 || steps[index - 1].state === 'done' ? 'ready' : 'locked';
        step.summary = '';
        for (const later of steps.slice(index + 1)) {
          later.exhibit.reset();
          later.state = 'locked';
          later.summary = '';
        }
        if (current > index) current = index;
        paint();
      },
      announce: live.say,
    };

    step.exhibit = spec.build(host);
    bodyHost.appendChild(step.exhibit.root);

    replace(lockPanel, [
      statusPill('pending', 'locked', `lock-pill-${spec.id}`),
      para(spec.unlocks),
      el('div', { class: 'step-lock-actions' }, [(() => {
        const skip = button('Show everything instead', `skip-${spec.id}`, 'secondary');
        skip.addEventListener('click', () => {
          view = 'full';
          viewSwitch.set('full');
          paint();
          live.say('Full evidence view. Every step is expanded and nothing is locked.');
          section.scrollIntoView({ block: 'start', behavior: 'auto' });
        });
        return skip;
      })()]),
    ]);
    steps.push(step);
    stepsHost.appendChild(section);
  });

  // ---- the rail ----------------------------------------------------------

  const rail = el('nav', { class: 'lab-rail', testid: 'lab-rail', attrs: { 'aria-label': 'Lab progress' } }, [
    railList,
    el('div', { class: 'lab-rail-tools' }, [viewSwitch.root, resetLab, copyTranscript]),
  ]);

  const root = el('div', { class: 'lab' }, [
    rail,
    live.root,
    el('div', { class: 'lab-preamble' }, [evidenceLimits, transcriptHost]),
    stepsHost,
    closing,
  ]);

  paint();

  return root;
}
