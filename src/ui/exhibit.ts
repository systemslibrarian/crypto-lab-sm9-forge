/**
 * The contract between an exhibit and the guided shell that sequences it.
 *
 * WHY THE PANES RETURN A RESET AND NOT JUST A ROOT. The shell can hide a pane
 * and it can scroll to one, but it cannot un-compute what the pane has already
 * printed. A verdict is a claim about an input, so when the learner goes back
 * and changes an upstream input — or presses Reset lab — every downstream
 * verdict has to disappear rather than sit there describing a state the page no
 * longer holds. Only the pane knows which of its own hosts hold verdicts, so the
 * pane hands back the closure that empties them.
 *
 * `complete` is the other half. The shell must not decide for itself when an
 * exhibit has been performed; "the button was clicked" is not the same claim as
 * "the computation finished and agreed". Each pane calls `onComplete` when its
 * own headline act has produced a real result, and the shell unlocks the next
 * step on that signal and nothing else.
 */
export interface Exhibit {
  /** The pane's own root <section>, mounted by the shell. */
  root: HTMLElement;
  /** Empty every verdict and result this pane has printed, back to pending. */
  reset: () => void;
}

/**
 * What the shell hands a pane at build time.
 *
 * `announce` is a shared polite live region rather than one per pane: several
 * panes finish inside the same task, and a screen reader given five competing
 * live regions reads whichever won the race. One region, written in order.
 */
export interface ExhibitHost {
  /**
   * Called by the pane when its headline act has produced a real result, with
   * the one line the step earned — the line the shell shows once the step is
   * collapsed. The pane writes it from its own measured totals, never from a
   * constant, so a collapsed step cannot claim more than it computed.
   */
  onComplete: (summary: string) => void;
  /** Called by the pane when an upstream input changed and its result is stale. */
  onStale: () => void;
  /** Say something once, politely, in the shell's single live region. */
  announce: (message: string) => void;
}

/** A host that does nothing, for a pane built outside the shell (unit tests). */
export const NO_HOST: ExhibitHost = {
  onComplete: (_summary: string) => {},
  onStale: () => {},
  announce: () => {},
};
