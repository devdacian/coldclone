# Skill-improvement strategies

This is the **"what to change" companion** to the Touchstone process in `TOUCHSTONE.md`.
`TOUCHSTONE.md` governs *how* you vet a change (consult, plan, review loops,
evidence-backed dispositions). This file catalogs *what kind of change* actually
fixes a recurring failure in a skill — strategies distilled from watching skills'
agents miss, skip, or mishandle the same thing across many runs.

Read this when your task is **improving an existing skill** — especially when an
eval, a test, or repeated real use shows the skill's agents persistently failing
the same way and "strengthening the wording" hasn't worked.

The meta-rule under all of it:

> Most skill bugs are not fixed by saying the same thing louder. They are fixed by
> changing the *class* of the instruction — its placement, its format, its
> structure, or which agent carries it. **When adding more content doesn't change
> behavior, change the form.**

Two postures follow from that rule:

- **Strengthen before you add.** When generalizing or fixing, prefer sharpening an
  instruction that already exists over bolting on a new one. A skill accretes
  contradictions and dead weight when every fix is an addition; often the right
  change is to make an existing clause land harder (better placement, format, or
  structure), not to write another one beside it.
- **Pruning is a successful outcome, not a loss.** Removing a stale, redundant, or
  never-followed instruction is an improvement — leaner instructions get followed
  more reliably. Do not measure a cycle by how much it added; a cycle that
  net-*removes* content and changes behavior for the better is a win.

Every change you derive from this guide still goes through the `TOUCHSTONE.md` review
loop. These strategies tell you *what* to try; the loop verifies it actually worked
and didn't break a sibling.

## Start by characterizing the failure class, not the instance

When a skill persistently misses or mishandles something:

1. **Name the class, not the instance.** Identify the general failure ("the agent
   confirms a result, then talks itself out of acting on it"; "the agent reads files
   sequentially and runs out of budget"), not the one symptom.
2. **Extract a generalizable principle** — the check, the invariant, the *why* —
   that applies to any input with the same shape, not just the example that exposed
   it.
3. **Verify generalizability before adding.** "Check whether the approval can be set
   on a sentinel address" is general; "check whether `_doMixSwap` approves
   `_ETH_ADDRESS_`" is overfitting. If the addition only catches the one example,
   it is an answer key, not a skill improvement.
4. **Place the knowledge where the agent naturally encounters the input** — not
   where it taxonomically "belongs." Ask: which agent, during which step, is looking
   at the thing this check applies to? That is where the check goes.
5. **Keep additions lean.** A 3-line clause that changes behavior beats a 30-line
   explanation that gets skimmed. Extract the actionable check; leave the long
   worked example in a reference file.

## Where knowledge goes (placement)

- **Put new knowledge in the always-loaded instructions, not a selectively-loaded
  catalog.** A concept buried in a reference file the agent only sees if it happens
  to look there does almost no work; the same concept as a clause in the file the
  agent loads on every relevant run fires every time. Treat numbered or
  selectively-loaded catalogs as **read-only reference** — update them to fix an
  existing entry, not to grow new knowledge the agent won't reliably load. The
  exception is a reference file the skill *explicitly tells an agent to load* as its
  whole instructions: that file is a live surface, so new content there does reach
  the agent. The discriminator is whether something routes the agent to load the
  file, not where the file sits.
- **Abstract in always-loaded instructions; concrete in reference files.** A worked
  example in the always-loaded methodology should use role-generic names
  (`CallerContract`, `A <= B`, `_paired()`) so applying it to a new input takes the
  same work as applying it to the example. Reserve concrete, real-world, named
  examples for selectively-loaded reference files. **The failure this prevents:** if
  you improve a skill by pasting the exact thing it just missed — verbatim, with
  real names — into the always-loaded methodology, every future eval on that same
  input now passes on *recall*, not on the skill generalizing. A concrete example in
  always-loaded methodology is an answer key; abstract it. (The only reliable way to
  catch this contamination is to check whether the methodology now names the same
  identifiers the test's expected answer lists.)
- **Put an instruction at the point of *action*, not the point of *definition*.** An
  instruction placed where the data is *created* is often ignored; the same
  instruction placed where the data is *consumed* — where the agent is actively
  doing the task — is followed. When a correctly-worded instruction is ignored, move
  it to where the action happens before you reword it again.

## Change the format when more content doesn't help

- **Procedural steps over prose.** Prose describes ("check every pair"); a numbered
  procedure directs ("1. List the pairs. 2. For each, run the test. 3. Record per
  pair."). Agents process numbered steps as sequential checkpoints that are harder
  to skip than a paragraph absorbed as general awareness. When several rounds of
  *adding content* haven't changed behavior, convert the prose to a procedure.
- **Mechanical calculations over abstract reasoning.** When an agent identifies the
  right mechanism but reasons about it backwards, replace the abstract description
  with a numbered calculation ("1. minimum cost to reach the boundary? 2.
  extractable at the boundary? 3. is 2 > 1?"). The same guidance restructured as a
  step-by-step calculation often succeeds where the abstract form failed.
- **Anti-intuition guards.** When an agent overrides its own literal, step-by-step
  analysis with general-domain intuition ("this feels safe / unlikely"), add an
  explicit guard — "do not let general intuition override the literal reading; read
  it as written" — paired with a short worked example of the correct reasoning to
  anchor it.
- **Concrete triggers over conceptual checks.** Tell the agent the specific pattern
  to look for while reading ("look for the X shape") instead of a conceptual
  instruction ("consider whether X could happen"). Triggers act as attention
  anchors. Caveat: an agent may not run a search *tool* just because it is told to —
  for cross-cutting discovery, prefer pre-computing (below) over a search
  instruction.
- **Completeness gates with counts.** When an agent finds some items and stops, add
  a count-based self-check at the end of the step ("in scope: X; checked: Y; if Y <
  X, go back"). A mismatched count is self-evidently incomplete. Say *why*
  completeness matters for that step — an agent that understands the stakes is more
  motivated to finish.

## Make the unwanted behavior impossible (structure)

- **Structural fix over instruction fix.** When an instruction is ignored despite
  escalating wording ("paste verbatim" → "paste the FULL block" → still
  abbreviated), switch to a structure that makes the unwanted behavior impossible —
  write the data to a file the next step reads directly, instead of asking the agent
  to carry it.
- **Pre-compute deterministic work and inject the result.** When a check needs a
  tool the agent keeps skipping in favor of its natural flow, run the tool upstream
  (deterministically) and put the results in the agent's input. A tool instruction
  competes with the agent's own preference and loses; pre-computing removes the
  competition — the agent doesn't need to be told to search if the answer is already
  in front of it.
- **But minimize the injected context.** Pre-computed analysis has an attention cost
  — every injected line competes with the agent's own investigation for budget.
  Inject conclusions (the sites to check), not full derivations. Over-injecting can
  crowd out something the skill previously caught. Ask: does the agent need the
  derivation, or just the result?
- **Promote a persistently-skipped procedure to its own checkpoint.** When an agent
  finds one issue in some code and treats it as "done", skipping a separate
  prescribed procedure for a different aspect of the same code, give that procedure
  its own heading and explicit anti-short-circuit framing ("run all steps regardless
  of other findings here — finding X does not verify Y"). Structural separation
  makes it a new task, not a continuation of the list where the agent already found
  something.
- **Finding one defect doesn't verify the rest works.** When an agent finds an issue
  and moves on, add the converse check: a defect in X does not mean X's intended
  behavior was tested — after any finding, exercise the normal/intended path too, and
  ask "if this were fixed, would it work correctly?"
- **Make dismissal structurally inadmissible.** When an agent runs a procedure,
  confirms a result, then talks itself out of acting on it via a recurring
  rationalization, do two things: (1) name the specific rationalizations inline and
  reject them, and (2) constrain the output schema at the decision point so the only
  ways to downgrade are structurally checkable (cite a concrete mitigation with
  evidence, or emit a tagged exception from a closed enumeration) — leave no
  free-text third path to narrate around. Inline text alone re-fights the battle the
  agent already learned to override; the schema constraint catches it at the moment
  of writing.
- **Structured discriminator fields for matching.** When automated matching (e.g. an
  eval comparing an agent's output to an expected result) produces false positives —
  a related-but-different result marked correct — add explicit fields that force
  comparison on the dimensions where results differ (actor, direction, root cause),
  with binary gates first and human/LLM judgment reserved for the last gate.
- **Make a deterministic artifact the oracle, and check the agent against it.** When
  an agent emits prose that references things which also exist in a structured,
  mechanically-checkable artifact from an earlier step, don't rely on the agent to
  self-verify — add an output-time parity check that fails on any drift between the
  prose and the artifact. The deterministic artifact is the truth source; the check
  is mechanical (no re-reading needed). Stamp the artifact with a hash of its
  upstream input so a stale artifact — regenerated input that wasn't re-checked —
  fails closed instead of silently passing.
- **Targeted reading with a fallback for budget-bound agents.** When a narrow-scope
  agent burns its budget reading everything sequentially — leaving too little for the
  analysis step where findings are actually made — give it a targeting strategy (read
  the relevant entities first) plus an explicit fallback so it doesn't treat the
  targeted set as exhaustive.

## Multi-agent skills

- **Framing diversity over procedure sharing.** When a failure spans several agents'
  specialties, give each agent its *own* copy of the check written in *that agent's*
  vocabulary — not one shared file they all reference with identical wording. The
  value of multiple agents is diverse framing; three agents reading identical text
  is one agent's analysis repeated three times (same blind spot, triple cost). Share
  *structure* (the step skeleton), not *wording*. Two quick tests: **swap test** —
  if swapping one agent's lens-vocabulary for another's loses no information, the
  framing was decorative (fold to one file, or deepen the framing); **drift test** —
  if the procedure would evolve in different directions for different agents over
  time, it should be per-agent.
- **Role-based framing for a persistent perspective gap.** When agents keep analyzing
  from the wrong perspective despite "also consider X" instructions, create an agent
  whose entire identity *is* the missing perspective. "You are X" cannot be
  deprioritized the way "also consider X" can.
- **A dedicated agent for a persistently-missed class.** When a failure class that
  general agents reliably miss survives every in-place fix, add a narrow extra agent
  whose sole job is that class, with its own attention budget. (Distinct from
  splitting below: splitting divides an existing agent's modes; this adds a
  specialist alongside them.)
- **Don't delegate a phase that must spawn an independent sub-agent.** If a step is
  meant to spawn a fresh arms-length reviewer or specialist, do not delegate the
  whole step to a sub-agent that cannot itself sub-spawn — the required independent
  sub-agent silently collapses to inline, preserving surface progress while
  destroying the independence. The reviewer *appears* to have run but shares the
  caller's context and blind spots. This is the failure mode that most directly
  defeats Touchstone's own arms-length-review premise, so place the warning on the
  step that owns the spawn.
- **Split an agent that must hold contradictory frames.** When one agent is forced
  to carry framings that pull against each other, it does each poorly and silently
  defaults to one. Two common boundaries to split along:
  - **analysis mode** — systematic/exhaustive (build the matrix, check every cell)
    vs. targeted/pattern-based (read, recognize patterns). The agent defaults to the
    natural mode and skips the systematic work; splitting gives the matrix its own
    agent so it becomes un-skippable.
  - **judgment role** — e.g. a single "validation" agent asked to decide validity
    *and* calibrate severity *and* compose the write-up is a skeptic, a rater, and a
    writer wearing one hat; the frames contradict, so it shortchanges most of them.
    Splitting into a disposition agent, a severity-calibration agent, etc. gives each
    one coherent frame and its own attention budget.

  Split by the *frame*, not by topic. After splitting, state what each slimmed agent
  still *owns*, not just what it defers — a bare "X is handled by the other agent"
  cues under-investment in adjacent checks.
- **Bidirectional enumeration against surface-form short-circuits.** When a procedure
  enumerates in one direction and a particular surface form makes the agent skip
  qualifying items, add a complementary pass that reaches the same targets through
  *different* evidence (walk writers vs. walk readers; parse the syntax vs. revisit
  known entities and search their use sites). The two passes catch what either
  misses because their failure modes are uncorrelated. Emit a *separate count field*
  per pass, so "ran pass A, skipped B" is distinguishable from "ran both, found
  nothing in B."

## Discipline before you iterate

- **Verify the failure's premise before deep iteration.** When something is missed
  across many runs despite targeted fixes, and multiple independent analyses all
  conclude "this looks correct," check the *expected* outcome against ground truth
  before iterating further — the description of what should happen may itself be
  imprecise, and the agents may be correctly rejecting a wrong scenario. Construct
  the exact sequence the expected outcome describes; if it doesn't produce the
  claimed effect, fix the expectation, not the skill.
- **Trace behavior, not the definition-site framing.** When you frame a problem by
  where something is *defined* — the first thing a grep surfaces, and especially for
  a duplication or consolidation question — verify the consumers actually run on the
  same input in the same pipeline before accepting that framing. Definition-site
  comments document *intent*; the call-graph documents *behavior*; when they diverge,
  behavior wins. The grep-visible framing is sticky precisely because tracing the
  call sites is more work — so it's exactly where a wrong premise hides.
- **Decide on the evidence in front of the agent, not a substituted counterfactual.**
  A recurring family of failures: a decision is made against something the agent
  *imagined* rather than what it *demonstrated*. Two faces of it — **over-rating**:
  inflating severity/impact to an unprovable worst case (cap it to the
  demonstrated/current value; "unclear impact" caps severity, it does not refute a
  demonstrated defect); and **over-merging**: dropping an item as "duplicate of" /
  "subsumed by" another on a shared *area* without verifying they share the same
  *fix* (distinct remediation = distinct item, even at one location). Seeing one of
  these, suspect the other — same root. Two guards generalize: an agent that doesn't
  hold the evidence for a call (e.g. the other item's body) must not *make* that call
  — defer it to the step that does; and when tightening, **relocate or re-band, never
  silently drop** — a leaner output that quietly loses valid items has just traded
  false positives for false negatives.
- **Anti-skip at phase boundaries.** When an orchestrator rationalizes skipping a
  step ("strong convergence", "comprehensive coverage", "for efficiency"), ban those
  phrases at the transition and reframe: a step that seems redundant after
  productive earlier steps is often the *highest-value remaining* step, because it
  covers the area where issues haven't been found yet.
