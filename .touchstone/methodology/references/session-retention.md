# Session-artifact retention

`TOUCHSTONE.md` § Long-running session reliability points to this reference. A completed session's working
artifacts under the artifact root (`TOUCHSTONE.md` § Configuration) — its `<topic>` plan, its
`logs/<topic>/`, its `ext-review/<topic>/` — otherwise accumulate without bound over a
checkout's life. Retire them under a fail-closed safety predicate, as a pass **distinct
from** the plan-delete-on-clean-step-7 gate (which fires before the deliverable is
committed). Only those per-topic subtrees are ever deletable; `TOUCHSTONE.md` § Configuration
states that retention-safety boundary. The predicate has TWO modes:

- **Same-session self-clean** (runs only AFTER the user has committed the deliverable):
  delete this session's `<topic>` plan / `logs/<topic>/` / `ext-review/<topic>/` when ALL
  hold — (1) **durable**: the deliverable's actual commit exists in history (not merely a
  clean tree) AND (no upstream configured, OR pushed to upstream) — when no remote exists
  "committed" is the strongest available durability and is the correct bar; (2) the
  dilemma open-set is empty (`TOUCHSTONE.md` § A deferred dilemma blocks termination); (3) the
  command in-flight set is empty; and (4) review close-out is proven under the path's
  review regime. On a round-block path, the topic's implementation-review state
  has no newer incomplete tail and its newest complete block records every
  expected arm converged or unavailable-skipped. In a still-live machinery-free
  same session, use the equivalent in-context clean-close-out proof. After a
  restart that lost record-free facts, or on any ambiguity, fail closed. No
  content-age term: the durable record is the committed change,
  not the gitignored logs.
- **Cross-session backlog sweep**: a later session may retire a PRIOR topic's artefacts
  under a weaker predicate — the topic is not the current live session AND has an
  identifiable committed deliverable — and only ever **PROPOSES** a delete set for user
  go/no-go, never auto-deletes (deletion of gitignored artefacts is unrecoverable). Fail
  closed on any uncertainty (retain).

Retention **never resets or truncates** the marker files: the state/dilemma records are
append-only and already inert once all their keys are terminal (a fresh run appends new
keys), and the consult-evidence record is a survival record a later phase still reads.
The retention pass READS the command + dilemma families only to gate a delete and writes no
marker. It reads them at the three fixed marker paths, via the record contracts in
`TOUCHSTONE.md` § Long-running session reliability and § A deferred dilemma blocks
termination. It is an out-of-loop reader, never the termination gate: reading
`.touchstone/.session-state.md` in this pass does not make it termination evidence.
