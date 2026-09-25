# ADR-007: Example-Region Context Engine for Severity Downgrade

## Status

Accepted

## Context

The regex pattern layer applied injection patterns at the *same* severity to
quoted attack text as to a genuine attack. A security-reviewer prompt that
quotes `ignore previous instructions`, a documentation table listing attack
vectors, a fenced `curl … | bash` example, or a source-code string literal
holding a destructive command all matched `INSTR_*` / `DEST_*` / `EXFIL_*` at
`CRITICAL` severity — producing a `BLOCK` verdict on **benign** content.

Evidence (roadmap §1.1, FP-5 / FP-11): a real repository scan produced 2
`BLOCK` files that were false positives, traced to attack examples quoted in
`scripts/security-review.js` and `package.json`. Source code was additionally
scanned at instruction parity, so any string literal containing an imperative
phrase could block.

This is a *context* problem, not a *pattern* problem: the payload is real, but
it is **data** (a quotation, an example, a string value), not an instruction the
agent is expected to follow. The roadmap's global constraint (§2.3) forbids
trading false positives for false negatives — recall on genuine injections
(`samples/ipi-injections/*`, `samples/malicious-skills/*`) must be preserved.

## Decision

Build a per-line **example-region map** in the pattern-matching layer and **cap
the severity** of every finding that *begins inside* an example region at
`EXAMPLE_REGION_SEVERITY_CEILING` (`Severity.MEDIUM`). Findings are **never
dropped, only downgraded**, so the content is still reported and reviewable.

An example region is one of:

| Region | Established by | Scope |
|--------|----------------|-------|
| Fenced code block | A CommonMark fence: a line matching `` ^ {0,3}(`{3,}\|~{3,}) `` that opens a fence — a *backtick* fence's info string must not contain backticks (so `` ```x``` `` is prose, not a fence) — and closes on a same-character run at least as long as the opener, followed only by spaces. **Exempt in agent-instruction files** (see below) | Every line between the opening and closing fence (inclusive) |
| Markdown table | A delimiter row plus the header above and contiguous pipe-bearing rows below | Header, delimiter and body rows |
| Inline code span | Paired backtick runs of equal length (CommonMark rule) | Column span between the backtick runs |
| Cued example list | A label-like example cue (`examples:`, `such as`, `for example`, `e.g.`, `payload:`, `например`, `例`) | Cue line plus following list items / indented continuation |
| Source-code string literal | A `[DOC]` (docstring) or `[STR]` (string value) fragment tag from `extract_comments_and_strings` | The whole fragment line |

The engine is deliberately conservative:

- **Comments are not example regions.** Code comments stay at full severity so
  an injection hidden in a comment (e.g. the miasm `_index.js` campaign) is
  still `CRITICAL`.
- **Content outside a region is unchanged.** An attack on a line adjacent to a
  fenced block keeps `CRITICAL`.
- **Fences are not example regions in agent-instruction files.** An
  `AGENTS.md` / `.cursorrules` / `CLAUDE.md` file *is* the live instruction
  channel: the agent reads and follows fenced content there, so a fence is
  monospace formatting, not a quotation. Capping it would let an attacker
  bypass the deterministic CRITICAL→BLOCK rule (invariant I002) simply by
  wrapping a payload in ```` ``` ````. The other framing (table rows,
  inline-code spans, lists under an "attack examples:" cue) **is** honoured
  there — benign agent prompts legitimately quote attack examples (FP-5), and
  the two cases are statically indistinguishable — but never below review:
  findings capped by framing in an agent-instruction file carry a `framed`
  flag, and confidence fusion **floors such a file's verdict at
  `REVIEW_REQUIRED`** — a fooled "safe" LLM verdict can never turn framed
  instruction-channel content into a silent PASS.
- **Markdown framing never applies to extracted source-code content.** In
  extracted text the `[DOC]`/`[STR]` tags are the only example-region marks:
  a comment cannot cap its own payload by embedding backticks, a fake fence
  or a fake table, and every fragment (including the L009 fallback) is
  labelled per line with a neutralized leading protocol token, so a forged
  `[L..]`/`[DOC]`/`[STR]` prefix can never occupy the label or tag position.
- **Cues must be label-like.** A bare occurrence such as `example.com/payload`
  is not treated as a cue.
- **Skill files are unaffected.** `match_skill_patterns()` does not apply the
  cap, so a fenced `sudo rm -rf /` in a `SKILL.md` remains `CRITICAL`.

The cap composes with the pre-existing non-agent Markdown rule: a finding is
downgraded when the file is a non-agent `.md` file **or** the finding starts in
an example region (with fenced blocks excluded from region detection in
agent-instruction files, per above).

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Mask / drop findings inside example regions** | Fewest results; quiet output | Silent loss of evidence; a genuine injection that looks like an example disappears | Hides evidence — a reviewer can no longer see what was matched |
| **Downgrade the whole file when it "looks like documentation"** | Simple | Over-broad; a real injection anywhere in a long doc is missed; heuristic "looks like" is fragile | Violates the no-recall-loss constraint |
| **Apply injection patterns only to agent-instruction files** | Simple; no region parser | Source-code injections (candidate FP-11) go undetected entirely | Source code is a first-class injection vector; loses real detection |
| **Region map + `MEDIUM` ceiling (chosen)** | Precise; retains evidence; keeps recall (P009); deterministic | More machinery (fence/table/inline/cue/tag parsing); the parser is itself a potential FN source | **Chosen.** Precision at the region level buys the FP fix without silent loss |

## Consequences

### Enables
- **FP-5 / FP-11 resolved**: quoted attack examples in docs, tables, fenced
  blocks and source-code strings no longer produce `BLOCK`.
- **Evidence retained**: downgraded findings still appear at `MEDIUM`, so
  nothing is silently discarded (roadmap §2.1).
- **Recall preserved**: the conservative region definition keeps genuine
  injections at `CRITICAL` (verified by the paired recall guard, ADR-009).

### Constrains
- Requires `code_extractor` to tag string/docstring fragments (`[DOC]` /
  `[STR]`) so the layer can distinguish data from comments.
- Cue detection must stay label-like; over-broad cues would capture ordinary
  prose and create false negatives.
- The ceiling is `MEDIUM`: a quoted example can still reach `REVIEW_REQUIRED`
  but can never produce `CRITICAL`/`BLOCK` on its own.
- Region parsing is line/column based and ReDoS-safe (no backtracking regex on
  the delimiter check).

## Cross-References

- [Pattern Matching](../domains/pattern-matching.md) — invariants P008 / P009 and the "Example Region Handling" section
- [ADR-003: Two-Stage Pipeline](003-two-stage-pipeline.md) — severity feeds the fusion decision
- [ADR-005: Pygments Code Extraction](005-pygments-code-extraction.md) — produces the `[DOC]` / `[STR]` tags this layer consumes
- [Roadmap §1.1 / §3 T1.1](../../docs/development/ipi-check-roadmap.md)
