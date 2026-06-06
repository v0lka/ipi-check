# WORKFLOW: How to Work with Specs

## Purpose

This document describes the workflows for creating, updating, and maintaining specification documents in the ipi-check project. Specs are the **source of truth** for intended system behavior — code follows specs, not the other way around.

## When to Create a Spec

Create a new spec when:
- Adding a new functional module that wasn't previously specified
- Defining a new external interface (CLI argument, API, file format)
- Making an architectural decision that affects multiple modules
- The design document (`docs/development/sast-agents-md-protection.md`) introduces a new concept

Use [`vibespec-create`] to generate the spec from the appropriate template.

## When to Update a Spec

Update an existing spec when:
- Implementation changes documented behavior (the spec was wrong or the behavior evolved)
- A module's input/output types change
- An invariant is added, removed, or modified
- Configuration constants change (thresholds, limits, patterns)

Use [`vibespec-update`] to update the spec while preserving format and cross-references.

## When to Check Specs

Run a spec consistency check when:
- After a major refactoring
- Before a release
- When you suspect code and specs have diverged
- During code review of structural changes

Use [`vibespec-check`] to detect discrepancies and resolve them interactively.

## Adding a New ADR

1. Copy `specs/decisions/_template.md` to `specs/decisions/NNN-title.md` (use the next available number)
2. Fill in all sections: Status, Context, Decision, Alternatives Considered, Consequences
3. Set Status to `Accepted` (ADRs are written after the decision is made)
4. Add cross-references to related specs
5. Update `specs/INDEX.md` — add the new ADR to the "Architecture Decision Records" section
6. Update any specs that are affected by the decision (add cross-references back to the ADR)

## Spec Quality Checklist

Before finalizing any spec, verify:
- [ ] All sections follow the correct [META](META.md) template order
- [ ] All cross-references resolve to existing files (use relative paths)
- [ ] Invariants are stated affirmatively ("MUST do X", not "Don't do Y")
- [ ] No passive voice, no future tense
- [ ] Configuration constants are listed with exact values
- [ ] Edge cases are documented in a table
- [ ] ASCII diagrams render correctly in monospace
- [ ] No implementation details (line numbers, variable names) unless they define a contract

## Typical Task Workflows

### Implementing a New Byte-Level Signature

1. Read [Byte-Level Analysis](domains/byte-analysis.md) — understand existing signatures and severity rules
2. Read [Security Model](architecture/security-model.md) — ensure the new signature doesn't create a vulnerability
3. Add the signature to the spec's `BYTE_SIGNATURES` constant and document its severity in the behavior section
4. Read [Reporting](domains/reporting.md) — add a new `ruleId` if the signature is a new category
5. Update [Pattern Matching](domains/pattern-matching.md) if the new signature affects normalization

### Adding a New CLI Flag

1. Read [CLI Interface](contracts/cli-interface.md) — understand existing arguments and error handling
2. Add the flag to the Options table with type, default, and description
3. Document how it affects the Execution Flow
4. Update the Examples section with usage
5. Check the Breaking Change Checklist — does this change break anything?
6. Update affected domain specs if the flag changes module behavior

### Changing a Fusion Rule

1. Read [Confidence Fusion](domains/confidence-fusion.md) — understand the decision matrix
2. Read [Security Model](architecture/security-model.md) — ensure the change doesn't weaken a defense
3. Update the Decision Matrix table and the reasoning generation logic
4. Verify invariants F001–F005 are still valid
5. Read [LLM Classifier](domains/llm-classifier.md) and [Semantic Heuristics](domains/semantic-heuristics.md) — these produce the inputs to fusion

### Onboarding a New Developer

Recommended reading order for a new contributor:
1. [INDEX](INDEX.md) — get oriented
2. [System Overview](architecture/system-overview.md) — understand the big picture
3. [ADR-003: Two-Stage Pipeline](decisions/003-two-stage-pipeline.md) — understand the core architectural decision
4. Domain specs in pipeline order: [File Discovery](domains/file-discovery.md) → [Byte-Level Analysis](domains/byte-analysis.md) → ... → [Reporting](domains/reporting.md)
5. [CLI Interface](contracts/cli-interface.md) — understand how users invoke the tool
6. [Security Model](architecture/security-model.md) — understand why things are the way they are
