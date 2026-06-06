# META: Specification System

## Purpose

This directory contains the specification system for **ipi-check** — a SAST scanner that detects indirect prompt injections (OWASP LLM01) in AI agent instruction files and source code.

Specs are the **source of truth** for intended system behavior. Code implements specs; specs do not describe code. When a discrepancy is found, the spec is updated first (via [`vibespec-update`]), then code follows.

## File Organization

```
specs/
├── META.md                  ← This file
├── INDEX.md                 ← Task→spec navigation
├── WORKFLOW.md              ← How to work with specs
│
├── architecture/            ← System-level design
│   ├── system-overview.md
│   └── security-model.md
│
├── domains/                 ← Functional modules
│   ├── file-discovery.md
│   ├── byte-analysis.md
│   ├── pattern-matching.md
│   ├── semantic-heuristics.md
│   ├── llm-classifier.md
│   ├── confidence-fusion.md
│   └── reporting.md
│
├── contracts/               ← External interfaces
│   └── cli-interface.md
│
└── decisions/               ← Architecture Decision Records
    ├── _template.md
    ├── 001-python-language.md
    ├── 002-sarif-format.md
    ├── 003-two-stage-pipeline.md
    ├── 004-litellm-provider.md
    └── 005-pygments-code-extraction.md
```

## Spec Types and Templates

### Architecture Spec (`architecture/*.md`)

Documents system-level design: layer hierarchy, data flow, cross-cutting concerns.

**Sections (in order):**
1. `# Title` — component name
2. `## Purpose` — what problem this architecture solves
3. `## Diagram` — ASCII diagram of the structure
4. `## Layers / Components` — description of each part
5. `## Data Flow` — how data moves through the system
6. `## Invariants` — rules that must never be violated
7. `## Anti-Patterns` — common mistakes to avoid
8. `## Cross-References` — links to related specs

### Domain Spec (`domains/*.md`)

Documents a functional module: its responsibility, data types, behavior, and boundaries.

**Sections (in order):**
1. `# Title` — module name
2. `## Responsibility` — single-sentence purpose
3. `## Input` — data this module receives (types, format, source)
4. `## Output` — data this module produces (types, format, consumers)
5. `## Behavior` — step-by-step happy path
6. `## Edge Cases` — boundary conditions and how they are handled
7. `## Configuration Constants` — named constants governing behavior
8. `## Dependencies` — other modules this module calls or imports
9. `## Invariants` — rules that must hold before/after execution
10. `## Cross-References` — links to related specs

### Contract Spec (`contracts/*.md`)

Documents an external interface: CLI, API, file format, or protocol.

**Sections (in order):**
1. `# Title` — interface name
2. `## Purpose` — what the interface exposes
3. `## Schema / Signature` — exact format (arguments, flags, types)
4. `## Behavior` — what happens for each valid input combination
5. `## Error Handling` — error codes, messages, exit codes
6. `## Examples` — concrete usage examples
7. `## Invariants` — guarantees the interface must uphold
8. `## Breaking Change Checklist` — what constitutes a breaking change
9. `## Cross-References` — links to related specs

### ADR (`decisions/NNN-title.md`)

Documents an architectural decision: context, options, rationale, consequences.

**Sections (in order):**
1. `# ADR-NNN: Title`
2. `## Status` — Proposed | Accepted | Deprecated | Superseded
3. `## Context` — what problem we are solving and why
4. `## Decision` — what we decided
5. `## Alternatives Considered` — table of options with pros/cons
6. `## Consequences` — what this decision enables and constrains
7. `## Cross-References` — links to related specs and ADRs

## Conventions

### Writing Style
- **Affirmative invariants**: "The scanner MUST process files in byte mode" — not "Don't process files in text mode"
- **No passive voice**: "The CLI parses arguments" — not "Arguments are parsed by the CLI"
- **No future tense**: "The module returns a list" — not "The module will return a list"
- **Concrete over abstract**: "Returns a `List[Finding]`" — not "Returns findings"

### Cross-References
- Within specs: `[Module Name](../domains/file-name.md)` for relative links
- External: `[OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)`
- Never use bare URLs

### Update Rules
1. When implementation changes a spec-documented behavior → run [`vibespec-update`]
2. When adding a new module → run [`vibespec-create`]
3. When specs and code diverge → run [`vibespec-check`]
4. Always update `INDEX.md` when adding or removing spec files

### No-Go
- Do NOT create specs that mirror code structure 1:1 — spec domains are conceptual, not file-system-based
- Do NOT include implementation details (specific algorithms, line numbers, variable names) unless they define a contract
- Do NOT duplicate information across specs — cross-reference instead
