# INDEX: Specification Navigation

## Task → Spec Table

Find the right spec for your task:

| Task | Spec File |
|------|-----------|
| Understand the overall system | [System Overview](architecture/system-overview.md) |
| Understand security boundaries | [Security Model](architecture/security-model.md) |
| Add/modify file discovery rules | [File Discovery](domains/file-discovery.md) |
| Add new byte-level signatures | [Byte-Level Analysis](domains/byte-analysis.md) |
| Add new regex injection patterns | [Pattern Matching](domains/pattern-matching.md) |
| Tune heuristic thresholds | [Semantic Heuristics](domains/semantic-heuristics.md) |
| Modify LLM classifier behavior | [LLM Classifier](domains/llm-classifier.md) |
| Change verdict fusion logic | [Confidence Fusion](domains/confidence-fusion.md) |
| Change SARIF output format | [Reporting](domains/reporting.md) |
| Add/modify CLI arguments | [CLI Interface](contracts/cli-interface.md) |
| Understand architectural decisions | [ADR Index](#architecture-decision-records) |
| Understand spec system conventions | [META](META.md) |
| Learn how to work with specs | [WORKFLOW](WORKFLOW.md) |

## Dependency Graph

```
┌─────────────────────────────────────────────────────────────────────┐
│                         SPEC DEPENDENCIES                            │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  architecture/                                                      │
│  ├── system-overview.md ──── (depends on all domain specs)          │
│  └── security-model.md ──── (depends on byte-analysis, llm-classifier, reporting) │
│                                                                     │
│  domains/                                                           │
│  ├── file-discovery.md ──── (no dependencies)                       │
│  ├── byte-analysis.md ───── (depends on file-discovery)             │
│  ├── pattern-matching.md ── (depends on file-discovery, byte-analysis) │
│  ├── semantic-heuristics.md (depends on file-discovery, byte-analysis) │
│  ├── llm-classifier.md ──── (depends on file-discovery, byte-analysis) │
│  ├── confidence-fusion.md ─ (depends on byte-analysis, pattern-matching, │
│  │                            semantic-heuristics, llm-classifier)  │
│  └── reporting.md ───────── (depends on confidence-fusion)          │
│                                                                     │
│  contracts/                                                         │
│  └── cli-interface.md ───── (depends on system-overview,            │
│                               llm-classifier, reporting)            │
│                                                                     │
│  decisions/                                                         │
│  ├── 001-python-language.md  (depends on system-overview, cli-interface) │
│  ├── 002-sarif-format.md     (depends on reporting, cli-interface)  │
│  ├── 003-two-stage-pipeline.md (depends on system-overview, security-model, │
│  │                               llm-classifier, confidence-fusion) │
│  ├── 004-litellm-provider.md (depends on llm-classifier, cli-interface) │
│  └── 005-pygments-code-extraction.md (depends on llm-classifier,         │
│       file-discovery, 004-litellm-provider)                               │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## Directory Listing

### Meta
- [META.md](META.md) — Spec system metadata: templates, conventions, update rules
- [INDEX.md](INDEX.md) — This file: task navigation and dependency graph
- [WORKFLOW.md](WORKFLOW.md) — How to work with specs: creating, updating, reviewing

### Architecture
- [System Overview](architecture/system-overview.md) — High-level architecture, pipeline stages, data flow, invariants
- [Security Model](architecture/security-model.md) — Threat model, attack vectors, defense mechanisms, trust boundaries

### Domains
- [File Discovery](domains/file-discovery.md) — Layer 1: discovering AI instruction files and source code
- [Byte-Level Analysis](domains/byte-analysis.md) — Layer 2: detecting hidden content at byte level
- [Pattern Matching](domains/pattern-matching.md) — Layer 3: regex-based injection phrase detection
- [Semantic Heuristics](domains/semantic-heuristics.md) — Layer 4: entropy, invisible ratio, instruction density
- [LLM Classifier](domains/llm-classifier.md) — Case 2: sanitization + LiteLLM classification
- [Confidence Fusion](domains/confidence-fusion.md) — Case 2: merging static + LLM verdicts
- [Reporting](domains/reporting.md) — Layer 5: SARIF v2.1.0 output generation

### Contracts
- [CLI Interface](contracts/cli-interface.md) — Command-line arguments, env expansion, exit codes, examples

### Architecture Decision Records
- [ADR-001: Python Language](decisions/001-python-language.md) — Why Python 3.12+
- [ADR-002: SARIF Format](decisions/002-sarif-format.md) — Why SARIF v2.1.0
- [ADR-003: Two-Stage Pipeline](decisions/003-two-stage-pipeline.md) — Why static-then-LLM
- [ADR-004: LiteLLM Provider](decisions/004-litellm-provider.md) — Why LiteLLM as unified provider
- [ADR-005: Pygments Code Extraction](decisions/005-pygments-code-extraction.md) — Why Pygments tokenization for code file preprocessing

### Templates
- [ADR Template](decisions/_template.md) — Template for new Architecture Decision Records
