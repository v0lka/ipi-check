# System Overview

## Purpose

Define the high-level architecture of **ipi-check** — a two-stage SAST scanner that detects indirect prompt injection payloads in AI agent instruction files and source code, combining deterministic static analysis (Case 1) with LLM-based semantic classification (Case 2). The scanner also performs a parallel **skill security audit** on AI agent skill directories (detected via `SKILL.md` presence), applying skill-specific static patterns and LLM classification to detect malicious behavior such as credential theft, remote execution, and privilege abuse. All findings are output in SARIF format.

## Diagram

```
┌──────────────────────────────────────────────────────────────────┐
│                          CLI ENTRY POINT                          │
│  Arguments: repo_path, llm_base_url?, llm_model?, llm_api_token? │
│  Env expansion: ${VAR_NAME} syntax                               │
└──────────────────────────────┬───────────────────────────────────┘
                               │
                               ▼
┌──────────────────────────────────────────────────────────────────┐
│                       SCANNER PIPELINE                            │
│                                                                  │
│  ┌─────────────────────────────────────┐                         │
│  │ 1. File Discovery                   │                         │
│  │    AI instruction files + source    │                         │
│  │    code + SKILL.md directories      │                         │
│  └───────┬─────────────┬───────────────┘                         │
│          │             │                                          │
│          │  non-skill  │  skill_units                             │
│          ▼             ▼                                          │
│  ┌──────────┐  ┌──────────────────────────┐                      │
│  │ Phase A  │  │ Phase C — Skills Audit    │                      │
│  │ Non-skill│  │ ┌──────────────────────┐  │                      │
│  │ files    │  │ │ C1. Skill Static     │  │                      │
│  │          │  │ │  Per-file byte+pat   │  │                      │
│  │ Layers   │  │ │  + heuristics on     │  │                      │
│  │ 2–7      │  │ │  SKILL.md body       │  │                      │
│  │ (below)  │  │ └──────────┬───────────┘  │                      │
│  │          │  │            │              │                      │
│  │          │  │            ▼              │                      │
│  │          │  │ ┌──────────────────────┐  │                      │
│  │          │  │ │ C2. Skill LLM        │  │                      │
│  │          │  │ │  classify_skill()    │  │                      │
│  │          │  │ │  (optional)          │  │                      │
│  │          │  │ └──────────┬───────────┘  │                      │
│  │          │  │            │              │                      │
│  │          │  │            ▼              │                      │
│  │          │  │ ┌──────────────────────┐  │                      │
│  │          │  │ │ C3. Skill Fusion     │  │                      │
│  │          │  │ │  fuse_skill_verdict()│  │                      │
│  │          │  │ └──────────┬───────────┘  │                      │
│  │          │  │            │              │                      │
│  │          │  └────────────┼──────────────┘                      │
│  │          │               │                                     │
│  └──────────┘               │                                     │
│          │                  │                                     │
│          ▼                  │                                     │
│  ┌────────────────┐         │                                     │
│  │ 2. Byte-Level  │         │                                     │
│  │    Analysis     │         │                                     │
│  └───────┬────────┘         │                                     │
│          │                  │                                     │
│          ▼                  │                                     │
│  ┌──────────────┐ ┌──────────────────┐                           │
│  │ 3. Pattern   │ │ 4. Semantic      │                           │
│  │    Matching  │ │    Heuristics     │                           │
│  └───────┬──────┘ └────────┬─────────┘                           │
│          │                 │                                      │
│          └────────┬────────┘                                      │
│                   │  StaticResult per file                        │
│                   ▼                                               │
│           ┌─────────────────┐                                     │
│           │ CRITICAL?       │──YES──▶ BLOCK (skip LLM)            │
│           └────────┬────────┘                                     │
│                    │ NO                                           │
│                    ▼                                              │
│  ┌────────────────────────────────────┐                           │
│  │ 5. Pre-LLM Sanitization            │                           │
│  └────────────────┬───────────────────┘                           │
│                   │                                               │
│                   ▼                                               │
│  ┌────────────────────────────────────┐                           │
│  │ 6. LLM Classifier (LiteLLM)        │                           │
│  │    Single-file + Batch             │                           │
│  └────────────────┬───────────────────┘                           │
│                   │                                               │
│                   ▼                                               │
│  ┌────────────────────────────────────┐                           │
│  │ 7. Confidence Fusion               │                           │
│  │    → BLOCK|REVIEW_REQUIRED|PASS    │                           │
│  └────────────────┬───────────────────┘                           │
│                   │  FinalVerdict per file                        │
│                   │                                               │
│                   ├───────────────────────────────────────────────┘
│                   │  SkillFinalVerdict per skill
│                   ▼
│  ┌────────────────────────────────────┐
│  │ 8. SARIF Reporter                  │
│  │    Per-file results + per-skill    │
│  │    results → SARIF v2.1.0          │
│  └────────────────┬───────────────────┘
│                   │  .sarif file
└───────────────────┼──────────────────────────────────────────────┘
                    │
                    ▼
              ┌──────────┐
              │ stdout / │
              │   file   │
              └──────────┘
```

## Layers / Components

### Entry Point
A single CLI command (`ipi-check scan <repo_path> [--llm-base-url] [--llm-model] [--llm-api-token]`) that parses arguments with `${ENV_VAR}` expansion and invokes the scanner pipeline. LLM arguments are optional; if omitted, only Case 1 (static analysis) runs. Skill scanning runs automatically whenever `SKILL.md` files are discovered — no additional CLI flags are required.

### Scanner Pipeline
A pipeline with three parallel phases: Phase A (non-skill files, layers 2–7), Phase C (skill audit, layers C1–C3), and a shared final stage.

| Stage | Module | Responsibility |
|-------|--------|----------------|
| 1 | File Discovery | Locate all files: AI instruction, source code, and `SKILL.md` skill directories; split into non-skill files and skill units |
| 2 | Byte-Level Analysis | Detect hidden content via byte-signature matching (non-skill files) |
| 3 | Pattern Matching | Detect injection phrases via regex on normalized text (non-skill); skill files use separate `match_skill_patterns()` |
| 4 | Semantic Heuristics | Compute structural suspicion metrics (entropy, density, invisible ratio) |
| 5 | Pre-LLM Sanitization | Neutralize invisible characters, escape sequences, decode Base64 and ROT13 before LLM input |
| 6 | LLM Classifier | Classify content as safe/suspicious/malicious via LiteLLM (non-skill + batch); separate `classify_skill_with_llm()` for skills |
| 7 | Confidence Fusion | Merge static and LLM results into a final verdict (non-skill + skills via `fuse_skill_verdict()`) |
| 8 | SARIF Reporter | Format all findings as SARIF v2.1.0; includes per-file results and per-skill results |

### Distribution
- **PyPI package**: `pip install ipi-check`, provides `ipi-check` CLI command
- **Docker image**: `docker run ipi-check scan /repo --llm-api-token $TOKEN`

## Data Flow

```
                    ┌─────────────────────────────┐
File Discovery ──▶  │  non_skill_files             │
                    │  skill_units                 │
                    └──────┬───────────┬──────────┘
                           │           │
              Phase A      │           │  Phase C
              (non-skill)  │           │  (skills)
                           ▼           ▼
ByteFindings ──▶ StaticResult     SkillStaticResult
     │                                     │
     ▼                                     ▼
SanitizedContent ──▶ LLMResult    Skill LLMResult
     │                                     │
     └─────────────┬───────────────────────┘
                   ▼
           ┌─────────────────────┐
           │   Confidence Fusion  │
           │   fuse_verdicts()    │
           │   fuse_skill_verdict()│
           └──────────┬──────────┘
                      │
           ┌──────────▼──────────┐
           │  FinalVerdict[]     │
           │  SkillFinalVerdict[]│
           └──────────┬──────────┘
                      │
           ┌──────────▼──────────┐
           │    SARIF Document    │
           └─────────────────────┘
```

1. **File Discovery** produces `(non_skill_files, skill_units)`
2. **Phase A** (non-skill): Each file passes through Byte-Level Analysis, Pattern Matching, Semantic Heuristics → `StaticResult` per file
3. **Phase C** (skills): Each skill passes through skill-specific static analysis (byte + skill patterns on every file, heuristics on SKILL.md body) → `SkillStaticResult` per skill
4. If `StaticResult.severity == CRITICAL` or `SkillStaticResult.aggregate_severity == CRITICAL` → verdict is BLOCK, skip LLM
5. Otherwise, Pre-LLM Sanitization transforms content; LLM Classifier produces `LLMResult` (for non-skill files and skills separately)
6. Confidence Fusion merges both streams: `fuse_verdicts()` for files, `fuse_skill_verdict()` for skills
7. SARIF Reporter consumes both `FinalVerdict[]` and `SkillFinalVerdict[]` to produce a unified SARIF document

## Invariants

- **I001**: The scanner MUST process all files in binary mode — never in text mode — to preserve byte-level information for Layer 2.
- **I002**: If `StaticResult.severity == CRITICAL` or `SkillStaticResult.aggregate_severity == CRITICAL`, the LLM classifier MUST NOT be invoked for that file or skill.
- **I003**: If no LLM arguments are provided, only Case 1 (static analysis) runs; the pipeline MUST skip stages 5–7 and output `FinalVerdict` / `SkillFinalVerdict` based on static analysis alone.
- **I004**: The SARIF output MUST conform to SARIF v2.1.0 specification and include `artifactLocation`, `region` (line/column), `level` (error/warning/note), and `message` with `text` and `markdown` fields.
- **I005**: The LLM classifier system prompt (both `CLASSIFIER_SYSTEM_PROMPT` and `SKILL_CLASSIFIER_SYSTEM_PROMPT`) MUST be immutable — they are security boundaries. Any change to them requires a spec update and security review.
- **I006**: All numeric thresholds (entropy, invisible ratio, instruction density) MUST be defined as named module-level constants, never as magic numbers inline.
- **I007**: The scanner MUST NOT modify any scanned files — it is strictly read-only.
- **I008**: Skill discovery is automatic — when `SKILL.md` is found, the containing directory is treated as a skill unit. The scanner MUST NOT require additional CLI flags to enable skill scanning.
- **I009**: Regular injection patterns (IPI101–109) MUST NOT be applied to skill files (`FileCategory.SKILL`). Skills use a dedicated pattern set (IPI401–411) via `match_skill_patterns()` to avoid false positives from legitimate instructions.

## Anti-Patterns

- **AP001**: Opening files in text mode — this loses raw byte information needed for ANSI/Unicode detection.
- **AP002**: Sending unsanitized file content to the LLM — this can attack the classifier itself.
- **AP003**: Using magic numbers for thresholds — use `ENTROPY_THRESHOLD`, `INVISIBLE_RATIO_THRESHOLD`, etc.
- **AP004**: Hardcoding LLM credentials or URLs — use CLI arguments with env expansion.
- **AP005**: Parallel file processing at the LLM stage without considering API rate limits.

## Cross-References

- [Security Model](security-model.md)
- [File Discovery](../domains/file-discovery.md)
- [Byte-Level Analysis](../domains/byte-analysis.md)
- [Pattern Matching](../domains/pattern-matching.md)
- [Semantic Heuristics](../domains/semantic-heuristics.md)
- [LLM Classifier](../domains/llm-classifier.md)
- [Confidence Fusion](../domains/confidence-fusion.md)
- [Reporting](../domains/reporting.md)
- [CLI Interface](../contracts/cli-interface.md)
- [ADR-003: Two-Stage Pipeline](../decisions/003-two-stage-pipeline.md)
- [Pattern Matching](../domains/pattern-matching.md)
- [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
