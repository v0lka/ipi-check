# System Overview

## Purpose

Define the high-level architecture of **ipi-check** — a two-stage SAST scanner that detects indirect prompt injection payloads in AI agent instruction files and source code, combining deterministic static analysis (Case 1) with LLM-based semantic classification (Case 2), and outputs findings in SARIF format.

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
│  ┌────────────────┐                                              │
│  │ 1. File        │  Discover AI instruction files + source code │
│  │    Discovery    │                                              │
│  └───────┬────────┘                                              │
│          │  List[FilePath]                                       │
│          ▼                                                       │
│  ┌────────────────┐                                              │
│  │ 2. Byte-Level  │  Detect hidden content at byte level         │
│  │    Analysis     │  (ANSI, Unicode tags, bidi, zero-width)     │
│  └───────┬────────┘                                              │
│          │  ByteFindings per file                                │
│          ▼                                                       │
│  ┌────────────────┐    ┌────────────────────┐                    │
│  │ 3. Pattern     │    │ 4. Semantic        │                    │
│  │    Matching    │    │    Heuristics       │                    │
│  │  (regex on     │    │  (entropy, density, │                    │
│  │   normalized   │    │   invisible ratio)  │                    │
│  │   text)        │    │                     │                    │
│  └───────┬────────┘    └─────────┬──────────┘                    │
│          │                       │                                │
│          └───────────┬───────────┘                                │
│                      │  StaticResult per file                     │
│                      ▼                                            │
│              ┌─────────────────┐                                  │
│              │ CRITICAL?       │──YES──▶ BLOCK (skip LLM)         │
│              └────────┬────────┘                                  │
│                       │ NO                                        │
│                       ▼                                           │
│  ┌────────────────────────────────────┐                           │
│  │ 5. Pre-LLM Sanitization            │  (Case 2 entry)          │
│  │    Replace invisible chars,        │                           │
│  │    ANSI escapes, decode Base64     │                           │
│  └────────────────┬───────────────────┘                           │
│                   │  SanitizedContent                             │
│                   ▼                                               │
│  ┌────────────────────────────────────┐                           │
│  │ 6. LLM Classifier (LiteLLM)        │                           │
│  │    Structured JSON output:         │                           │
│  │    verdict + confidence + findings │                           │
│  └────────────────┬───────────────────┘                           │
│                   │  LLMResult                                    │
│                   ▼                                               │
│  ┌────────────────────────────────────┐                           │
│  │ 7. Confidence Fusion               │                           │
│  │    Merge StaticResult + LLMResult  │                           │
│  │    → BLOCK | REVIEW_REQUIRED | PASS│                           │
│  └────────────────┬───────────────────┘                           │
│                   │  FinalVerdict per file                        │
│                   ▼                                               │
│  ┌────────────────────────────────────┐                           │
│  │ 8. SARIF Reporter                  │                           │
│  │    Generate SARIF v2.1.0 output    │                           │
│  └────────────────┬───────────────────┘                           │
│                   │  .sarif file                                  │
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
A single CLI command (`ipi-check scan <repo_path> [--llm-base-url] [--llm-model] [--llm-api-token]`) that parses arguments with `${ENV_VAR}` expansion and invokes the scanner pipeline. LLM arguments are optional; if omitted, only Case 1 (static analysis) runs.

### Scanner Pipeline
A sequential pipeline of 8 processing stages. Each stage receives output from the previous stage and transforms it.

| Stage | Module | Responsibility |
|-------|--------|----------------|
| 1 | File Discovery | Locate all files that may contain prompt injection payloads |
| 2 | Byte-Level Analysis | Detect hidden content via byte-signature matching |
| 3 | Pattern Matching | Detect known injection phrases via regex on normalized text |
| 4 | Semantic Heuristics | Compute structural suspicion metrics (entropy, density, invisible ratio) |
| 5 | Pre-LLM Sanitization | Neutralize invisible characters, escape sequences, decode Base64 and ROT13 before LLM input |
| 6 | LLM Classifier | Classify content as safe/suspicious/malicious via LiteLLM |
| 7 | Confidence Fusion | Merge static and LLM results into a final verdict |
| 8 | SARIF Reporter | Format all findings as SARIF v2.1.0 |

### Distribution
- **PyPI package**: `pip install ipi-check`, provides `ipi-check` CLI command
- **Docker image**: `docker run ipi-check scan /repo --llm-api-token $TOKEN`

## Data Flow

```
FilePath ──▶ ByteFindings ──▶ StaticResult ──▶ SanitizedContent ──▶ LLMResult
                                                    │
                                                    ▼
                                        ┌─────────────────────┐
                                        │   Confidence Fusion  │
                                        └──────────┬──────────┘
                                                   │
                                        ┌──────────▼──────────┐
                                        │    FinalVerdict[]    │
                                        └──────────┬──────────┘
                                                   │
                                        ┌──────────▼──────────┐
                                        │    SARIF Document    │
                                        └─────────────────────┘
```

1. **File Discovery** produces `List[FilePath]`
2. Each file passes through **Byte-Level Analysis** producing `ByteFindings`
3. **Pattern Matching** and **Semantic Heuristics** consume the same file content (normalized post-byte-analysis) and produce `PatternFindings` and `HeuristicScores`
4. All three are combined into `StaticResult` per file
5. If `StaticResult.severity == CRITICAL` → verdict is BLOCK, skip LLM
6. Otherwise, **Pre-LLM Sanitization** transforms file content into `SanitizedContent`
7. **LLM Classifier** consumes `SanitizedContent` and produces `LLMResult`
8. **Confidence Fusion** merges `StaticResult` + `LLMResult` → `FinalVerdict`
9. **SARIF Reporter** consumes `List[(FilePath, FinalVerdict, StaticResult, LLMResult?)]` and produces a SARIF document

## Invariants

- **I001**: The scanner MUST process all files in binary mode — never in text mode — to preserve byte-level information for Layer 2.
- **I002**: If `StaticResult.severity == CRITICAL`, the LLM classifier MUST NOT be invoked for that file.
- **I003**: If no LLM arguments are provided, only Case 1 (static analysis) runs; the pipeline MUST skip stages 5–7 and output `FinalVerdict` based on `StaticResult` alone.
- **I004**: The SARIF output MUST conform to SARIF v2.1.0 specification and include `artifactLocation`, `region` (line/column), `level` (error/warning/note), and `message` with `text` and `markdown` fields.
- **I005**: The LLM classifier system prompt MUST be immutable — it is a security boundary. Any change to it requires a spec update and security review.
- **I006**: All numeric thresholds (entropy, invisible ratio, instruction density) MUST be defined as named module-level constants, never as magic numbers inline.
- **I007**: The scanner MUST NOT modify any scanned files — it is strictly read-only.

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
- [OWASP LLM01](https://genai.owasp.org/llmrisk/llm01-prompt-injection/)
