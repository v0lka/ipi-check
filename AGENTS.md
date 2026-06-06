# AGENTS.md — ipi-check

## Project Overview

**ipi-check** is a SAST scanner that detects **indirect prompt injection** (OWASP LLM01) in AI agent instruction files and source code. It combines deterministic static analysis with an **optional** LLM classifier and emits **SARIF v2.1.0** — compatible with GitHub Code Scanning, GitLab SAST, and VS Code SARIF Viewer.

The scanner protects against attackers who smuggle malicious instructions into files like `AGENTS.md`, `.cursorrules`, `CLAUDE.md`, `.windsurfrules`, or source-code comments — files that LLM-powered coding agents read and trust.

### Two-Stage Pipeline

1. **Stage 1 — Static analysis (always on).** Byte-level inspection, regex pattern matching, and semantic heuristics produce per-file results with deterministic confidence scores.
2. **Stage 2 — LLM classification (optional).** When an LLM provider is configured via CLI or environment, sanitized content is forwarded to the model for a structured classification verdict.

A deterministic confidence-fusion matrix combines both stages into a final verdict: `PASS`, `REVIEW_REQUIRED`, or `BLOCK`.

---

## Technology Stack

| Component          | Technology                                                                |
| ------------------ | ------------------------------------------------------------------------- |
| Language           | Python 3.12+                                                              |
| Build system       | Hatchling                                                                 |
| LLM provider       | [LiteLLM](https://github.com/BerriAI/litellm)                             |
| Token counting     | [tiktoken](https://github.com/openai/tiktoken) (optional `[batch]` extra) |
| Code extraction    | [Pygments](https://pygments.org/)                                         |
| Gitignore matching | [pathspec](https://github.com/cpburnz/python-pathspec)                    |
| Linter             | Ruff (`E`, `F`, `W`, `I`, `N`, `UP`, `B`, `A`, `SIM`, `TCH`)              |
| Type checker       | mypy (strict mode)                                                        |
| Tests              | pytest + pytest-mock                                                      |
| CI                 | GitHub Actions (lint → type-check → test → docker)                        |

---

## Project Structure

```
ipi-check/
├── src/ipi_check/
│   ├── __init__.py              # TOOL_INFO, __version__
│   ├── cli/
│   │   └── main.py              # argparse CLI entry point
│   ├── core/
│   │   └── types.py             # All enums, dataclasses, type aliases
│   ├── scanner/
│   │   ├── file_discovery.py    # Layer 1: locate scannable files
│   │   ├── byte_analysis.py     # Layer 2: hidden-byte detection
│   │   ├── pattern_matching.py  # Layer 3: regex injection patterns
│   │   ├── semantic_heuristics.py # Layer 4: entropy, density, ratios
│   │   ├── static_result.py     # Layers 1-4 orchestration + severity calc
│   │   ├── code_extractor.py    # Layer 5: Pygments comment/string extraction
│   │   ├── llm_sanitizer.py     # Layer 5b: neutralize hostile content for LLM
│   │   ├── token_counter.py     # Token counting for batch assembly (tiktoken/fallback)
│   │   ├── llm_classifier.py    # Layer 6: LiteLLM-backed classification (single + batch)
│   │   ├── confidence_fusion.py # Layer 7: static+LLM → final verdict
│   │   └── pipeline.py          # End-to-end orchestration (layers 1-7)
│   └── reporter/
│       └── sarif_reporter.py    # SARIF v2.1.0 emission
├── tests/                       # pytest test suite (mirrors src structure)
├── scripts/
│   └── ipi-check-hook.sh        # Git post-checkout hook wrapper
├── specs/                       # Architecture specs, ADRs, domain docs
├── Dockerfile                   # Multi-stage Python 3.12-slim
├── pyproject.toml               # Build config, deps, ruff, mypy, pytest
└── .github/workflows/ci.yml     # CI: lint, type-check, test (3.12+3.13), docker
```

---

## Architecture — Scanner Layers

```
Layer 1: File Discovery     →  DiscoveredFile
Layer 2: Byte Analysis      →  ByteFinding[]
Layer 3: Pattern Matching   →  PatternFinding[]
Layer 4: Semantic Heuristics →  HeuristicScores
          ↓
     StaticResult  (assembled via static_result.py)
          ↓
Layer 5: Code Extraction + Sanitization  (only for LLM path)
Layer 6: LLM Classification              (optional, single-file or batch)
Layer 7: Confidence Fusion               → FinalVerdict (BLOCK/REVIEW_REQUIRED/PASS)
```

### Layer Details

**Layer 1 — File Discovery** (`file_discovery.py`)

- Discovers: agent instruction files (`.cursorrules`, `AGENTS.md`, `CLAUDE.md`, etc.), dot-directory markdown (`.github/*.md`), and source code (20+ extensions).
- Skips: binaries, files >10 MB, `.git/`, gitignore-matching paths, symlinks escaping the repo root.
- Supports `--exclude` glob patterns and `--no-gitignore`.

**Layer 2 — Byte Analysis** (`byte_analysis.py`)
Detects hidden content at byte level:

- ANSI escape sequences (CRITICAL)
- Unicode tag characters U+E0000–U+E007F (CRITICAL)
- Variation selectors (HIGH)
- Bidi overrides U+202A–U+202E, U+2066–U+2069 (HIGH)
- Zero-width characters (MEDIUM)
- Private Use Area codepoints (MEDIUM)
- Cyrillic homoglyphs at density >5% (MEDIUM)

**Layer 3 — Pattern Matching** (`pattern_matching.py`)
Regex-based detection with ReDoS protection (0.1s thread timeout per line):

- Instruction overrides (INSTR_001–006) — CRITICAL (includes multilingual: RU, CN, FR, ES, DE, JP, KR)
- Authority claims (AUTH_001–003, AUTH_005–007) — HIGH (includes CVE-2025-53773 `chat.tools.autoApprove`)
- Destructive commands (DEST_001–004) — CRITICAL
- Data exfiltration (EXFIL_001–006) — CRITICAL (includes conversation leakage)
- Shell injection (SHELL_001) — CRITICAL
- Jailbreak patterns (JAIL_001–006) — HIGH (includes STAN/DUDE, token system, role-play)
- Social engineering (AUTH_004, SOC_001–002) — MEDIUM
- Obfuscation (OBFUSC_001–004) — MEDIUM

Severity downgrade: non-agent `.md` files are capped at MEDIUM.

**Layer 4 — Semantic Heuristics** (`semantic_heuristics.py`)

- Shannon entropy (suspicious if >5.5 bits/char for text, >6.0 for source code)
- Invisible content ratio (suspicious if >10%)
- Instruction density — imperative verbs per paragraph (suspicious if >3.0)

**Layer 5 — Code Extraction** (`code_extractor.py`, `llm_sanitizer.py`)

- Pygments-based: extracts only comments and string literals from source code
- Falls back to full content when Pygments is unavailable or no comments found
- Sanitizer neutralizes invisible characters to visible placeholders, decodes base64 and ROT13
- Sanitizer no longer truncates content (truncation removed to prevent payload evasion; batch processing handles large files via chunking)

**Layer 6 — LLM Classification** (`llm_classifier.py`)

- LiteLLM with strict JSON schema validation
- System prompt instructs the model to analyze, not follow
- Single-file mode: per-file classification with `CLASSIFIER_SYSTEM_PROMPT`
- Batch mode: multi-file classification for source code with `BATCH_CLASSIFIER_SYSTEM_PROMPT`
- Oversized files (>30K tokens) are chunked and classified per-chunk, then merged (worst verdict wins)
- Partial batch failures trigger per-file retry with exponential backoff (1s → 2s → 4s, max 3 attempts)
- Any failure (network, timeout, invalid schema) → compromised fallback
- LLM timeout: 180 seconds per call

**Layer 7 — Confidence Fusion** (`confidence_fusion.py`)
Deterministic decision matrix:

- CRITICAL static → always BLOCK (LLM skipped, invariant I002)
- HIGH static + malicious/suspicious LLM → BLOCK
- HIGH static + safe LLM → REVIEW_REQUIRED
- MEDIUM static + malicious LLM (high confidence) → BLOCK
- MEDIUM static + malicious LLM (low confidence) → REVIEW_REQUIRED
- MEDIUM static + suspicious LLM → REVIEW_REQUIRED
- MEDIUM static + safe LLM → PASS
- NONE static + high-confidence malicious LLM → REVIEW_REQUIRED
- Everything else → PASS

---

## Key Invariants

1. **CRITICAL static severity always blocks** — LLM is not consulted for these files (invariant I002).
2. **Scanner always exits 0** on successful scan regardless of findings — the SARIF carries the verdicts.
3. **Exit codes**: 0 = success, 1 = runtime error, 2 = usage error.
4. **LLM result contamination**: if the LLM response fails JSON schema validation, it's marked `compromised=True` and static-only fallback is used.
5. **Path traversal protection**: symlinks resolving outside the repo root are skipped with a warning.
6. **Pre-LLM sanitization**: invisible characters are replaced with visible placeholders before sending to LLM — prevents the scanner itself from being prompt-injected.

---

## Rule IDs

| Range      | Layer               |
| ---------- | ------------------- |
| IPI001–007 | Byte analysis       |
| IPI101–108 | Pattern matching    |
| IPI201–203 | Semantic heuristics |
| IPI301     | LLM findings        |
| IPI900     | LLM compromise      |

CWE mappings: CWE-506 (embedded malicious code), CWE-451 (UI misrepresentation), CWE-1007 (insufficient visual distinction), CWE-77 (command injection).

---

## Development Commands

```bash
# Setup
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# Tests
pytest tests/ -v --tb=short

# Lint
ruff check src/ tests/

# Type check
mypy src/

# Run on self
ipi-check scan . --output results.sarif

# Build Docker
docker build -t ipi-check .
docker run --rm -v "$(pwd):/repo" ipi-check scan /repo
```

---

## Code Conventions

### Style

- Python 3.12+ with `from __future__ import annotations` in every module
- Ruff-enforced: line length 100, imports sorted (I), flake8 (E/F/W), pep8-naming (N), pyupgrade (UP), flake8-bugbear (B), flake8-builtins (A), flake8-simplify (SIM), flake8-type-checking (TCH)
- mypy strict mode, `warn_return_any=True`, `warn_unused_configs=True`

### Patterns

- **Dataclasses over dicts**: all structured data uses `@dataclass` from `core/types.py`
- **Enums over strings**: `FileCategory`, `Severity`, `ByteFindingCategory`, `PatternFindingCategory`, `VerdictDecision`
- **Interface symmetry**: scanner functions accept parameters they don't always use (e.g., `file` in `analyze_bytes`) to maintain a uniform call signature across layers
- **`del` unused args**: explicitly mark unused parameters with `del` to satisfy linters while keeping the interface
- **Deferred imports**: `litellm`, `pygments`, and `tiktoken` are imported inside functions to allow graceful fallback when not installed
- **Thread-based ReDoS protection**: pattern matching runs regexes with a 0.1s timeout via `ThreadPoolExecutor`
- **Progress to stderr**: all progress/banner/summary output goes to stderr; SARIF goes to stdout (or a file)
- **`${VAR}` expansion**: CLI string arguments support `${VAR_NAME}` expansion; undefined vars become empty strings

### Testing

- pytest with `pytest-mock`
- Shared fixtures in `conftest.py`: `sample_repo`, `malicious_repo`, `empty_repo`, `code_repo`, `sample_discovered_file`, `llm_config`, `empty_llm_config`
- `_isolate_env` autouse fixture clears LLM-related env vars to prevent test leakage
- Test files mirror source structure: `tests/test_<module>.py` for `src/ipi_check/<package>/<module>.py`
- No type-checking exemptions needed in tests — ruff `TC001/2/3` ignored globally for `tests/**`

### File Organization

- `core/types.py` is the single source of truth for all data types — nothing is redefined elsewhere
- Each scanner layer is one file, named by its domain concept
- `pipeline.py` is the only orchestrator; `static_result.py` provides a standalone static-only pipeline for simpler use cases
- CLI handles validation, env var expansion, and output writing; pipeline handles all scanning logic

---

## CLI Contract

```
ipi-check scan REPO_PATH [--llm-model NAME] [--llm-api-token TOKEN]
                         [--llm-base-url URL] [--output PATH]
                         [--quiet] [--no-gitignore] [--exclude PAT]
```

- `REPO_PATH` supports `${VAR}` expansion
- `--output` writes compact JSON; stdout gets pretty-printed JSON
- Warning emitted if `--output` extension is not `.sarif`
- `--exclude` is repeatable, uses gitignore-style globs

---

## SARIF Output

- Version 2.1.0, schema: `https://json.schemastore.org/sarif-2.1.0.json`
- Each finding includes: `ruleId`, `level` (error/warning/note/none), `message` (text + markdown), physical location with line/column
- User-controlled content is HTML-escaped and truncated at 200 chars (R005)
- Rule definitions include CWE tags in `properties.tags`

---

## Environment Variables

| Variable                    | Purpose                                     |
| --------------------------- | ------------------------------------------- |
| `LITELLM_API_KEY`           | Fallback LLM API key                        |
| `OPENAI_API_KEY`            | Fallback LLM API key                        |
| `ANTHROPIC_API_KEY`         | Fallback LLM API key                        |
| `IPI_CHECK_HOOK_DISABLE`    | Set to `1` to skip the git hook scan        |
| `IPI_CHECK_BLOCK_ON_REVIEW` | Set to `1` to fail on REVIEW_REQUIRED       |
| `IPI_CHECK_BIN`             | Override path to `ipi-check` binary in hook |

---

## Security Policy

This project maintains a security policy in [SECURITY.md](./SECURITY.md).
All AI coding agents MUST read and follow SECURITY.md before making changes.
It contains:

- Threat model and trust boundaries
- Secure coding guidelines specific to this project's stack
- Hard constraints and forbidden patterns for AI agents
- Vulnerability reporting procedures
- Scanner self-protection invariants (S001–S006, I001–I007)

Any code contribution that violates the rules in SECURITY.md will be rejected.
