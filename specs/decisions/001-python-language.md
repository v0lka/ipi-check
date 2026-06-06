# ADR-001: Python as Implementation Language

## Status

Accepted

## Context

The ipi-check scanner requires a language that supports:
- Raw byte-level file I/O for ANSI/Unicode signature detection
- Regex pattern matching with timeout support (ReDoS protection)
- Integration with LiteLLM (Python-native library)
- SARIF generation (no native SARIF library in most languages, but Python's `json` module is sufficient)
- Easy distribution via PyPI and Docker
- Rapid prototyping for security tooling

## Decision

**Use Python 3.12+** as the sole implementation language.

Python is the natural choice because:
1. **LiteLLM is a Python library** — using it natively avoids subprocess/API bridge complexity
2. **Raw byte handling** — Python's `bytes` type and `re` module on bytes handle ANSI/Unicode signatures directly
3. **Distribution** — PyPI is the standard Python package index; `pip install ipi-check` is frictionless
4. **Docker** — python-slim base images are well-maintained and minimal

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Go** | Fast, single binary, no runtime | LiteLLM has no Go SDK; would require HTTP bridge or subprocess calls to a Python process; SARIF requires manual JSON construction | LLM integration is the critical path — wrapping LiteLLM in Go adds significant complexity |
| **Rust** | Maximum performance, no GC | LiteLLM is Python-only; no ecosystem for LLM API calls; overkill for a file scanner bottlenecked on I/O and API latency, not CPU | Performance gains negligible compared to I/O-bound workload |
| **TypeScript/Node.js** | Good JSON handling, npm ecosystem | No LiteLLM; OpenAI/Anthropic SDKs exist but no unified provider abstraction; byte-level operations in Node.js Buffers are less ergonomic than Python bytes | Requires building a LiteLLM-equivalent abstraction from scratch |

## Consequences

### Enables
- Direct use of `litellm` library for all LLM provider interactions
- `re` module with timeout support (Python 3.11+) for ReDoS-safe pattern matching
- `dataclasses` for strict type definitions of finding objects
- `pathlib` for cross-platform file path handling
- `argparse` for CLI argument parsing
- `json` module for SARIF generation (no external SARIF library needed)
- `build` + `twine` for PyPI publishing

### Constrains
- Requires Python 3.12+ runtime on user machines (no single-binary distribution without PyInstaller)
- Startup time is slower than compiled languages (negligible for a CLI tool that runs once per scan)
- No static type checking at compile time (mitigated by `mypy` in CI)

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [CLI Interface](../contracts/cli-interface.md)
- [ADR-004: LiteLLM Provider](004-litellm-provider.md)
