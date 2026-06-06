# ADR-003: Two-Stage Static-then-LLM Pipeline

## Status

Accepted

## Context

The scanner must detect prompt injection payloads at two levels:
1. **Byte/syntactic level** — ANSI escapes, Unicode tags, known injection phrases (regex). Fast, deterministic, cheap.
2. **Semantic level** — paraphrased attacks, multi-step injections, intent inference. Requires LLM. Slow, probabilistic, expensive.

We need to decide the relationship between these two detection approaches: should they run in parallel, sequential, or be mutually exclusive?

## Decision

**Run static analysis first. If it produces a CRITICAL verdict, skip LLM. Otherwise, invoke LLM classification and fuse results.**

This is an asymmetric pipeline:
- Stage 1 (static) acts as a **fast gate** — catches obvious attacks in <100ms/file with zero cost
- Stage 2 (LLM) acts as a **deep inspector** — catches semantic attacks that evade regex, but costs ~$0.01-0.05/file and takes 1-5s

The static stage never defers to LLM for CRITICAL findings — this is a security boundary. If the file contains ANSI escape sequences designed to hide text from humans, it is blocked regardless of LLM opinion.

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Parallel (static + LLM simultaneously)** | Maximum speed for non-critical files | Wastes LLM calls on files that static analysis would block anyway; LLM sees unsanitized content | Violates security boundary — CRITICAL files must not reach LLM |
| **LLM-first** | Catches semantic attacks early | Every file incurs LLM cost (~100x more expensive); LLM is attacked by invisible payloads that static analysis would neutralize | LLM is the most vulnerable and expensive component — it should be the last resort, not the first |
| **Static-only (Case 1 only)** | Free, fast, offline | Cannot detect paraphrased attacks ("Please erase the testing directory" vs "delete all tests") | Attacks are evolving beyond regex-detectable patterns — see arXiv 2601.17548 showing >78% success against static defenses |
| **LLM-only** | Maximum semantic coverage | $0.01-0.05/file; 1-5s/file; requires internet; LLM can be prompt-injected via the payload it's analyzing | Too expensive, too slow, and introduces a new attack vector without static sanitization |

## Consequences

### Enables
- **Cost efficiency**: LLM is only called for files that pass static analysis (majority of files in a typical repo are clean)
- **Speed**: Most scans complete in milliseconds (static-only on clean files)
- **Defense in depth**: Static layer protects LLM from byte-level attacks; LLM catches what static misses
- **Graceful degradation**: If LLM is unavailable (no token, network down), scanner still works in Case 1 mode

### Constrains
- Pipeline is strictly sequential — file N+1 waits for file N's LLM call to complete (acceptable for per-file latency of 1-5s)
- No parallel LLM fan-out (simplifies error handling and rate limiting)
- Static findings cannot be "overruled" by LLM — a CRITICAL static finding always blocks, even if LLM says "safe"

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [Security Model](../architecture/security-model.md) — AV1: LLM Classifier Prompt Injection
- [LLM Classifier](../domains/llm-classifier.md)
- [Confidence Fusion](../domains/confidence-fusion.md)
- [ADR-004: LiteLLM Provider](004-litellm-provider.md)
