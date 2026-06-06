# ADR-004: LiteLLM as Unified LLM Provider

## Status

Accepted

## Context

The scanner needs to call an LLM for semantic classification (Case 2). Users may use different LLM providers:
- OpenAI (GPT-4o, GPT-4o-mini)
- Anthropic (Claude 3 Haiku, Claude 3.5 Sonnet)
- Self-hosted models via OpenAI-compatible APIs (vLLM, Ollama, LocalAI)
- Azure OpenAI, AWS Bedrock, Google Vertex AI

Building and maintaining separate integrations for each provider is unsustainable. We need a single abstraction that covers all major providers without vendor lock-in.

## Decision

**Use LiteLLM as the sole LLM provider abstraction.**

LiteLLM provides a unified interface (`litellm.completion()`) across 100+ LLM providers using a consistent OpenAI-compatible API format. The scanner invokes `litellm.completion(model=..., messages=[...], temperature=0.3)` and LiteLLM handles provider routing, authentication, and response parsing.

Configuration is passed via CLI arguments (`--llm-base-url`, `--llm-model`, `--llm-api-token`) which map to LiteLLM's configuration model. If arguments are not provided, LiteLLM falls back to its default behavior (environment variables, config files).

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **OpenAI SDK only** | Simple, well-documented | Vendor lock-in; no Anthropic, no self-hosted support | Users need provider choice — Claude is explicitly mentioned in the design document |
| **Separate integrations (OpenAI + Anthropic + Ollama)** | Optimized for each provider | Code duplication; maintenance burden; adding a new provider requires new code | 3 providers = 3x integration code, 3x testing surface |
| **LangChain** | Popular, many integrations | Heavy dependency; opinionated abstractions; frequent breaking changes; overkill for a single completion call | We need one API call, not an agent framework |
| **Direct HTTP calls** | Zero dependencies | Must implement auth, retry, error handling for each provider; fragile to API changes | Reinventing LiteLLM |
| **llama.cpp / local-only** | Offline, private | No cloud provider support; model management burden; no GPT-4/Claude access | Limits scanner to users with local GPU infrastructure |

## Consequences

### Enables
- One code path for all LLM calls — `litellm.completion()`
- Users can switch providers by changing `--llm-model` (e.g., `gpt-4o-mini` → `claude-3-haiku-20240307` → `ollama/llama3`)
- Self-hosted models via `--llm-base-url http://localhost:11434` (Ollama) or any OpenAI-compatible endpoint
- LiteLLM handles retry logic, rate limiting, and error mapping
- LiteLLM is well-maintained with regular updates for new models

### Constrains
- Adds a dependency on `litellm` package (~5MB)
- LiteLLM's model name format must be documented (e.g., `openai/gpt-4o-mini` vs just `gpt-4o-mini`)
- LiteLLM configuration via environment variables may conflict with CLI arguments — CLI takes precedence
- Breaking changes in LiteLLM could affect the scanner (mitigated by version pinning)

## Cross-References

- [System Overview](../architecture/system-overview.md)
- [LLM Classifier](../domains/llm-classifier.md)
- [CLI Interface](../contracts/cli-interface.md)
- [ADR-001: Python Language](001-python-language.md)
- [ADR-003: Two-Stage Pipeline](003-two-stage-pipeline.md)
