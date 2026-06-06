# ADR-006: tiktoken for Accurate Token Counting in Batch LLM Processing

## Status

Accepted

## Context

The scanner's upcoming batch LLM processing feature needs to assemble multiple source-code files into a single LLM call, targeting ~30,000 tokens per batch (adaptive fill, ~1/3 of a typical 100K context window). Accurate token counting is needed at batch assembly time to determine how many files fit in each batch.

The existing `CHARS_PER_TOKEN = 4` heuristic used in `llm_sanitizer.py` provides a rough estimate but has a **±25% error margin** in the worst case. For batch assembly, this means:
- **Under-counting**: Batches may exceed the provider's actual context limit, causing API errors.
- **Over-counting**: Batches may be smaller than necessary, wasting the batching benefit.

Furthermore, tokenization varies by content type:
- **Natural language text** (agent instruction files, markdown) tends to have ~4 chars/token.
- **Code** (source code comments and strings, the primary batch content) often has ~2.5-3 chars/token due to shorter tokens (operators, punctuation).
- **Non-English text** or strings with Unicode content can have 1-2 chars/token.

A single chars/4 ratio cannot accurately handle all three categories simultaneously.

## Decision

**Use `tiktoken` with `cl100k_base` encoding as the primary token counter, with `len(content) // 4` as a graceful fallback when `tiktoken` is not installed.**

- **Encoding**: `cl100k_base` — this is the encoding used by GPT-4, GPT-4o, GPT-4o-mini, and is closely compatible with Anthropic's tokenizer (differing by <1% in typical content). It covers the vast majority of models our users will deploy.
- **Optional dependency**: `tiktoken` is added as an optional dependency under the `[batch]` extra. Users who don't use LLM classification or don't care about batch optimization can skip it.
- **Fallback**: When `tiktoken` is not installed, `count_tokens()` falls back to `len(content) // 4`. The fallback is a safe underestimate for most content types (code has MORE tokens per char than text, so chars/4 slightly overestimates token count, making batches conservatively smaller — never exceeding the provider's limit).

## Alternatives Considered

| Alternative | Pros | Cons | Why Rejected |
|-------------|------|------|--------------|
| **Always chars/4** | Zero dependencies, trivial | ±25% error, can't distinguish code from text | Inaccurate for batch sizing; code files are the primary batch target and they tokenize differently from text |
| **Hard dependency on tiktoken** | Always accurate | Forces 1MB install on all users; tiktoken has native Rust compilation requirements | Batch processing is an optimization, not core functionality. Non-batch paths (per-file classification, static-only scanning) don't need token counting at all |
| **Per-model tokenizers (tiktoken + Anthropic tokenizer + Gemini tokenizer + ...)** | Perfect per-model accuracy | Unsustainable maintenance burden; each provider has its own tokenizer library | The `cl100k_base` encoding is within 1% of Anthropic's and most OpenAI-compatible providers. Gemini and other providers are marginal use cases |
| **Server-side token counting (API endpoint)** | Always correct for the specific model | Extra API call per file; adds latency; defeats the purpose of batching | We're batching to REDUCE API calls, not add more |
| **Fixed batch size (e.g., always 15 files)** | Simplest implementation | Unreliable — file sizes vary widely; some batches may be 5K tokens, others 50K+ | No control over actual context window utilization |

## Consequences

### Enables
- **Accurate batch sizing**: Batches consistently fill ~30K tokens regardless of content type (code vs text).
- **No provider errors**: Correct token counting prevents batches from exceeding the provider's context limit.
- **Graceful degradation**: When `tiktoken` is not installed, the chars/4 fallback produces conservatively sized batches (safe underestimate for code) — never exceeding limits.
- **Zero cost for non-batch users**: The optional dependency model means static-only users and per-file LLM users don't install `tiktoken`.

### Constrains
- **Model coverage**: `cl100k_base` is not the exact tokenizer for Anthropic, Gemini, or Cohere models. However, it is within 1% for Anthropic and within 5% for most others. The 30K target leaves sufficient headroom.
- **Encoding deprecation risk**: If OpenAI deprecates `cl100k_base` in favor of a new encoding, we'd need to update `TIKTOKEN_ENCODING`. Mitigated by `tiktoken`'s built-in support for multiple encodings (`o200k_base`, `p50k_base`, etc.).
- **Rust compilation**: `tiktoken` requires a Rust toolchain for source installs. Pre-built wheels are available for all major platforms (macOS, Linux, Windows) on PyPI, so this only affects users on exotic architectures.

## Cross-References

- [LLM Classifier](../domains/llm-classifier.md) — batch processing feature
- [ADR-003: Two-Stage Pipeline](003-two-stage-pipeline.md)
- [ADR-004: LiteLLM Provider](004-litellm-provider.md)
