"""Pipeline orchestrator — run the complete scan pipeline."""

from __future__ import annotations

import json
import multiprocessing
import re
import sys
import warnings
from concurrent.futures import ProcessPoolExecutor
from functools import lru_cache
from typing import TYPE_CHECKING

import pathspec
from pathspec.pattern import Pattern as _PathSpecPattern

from ipi_check.core.types import (
    BatchFileInput,
    BatchRequest,
    ByteFinding,
    CompromisedReason,
    DiscoveredFile,
    FileCategory,
    FileDirectives,
    FinalVerdict,
    IgnoreEntry,
    LLMConfig,
    LLMFinding,
    LLMResult,
    PatternFinding,
    Severity,
    SkillFinalVerdict,
    SkillStaticResult,
    StaticResult,
    Suppression,
    SuppressionKind,
    SuppressionPolicy,
    worst_compromised_reason,
)
from ipi_check.scanner.byte_analysis import analyze_bytes
from ipi_check.scanner.code_extractor import comment_line_numbers, extract_comments_and_strings
from ipi_check.scanner.confidence_fusion import fuse_skill_verdict, fuse_verdicts
from ipi_check.scanner.file_discovery import MAX_FILE_SIZE_BYTES, discover_files
from ipi_check.scanner.llm_classifier import (
    FAILURE_SCHEMA,
    LLMLedger,
    _strip_code_fence,
    call_raw_completion,
    classify_batch_with_llm,
    classify_skill_with_llm,
    classify_with_llm,
    is_llm_available,
    llm_unavailable_reason,
    resolve_llm_cache_dir,
    resolve_model,
    retry_broken_files,
)
from ipi_check.scanner.llm_sanitizer import sanitize_content
from ipi_check.scanner.pattern_matching import match_patterns
from ipi_check.scanner.semantic_heuristics import compute_heuristics
from ipi_check.scanner.static_result import (
    _get_visible_text,
    assemble_static_result,
    compute_skill_static_result,
)
from ipi_check.scanner.token_counter import TARGET_BATCH_TOKENS, count_tokens

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path

# ---------------------------------------------------------------------------
# Progress message templates
# ---------------------------------------------------------------------------

_PROGRESS_SCAN_START: str = "Scanning {repo_path}..."
_PROGRESS_DISCOVERED: str = "Discovered {count} files to scan"
_PROGRESS_LLM_SKIPPED: str = "  [llm]              SKIPPED (no LLM configured)"
_PROGRESS_LLM_CONFIG: str = (
    "  [llm]              model={model} base_url={base_url} api_token={api_token}"
)
_WARNING_FILE_READ_FAILED: str = "Skipping file due to read error: {path} ({err})"
_WARNING_LLM_FALLBACK: str = "LLM API error: {msg} — falling back to static analysis"

# Emitted in place of _PROGRESS_LLM_SKIPPED when an LLM credential is present
# but no model resolves: the scan degrades to static analysis and says why,
# instead of silently reporting "no LLM configured".
_WARNING_LLM_NO_MODEL: str = (
    "  [llm]              SKIPPED (static analysis only) — WARNING: {reason}"
)

# LLM budget / usage summary (IN-20). Emitted once, after the LLM and skill
# phases, unless --quiet; the literal "tokens in"/"tokens out" is part of the
# contract surfaced in specs/contracts/cli-interface.md.
_PROGRESS_LLM_USAGE: str = (
    "  [llm] usage: {prompt} tokens in / {completion} tokens out "
    "({calls} calls, {cache_hits} cache hits)"
)
_PROGRESS_LLM_BUDGET: str = (
    "  [llm] budget: --max-llm-calls={max_calls} reached; "
    "remaining files fall back to static analysis"
)

# Placeholder for a verbose LLM-config diagnostic when a parameter is unset.
_CONFIG_UNSET: str = "<provider default>"

# Progress bar formatting.
_BAR_WIDTH: int = 16
_BAR_FILL: str = "█"
_BAR_EMPTY: str = " "
_STAGE_LABEL_PAD: int = 17

# Stage names (per CLI contract).
_STAGE_BYTE_ANALYSIS: str = "byte-analysis"
_STAGE_PATTERN_MATCHING: str = "pattern-matching"
_STAGE_HEURISTICS: str = "heuristics"
_STAGE_LLM: str = "llm"
_STAGE_SKILL_STATIC: str = "skill-static"
_STAGE_SKILL_LLM: str = "skill-llm"


def _emit(message: str, *, quiet: bool) -> None:
    """Write a progress message to stderr unless ``quiet`` is set."""
    if quiet:
        return
    print(message, file=sys.stderr, flush=True)


def _emit_progress(message: str, *, quiet: bool, final: bool = False) -> None:
    """Write an in-place progress update to stderr (carriage-return overwrite).

    When ``final`` is True, a newline is appended so subsequent output
    starts on the next line.
    """
    if quiet:
        return
    end = "\n" if final else ""
    print(f"\r{message}", end=end, file=sys.stderr, flush=True)


def _progress_bar(stage: str, done: int, total: int) -> str:
    """Format a completed progress bar line.

    Layout: ``  [{stage}]<padding> {pct:>3}% |{bar}| {done}/{total}``.
    The bar is :data:`_BAR_WIDTH` characters wide. When ``total`` is zero,
    the bar is rendered as fully filled at 100% to avoid division by zero.
    """
    if total == 0:
        pct = 100
        filled = _BAR_WIDTH
    else:
        pct = (done * 100) // total
        filled = (_BAR_WIDTH * done) // total
    bar = _BAR_FILL * filled + _BAR_EMPTY * (_BAR_WIDTH - filled)
    pad = " " * max(1, _STAGE_LABEL_PAD - len(stage))
    return f"  [{stage}]{pad}{pct:>3}% |{bar}| {done}/{total}"


def _read_bytes(file: DiscoveredFile) -> bytes | None:
    """Read a file's bytes, emitting a warning on I/O failure."""
    try:
        with open(file.path, "rb") as handle:
            return handle.read()
    except OSError as exc:
        warnings.warn(_WARNING_FILE_READ_FAILED.format(path=file.path, err=exc), stacklevel=2)
        return None


# ---------------------------------------------------------------------------
# Parallel static analysis (--jobs)
# ---------------------------------------------------------------------------

#: In-flight tasks per worker when fanning a pass out to a process pool.
_POOL_TASKS_PER_WORKER: int = 4


def _parallel_start_method() -> str:
    """Return the multiprocessing start method used for ``--jobs`` pools.

    ``fork`` is preferred on POSIX: workers start almost instantly and — unlike
    ``spawn`` — do not re-import the caller's ``__main__`` module (which would
    re-execute an unguarded script). ``spawn`` is the portable fallback (e.g.
    Windows, or a platform without ``fork``). The pool is created before any
    auxiliary threads exist, so forking is safe.
    """
    methods = multiprocessing.get_all_start_methods()
    return "fork" if "fork" in methods else "spawn"


def _static_pass_bytes(item: tuple[DiscoveredFile, bytes]) -> list[ByteFinding]:
    """Pass 1 worker: byte-level analysis for one file (picklable, pure)."""
    file, raw_bytes = item
    return analyze_bytes(file, raw_bytes)


def _static_pass_patterns(item: tuple[DiscoveredFile, bytes]) -> list[PatternFinding]:
    """Pass 2 worker: injection-pattern matching for one file (picklable, pure).

    Source-code files are matched against extracted comments and string
    literals only — mirroring the sequential pass — to avoid false positives
    on identifiers and doc comments.
    """
    file, raw_bytes = item
    if file.category == FileCategory.SOURCE_CODE:
        extracted = extract_comments_and_strings(file, raw_bytes)
        return match_patterns(file, raw_bytes, target_text=extracted)
    return match_patterns(file, raw_bytes)


def _static_pass_heuristics(
    item: tuple[DiscoveredFile, bytes, list[ByteFinding], list[PatternFinding]],
) -> StaticResult:
    """Pass 3 worker: semantic heuristics + static-result assembly for one file."""
    file, raw_bytes, byte_findings, pattern_findings = item
    visible_text = _get_visible_text(raw_bytes)
    heuristic_scores = compute_heuristics(file, raw_bytes, visible_text, byte_findings)
    return assemble_static_result(file, byte_findings, pattern_findings, heuristic_scores)


def _apply_static_pass[T, R](
    executor: ProcessPoolExecutor | None,
    jobs: int,
    worker: Callable[[T], R],
    items: list[T],
    *,
    stage: str,
    quiet: bool,
) -> list[R]:
    """Run one per-file static pass, in-process or across a process pool.

    With ``executor=None`` (``--jobs 1``) the pass runs in-process, iterating
    ``items`` in order — the historical behaviour. Otherwise the work is fanned
    out to ``jobs`` worker processes via :meth:`ProcessPoolExecutor.map`, whose
    results are re-ordered to match ``items`` so the pipeline output stays
    independent of scheduling order. Progress is reported per file (unless
    ``quiet``), exactly as in the sequential path.
    """
    total = len(items)
    results: list[R] = []
    if executor is not None and total > 1:
        chunksize = max(1, total // (jobs * _POOL_TASKS_PER_WORKER))
        for done, result in enumerate(executor.map(worker, items, chunksize=chunksize), 1):
            results.append(result)
            _emit_progress(_progress_bar(stage, done, total), quiet=quiet)
    else:
        for done, item in enumerate(items, 1):
            results.append(worker(item))
            _emit_progress(_progress_bar(stage, done, total), quiet=quiet)
    _emit_progress(_progress_bar(stage, total, total), quiet=quiet, final=True)
    return results


def _emit_llm_warning(
    llm_result: LLMResult,
    *,
    quiet: bool,
    verbose: bool = False,
    context: str | None = None,
) -> None:
    """Emit a warning to stderr when an LLM result is compromised.

    The reason carried by ``raw_response`` — the provider exception type,
    HTTP status code and message (see ``_describe_exception``) — is always
    shown, so an unavailable API is visible on stderr even without
    ``--verbose``. With ``verbose`` the offending file/skill is appended so
    the degraded call can be pinpointed (IN-13).
    """
    if not llm_result.compromised:
        return
    msg = llm_result.raw_response or "classification failed"
    if verbose and context:
        msg = f"{msg} [in {context}]"
    _emit(_WARNING_LLM_FALLBACK.format(msg=msg), quiet=quiet)


def _emit_llm_usage(ledger: LLMLedger, *, quiet: bool) -> None:
    """Emit the end-of-scan LLM token/budget summary to stderr.

    Silenced when there was no LLM activity (so static-only scans add no
    noise). Reports ``tokens in``/``tokens out`` plus call and cache-hit counts,
    and flags when the ``--max-llm-calls`` budget was reached.
    """
    usage = ledger.usage
    if usage.calls == 0 and usage.cache_hits == 0 and usage.total_tokens == 0:
        return
    _emit(
        _PROGRESS_LLM_USAGE.format(
            prompt=usage.prompt_tokens,
            completion=usage.completion_tokens,
            calls=usage.calls,
            cache_hits=usage.cache_hits,
        ),
        quiet=quiet,
    )
    if ledger.budget_exhausted() and ledger.max_calls is not None:
        _emit(
            _PROGRESS_LLM_BUDGET.format(max_calls=ledger.max_calls),
            quiet=quiet,
        )


def _classify_via_llm(
    file: DiscoveredFile,
    raw_bytes: bytes,
    static_result: StaticResult,
    llm_config: LLMConfig,
    ledger: LLMLedger | None = None,
) -> LLMResult:
    """Run code extraction → sanitization → LLM classification."""
    extracted = extract_comments_and_strings(file, raw_bytes)
    sanitized = sanitize_content(extracted.encode("utf-8"), static_result.byte_findings)
    return classify_with_llm(file, sanitized, llm_config, ledger=ledger)


# ---------------------------------------------------------------------------
# Batch assembly helpers
# ---------------------------------------------------------------------------

# Verdict ordering for chunk-result merging (higher = worse).
_VERDICT_ORDER: dict[str, int] = {"malicious": 3, "suspicious": 2, "safe": 1}


def _split_static_results(
    static_results: list[tuple[DiscoveredFile, bytes, StaticResult]],
) -> tuple[
    list[tuple[DiscoveredFile, bytes, StaticResult]],
    list[tuple[DiscoveredFile, bytes, StaticResult]],
]:
    """Split static results into non-code and source-code streams.

    Non-code: ``AGENT_INSTRUCTION`` and ``DOT_DIRECTORY_MD`` — processed per-file.
    Source code: ``SOURCE_CODE`` — eligible for batching.
    """
    non_code: list[tuple[DiscoveredFile, bytes, StaticResult]] = []
    code: list[tuple[DiscoveredFile, bytes, StaticResult]] = []
    for file, raw_bytes, sr in static_results:
        if file.category == FileCategory.SOURCE_CODE:
            code.append((file, raw_bytes, sr))
        else:
            non_code.append((file, raw_bytes, sr))
    return non_code, code


def _find_split_point(text: str, max_tokens: int, delimiter: str) -> int:
    """Find the last ``delimiter`` position whose prefix fits within ``max_tokens``."""
    lo, hi = 0, len(text)
    best = 0
    while lo <= hi:
        mid = (lo + hi) // 2
        candidate = text[:mid]
        if count_tokens(candidate) <= max_tokens:
            pos = candidate.rfind(delimiter)
            if pos > best:
                best = pos
            lo = mid + 1
        else:
            hi = mid - 1
    if best > 0:
        return best + len(delimiter)
    return 0


def _hard_split_at_tokens(text: str, max_tokens: int) -> int:
    """Find the longest prefix of ``text`` within ``max_tokens`` (binary search)."""
    lo, hi = 0, len(text)
    while lo < hi:
        mid = (lo + hi + 1) // 2
        if count_tokens(text[:mid]) <= max_tokens:
            lo = mid
        else:
            hi = mid - 1
    return max(lo, 1)


def _chunk_content(content: str, max_tokens: int) -> list[str]:
    """Split content into chunks at natural boundaries, each ≤ ``max_tokens``.

    Prefers paragraph breaks (double-newline), then single-newline, then
    falls back to a hard character-level split.
    """
    chunks: list[str] = []
    remaining = content

    while remaining:
        if count_tokens(remaining) <= max_tokens:
            chunks.append(remaining)
            break

        # Try paragraph break first.
        split_point = _find_split_point(remaining, max_tokens, "\n\n")
        if split_point == 0:
            # Try single newline.
            split_point = _find_split_point(remaining, max_tokens, "\n")
        if split_point == 0:
            # Hard split.
            split_point = _hard_split_at_tokens(remaining, max_tokens)

        chunks.append(remaining[:split_point])
        remaining = remaining[split_point:]

    return chunks


def _merge_chunk_results(chunk_results: list[LLMResult]) -> LLMResult:
    """Merge LLM results from chunks of the same file.

    Rules:
      - Worst verdict wins (malicious > suspicious > safe).
      - Maximum confidence across all chunks.
      - Combine findings, deduplicated by (line, category).
      - If any chunk is compromised, the merged result is compromised, with
        the *worst* compromised reason preserved
        (:func:`ipi_check.core.types.worst_compromised_reason`) — an
        ``INJECTION_SUSPECTED`` chunk must keep escalating the fused verdict
        even when other chunks failed for benign reasons.
    """
    if not chunk_results:
        return LLMResult(verdict="safe", confidence=0.0, compromised=True)

    worst_verdict = "safe"
    max_conf = 0.0
    any_compromised = False
    all_findings: list[LLMFinding] = []
    seen: set[tuple[int, str]] = set()
    reasons: list[CompromisedReason | None] = []

    for result in chunk_results:
        if result.compromised:
            any_compromised = True
            reasons.append(result.compromised_reason)
            continue
        if _VERDICT_ORDER.get(result.verdict, 0) > _VERDICT_ORDER.get(worst_verdict, 0):
            worst_verdict = result.verdict
        if result.confidence > max_conf:
            max_conf = result.confidence
        for finding in result.findings:
            key = (finding.line, finding.category)
            if key not in seen:
                seen.add(key)
                all_findings.append(finding)

    return LLMResult(
        verdict=worst_verdict,
        confidence=max_conf,
        findings=all_findings,
        compromised=any_compromised,
        compromised_reason=worst_compromised_reason(reasons) if any_compromised else None,
    )


# ---------------------------------------------------------------------------
# Cross-chunk contradiction detection (intra-file, pattern E)
# ---------------------------------------------------------------------------

CROSS_CHUNK_CONTRADICTION_PROMPT: str = (
    "You are a security auditor checking for intra-file instruction contradictions. "
    "Below are key claims extracted from the BEGINNING and END of a file. "
    "Determine if any claim in the END directly contradicts or negates a claim "
    "in the BEGINNING (e.g., 'must never X' vs 'X is waived', "
    "'always follow rules' vs 'rules do not apply').\n\n"
    "BEGINNING claims:\n{early_claims}\n\n"
    "END claims:\n{late_claims}\n\n"
    'Respond with ONLY a JSON object: {{"verdict": "CONTRADICTION"}} if a '
    'contradiction is found, or {{"verdict": "CONSISTENT"}} if no contradiction '
    "is detected. Output nothing else."
)

_CC_IMPERATIVE_SENTENCE_RE: re.Pattern[str] = re.compile(
    r"(?:^|[.!?\n])\s*([^.!?\n]{20,}(?:must|shall|should|always|never"
    r"|cannot|prohibited|forbidden|required|mandatory|apply|applies"
    r"|restriction|rule|policy|limitation|constraint|waived|void"
    r"|invalid|enforced|override|exception|unless|except"
    r"|notwithstanding|do not|does not|are not|is not)[^.!?\n]*[.!?\n]?)",
    re.IGNORECASE,
)


def _extract_imperative_sentences(text: str, max_sentences: int = 8) -> str:
    """Extract up to ``max_sentences`` sentences containing policy-language keywords."""
    matches = _CC_IMPERATIVE_SENTENCE_RE.findall(text)
    if not matches:
        # Fallback: return the first ~500 characters so the LLM has *something*.
        return text[:500].strip()
    return "\n".join(m.strip() for m in matches[:max_sentences])


def _check_cross_chunk_contradiction(
    file: DiscoveredFile,
    chunks: list[str],
    merged_result: LLMResult,
    llm_config: LLMConfig,
    ledger: LLMLedger | None = None,
) -> LLMResult:
    """Detect contradictions between the first and last chunks of an oversized file.

    Only runs when the merged chunk result is ``"safe"`` and uncompromised —
    a suspicious or malicious verdict from any single chunk already wins via
    merging, so there is no need for a second pass, and a compromised merged
    result must propagate *unchanged*: its ``compromised`` flag and
    ``compromised_reason`` (e.g. ``INJECTION_SUSPECTED``) drive the IPI900
    warning and the fusion-side escalation, and replacing the result — even
    with an escalation of our own — would silently clear that integrity
    signal while its "safe" verdict is not trustworthy to begin with.  When
    the merged verdict is safe we extract policy-language sentences from the
    first and last chunks and ask the LLM a focused contradiction question.
    On detection the verdict is upgraded to ``"suspicious"``; on any failure
    the original result is returned unchanged (graceful degradation,
    invariant S004).

    The LLM response is parsed as JSON and validated against the expected
    schema (``{"verdict": "CONTRADICTION"|"CONSISTENT"}``). On any parse
    or validation failure, the original result is returned unchanged
    (security invariant S003/S004 compliance). The probe is issued through
    :func:`call_raw_completion`, so it is budget-gated and token-accounted
    like every other call.
    """
    del file  # Kept for interface symmetry.

    if merged_result.verdict != "safe" or merged_result.compromised:
        return merged_result

    if len(chunks) < 2:
        return merged_result

    early_claims = _extract_imperative_sentences(chunks[0])
    late_claims = _extract_imperative_sentences(chunks[-1])

    if not early_claims or not late_claims:
        return merged_result

    prompt = CROSS_CHUNK_CONTRADICTION_PROMPT.format(
        early_claims=early_claims,
        late_claims=late_claims,
    )

    raw_text = call_raw_completion(
        [{"role": "user", "content": prompt}], llm_config, ledger=ledger
    )
    if raw_text is None:
        return merged_result

    # Parse and validate JSON response.
    cleaned = _strip_code_fence(raw_text)
    try:
        data = json.loads(cleaned)
    except (json.JSONDecodeError, ValueError):
        return merged_result

    if not isinstance(data, dict):
        return merged_result

    verdict = data.get("verdict")
    if verdict not in ("CONTRADICTION", "CONSISTENT"):
        return merged_result

    if verdict == "CONTRADICTION":
        return LLMResult(
            verdict="suspicious",
            confidence=0.7,
            findings=[
                LLMFinding(
                    line=0,
                    category="cross_chunk_contradiction",
                    explanation=(
                        "Cross-chunk contradiction detected: claims in the end "
                        "of the file contradict claims in the beginning"
                    ),
                )
            ],
            compromised=False,
        )

    return merged_result


def _process_oversized_file(
    file: DiscoveredFile,
    raw_bytes: bytes,
    static_result: StaticResult,
    llm_config: LLMConfig,
    ledger: LLMLedger | None = None,
) -> LLMResult:
    """Process a single file whose content exceeds ``TARGET_BATCH_TOKENS``.

    Chunks the content, sends each chunk as an individual LLM call, and
    merges the results.
    """
    extracted = extract_comments_and_strings(file, raw_bytes)
    sanitized = sanitize_content(extracted.encode("utf-8"), static_result.byte_findings)
    chunks = _chunk_content(sanitized, TARGET_BATCH_TOKENS)

    chunk_results: list[LLMResult] = []
    for chunk in chunks:
        chunk_results.append(classify_with_llm(file, chunk, llm_config, ledger=ledger))

    merged = _merge_chunk_results(chunk_results)
    return _check_cross_chunk_contradiction(file, chunks, merged, llm_config, ledger=ledger)


def _assemble_batches(
    code_files: list[tuple[DiscoveredFile, bytes, StaticResult]],
) -> list[BatchRequest]:
    """Assemble source code files into batches targeting ``TARGET_BATCH_TOKENS``.

    Adaptive fill: accumulates files until adding the next would exceed
    the target, then starts a new batch. The last batch may be smaller.

    Oversized files (content > ``TARGET_BATCH_TOKENS``) are NOT handled
    here — they must be processed by ``_process_oversized_file`` before
    batch assembly.
    """
    batches: list[BatchRequest] = []
    current_files: list[BatchFileInput] = []
    current_tokens: int = 0

    for file, raw_bytes, static_result in code_files:
        extracted = extract_comments_and_strings(file, raw_bytes)
        sanitized = sanitize_content(extracted.encode("utf-8"), static_result.byte_findings)
        file_tokens = count_tokens(sanitized)

        # Flush current batch if adding this file would exceed the target.
        if current_files and (current_tokens + file_tokens > TARGET_BATCH_TOKENS):
            batches.append(BatchRequest(files=current_files, estimated_tokens=current_tokens))
            current_files = []
            current_tokens = 0

        current_files.append(BatchFileInput(path=file.relative_path, content=sanitized))
        current_tokens += file_tokens

    # Flush final partial batch.
    if current_files:
        batches.append(BatchRequest(files=current_files, estimated_tokens=current_tokens))

    return batches


def _process_single_batch(
    batch: BatchRequest,
    code_files: list[tuple[DiscoveredFile, bytes, StaticResult]],
    batch_start_idx: int,
    llm_config: LLMConfig,
    ledger: LLMLedger | None = None,
) -> list[LLMResult]:
    """Process one batch: classify, handle partial failures with retry.

    ``batch_start_idx`` is the index into ``code_files`` where this batch
    begins. Returns one ``LLMResult`` per file in the batch (same order).
    """
    batch_result = classify_batch_with_llm(batch, llm_config, ledger=ledger)

    if batch_result.compromised:
        if batch_result.raw_response == FAILURE_SCHEMA:
            # The provider answered but the aggregate JSON stayed invalid even
            # after the repair retry — degrade to per-file classification, which
            # reuses the shared retry/repair policy for each file.
            all_indices = list(range(len(batch.files)))
            batch_files = [
                code_files[batch_start_idx + i][0] for i in range(len(batch.files))
            ]
            batch_contents = [f.content for f in batch.files]
            return retry_broken_files(
                batch_files, batch_contents, llm_config, all_indices, ledger=ledger
            )
        # Whole-batch provider/transport failure — every file is compromised.
        # Propagate the failure metadata (reason, raw response) so downstream
        # consumers see the real cause: an INJECTION_SUSPECTED batch must keep
        # its reason, letting confidence fusion escalate NONE-severity files to
        # REVIEW_REQUIRED instead of silently fusing them to PASS.
        return [
            LLMResult(
                verdict="safe",
                confidence=0.0,
                compromised=True,
                raw_response=batch_result.raw_response,
                compromised_reason=batch_result.compromised_reason,
            )
            for _ in batch.files
        ]

    file_results = batch_result.file_results

    # Retry broken entries individually.
    if batch_result.retry_indices:
        batch_files = [code_files[batch_start_idx + i][0] for i in range(len(batch.files))]
        batch_contents = [f.content for f in batch.files]
        retried = retry_broken_files(
            batch_files,
            batch_contents,
            llm_config,
            batch_result.retry_indices,
            ledger=ledger,
        )
        for offset, retry_result in enumerate(retried):
            idx = batch_result.retry_indices[offset]
            if idx < len(file_results):
                file_results[idx] = retry_result

    return file_results


def _cache_dir_exclude_pattern(cache_dir: Path | None, repo_path: Path) -> str | None:
    """Return a repo-relative exclude pattern for an in-tree cache directory.

    A response cache placed inside the scanned repository would otherwise be
    discovered (and re-scanned) on every run, feeding its own entries back into
    the scan. When the cache lives under the repo root, a gitignore-style
    directory pattern (``"<rel>/"``) is returned so discovery skips it. Returns
    ``None`` when caching is disabled or the cache lives outside the repository.
    """
    if cache_dir is None:
        return None
    try:
        rel = cache_dir.resolve().relative_to(repo_path.resolve())
    except (OSError, ValueError):
        return None
    rel_str = rel.as_posix()
    if not rel_str or rel_str == ".":
        return None
    return f"{rel_str}/"


# ---------------------------------------------------------------------------
# Suppression (T5.3 / IN-19): ``.ipi-checkignore`` + inline directives
# ---------------------------------------------------------------------------

#: Ignore file read from the repository root.
IGNORE_FILE_NAME: str = ".ipi-checkignore"

#: Fast pre-check before parsing a file's text for inline directives.
_INLINE_DIRECTIVE_MARKER: str = "ipi-check:ignore"

#: Matches an inline directive token only in a *comment context*: the token
#: must be preceded on the line by a comment marker (``#``, ``//``, ``/*``,
#: ``<!--``, ``--``, ``;``) itself at the line start or after whitespace, with
#: at most a short stretch of comment text between marker and token
#: (``# ipi-check:ignore[IPI006]``, ``x = 1  // ipi-check:ignore-file[IPI105]``).
#: A bare prose mention ("see ipi-check:ignore in docs") is NOT a directive —
#: untrusted content must not be able to suppress its own findings.
#:
#: The marker alone is NOT a trust boundary: in Markdown-family content ``#``
#: is a *heading* and ``<!--`` an HTML comment — ordinary attacker-writable
#: prose. :func:`build_suppression_policy` therefore honours inline directives
#: only in source-code files (``inline_directive_paths``), where a comment
#: marker is an author annotation, and only on lines the syntax tokenizer
#: classified as real comment tokens (a directive inside a string literal is
#: untrusted data); agent-instruction / dot-directory / skill files suppress
#: exclusively through the repository-root ``.ipi-checkignore``.
_INLINE_IGNORE_RE: re.Pattern[str] = re.compile(
    r"(?:^|\s)(?:<!--|--|//|/\*|#|;)[^\n]{0,40}?"
    r"ipi-check:ignore(?P<file>-file)?(?:\[(?P<rules>[^\]]*)\])?"
)

#: The bare directive token, anchored to the line start (optionally after a
#: block-comment decoration run of ``*``). Searched **only** on lines the
#: syntax tokenizer already classified as a real comment token (see
#: ``comment_lines`` in :func:`parse_inline_directives`): there the tokenizer
#: is the trust boundary and is strictly stronger than the same-line marker
#: heuristic, which cannot express a ``/* ... */`` continuation line — a
#: directive there is as much an author annotation as one after ``//``. The
#: line-start anchor keeps the prose-mention guard intact even inside
#: comments: ``see docs#ipi-check:ignore in the manual`` is not directive-
#: shaped and never matches.
_INLINE_IGNORE_TOKEN_RE: re.Pattern[str] = re.compile(
    r"^\s*(?:\*+/?\s*)?ipi-check:ignore(?P<file>-file)?(?:\[(?P<rules>[^\]]*)\])?"
)

#: A leading run of ``IPI###`` rule ids acting as the selector of an ignore-file
#: line (e.g. ``IPI105,IPI106 path/**``), optionally followed by a path pattern.
_RULE_SELECTOR_RE: re.Pattern[str] = re.compile(
    r"^\s*((?:IPI\d{3})(?:\s*,?\s*IPI\d{3})*)(?=\s|$)\s*(.*)$",
    re.IGNORECASE,
)

#: A single ``IPI###`` rule id.
_RULE_ID_RE: re.Pattern[str] = re.compile(r"^IPI\d{3}$")

_WARNING_IGNORE_FILE_FAILED: str = (
    "Could not read ignore file {path}: {err}; proceeding without it."
)

# Concrete PathSpec type for a single ignore-file path pattern.
_IgnorePathSpec = pathspec.PathSpec[_PathSpecPattern]


def _parse_rule_ids(text: str) -> frozenset[str]:
    """Parse a comma/whitespace separated list of ``IPI###`` rule ids."""
    tokens = [token.strip().upper() for token in re.split(r"[,\s]+", text) if token.strip()]
    return frozenset(token for token in tokens if _RULE_ID_RE.match(token))


def load_ignore_entries(ignore_path: Path) -> list[IgnoreEntry]:
    """Load and parse a ``.ipi-checkignore`` file (gitignore-style syntax).

    Each effective line is one of:

    * a gitignore path pattern -- suppresses every finding in matching files;
    * one or more ``IPI###`` rule ids, optionally followed by a path pattern --
      suppresses those rules in matching files, or in *every* file when no
      pattern is given.

    A leading ``!`` negates the entry (re-including findings suppressed by an
    earlier line); blank lines and ``#`` comments are ignored. A missing file
    yields an empty list.
    """
    if not ignore_path.is_file():
        return []
    try:
        text = ignore_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        warnings.warn(
            _WARNING_IGNORE_FILE_FAILED.format(path=ignore_path, err=exc),
            stacklevel=2,
        )
        return []

    entries: list[IgnoreEntry] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        negated = line.startswith("!")
        if negated:
            line = line[1:].strip()
            if not line:
                continue
        selector = _RULE_SELECTOR_RE.match(line)
        if selector is not None:
            rules: frozenset[str] | None = _parse_rule_ids(selector.group(1))
            pattern: str | None = selector.group(2).strip() or None
        else:
            rules = None
            pattern = line
        entries.append(IgnoreEntry(pattern=pattern, rules=rules, negated=negated))
    return entries


def parse_inline_directives(
    text: str, *, comment_lines: frozenset[int] | None = None
) -> FileDirectives:
    """Parse inline ``ipi-check:ignore`` directives from a file's text.

    Recognised forms (in any comment style -- ``#``, ``//``, ``/* ... */``,
    ``<!-- -->``, ``--``, ``;``):

    * ``ipi-check:ignore`` / ``ipi-check:ignore[]`` -- suppress every rule on
      the directive's line and the line below it;
    * ``ipi-check:ignore[IPI006]`` / ``ipi-check:ignore[IPI006,IPI101]`` --
      suppress the listed rules on the directive's line and the line below it
      (so the directive may sit on the same line as the finding, or directly
      above it);
    * ``ipi-check:ignore-file[...]`` -- the same, but scoped to the whole file.

    A selector that contains text but not a single valid ``IPI###`` id (a
    typo, or an internal pattern id like ``INSTR_001``) suppresses NOTHING:
    the empty set means "all rules", so honouring it would silently widen an
    unrecognized selector into a blanket suppression.

    Context-free parsing: this helper only applies the comment-marker
    heuristic to a line (the token must be preceded by a comment marker, so a
    bare prose mention of ``ipi-check:ignore`` is ignored). Whether a *file*
    may carry directives at all is a trust decision made by
    :func:`build_suppression_policy`, which honours them in source-code files
    only -- in markdown-family content ``#`` is a heading and ``<!--`` a
    comment, i.e. ordinary attacker-writable prose.

    ``comment_lines`` (the set of line numbers the syntax tokenizer classified
    as real comment tokens, see
    :func:`ipi_check.scanner.code_extractor.comment_line_numbers`) closes the
    string-literal channel: when given, a directive is honoured only when the
    match sits on a comment line, so ``# ipi-check:ignore`` inside a Python
    triple-quoted string is treated as the untrusted data it is. On such a
    tokenizer-confirmed comment line a *line-start* directive token (optionally
    after a ``*`` block-comment decoration, no same-line marker) is honoured
    too -- the syntax-aware check is the stronger boundary and covers
    ``/* ... */`` continuation lines, which the marker heuristic cannot
    express, while the line-start anchor keeps mid-line prose mentions from
    counting. ``None`` applies no line restriction (unit tests, trusted
    input) and requires the marker form.
    """
    directives = FileDirectives()
    # Split on "\n" only, never str.splitlines(): the directive's line number
    # must land on the same physical line the rest of the scanner counts.
    # comment_line_numbers() (the tokenizer trust boundary) and the pattern
    # matchers that produce the findings being suppressed both number lines
    # by "\n" — str.splitlines() additionally splits on \r, \v, \f, \x1c-\x1e,
    # \x85 and U+2028/2029, which would shift directive numbers off the
    # finding numbers and silently break (or mis-target) suppressions.
    for line_number, raw in enumerate(text.split("\n"), start=1):
        if comment_lines is not None and line_number not in comment_lines:
            continue
        match = _INLINE_IGNORE_RE.search(raw)
        if match is None:
            if comment_lines is None:
                continue
            # No comment marker precedes the token on this line. The line is
            # nevertheless a tokenizer-confirmed comment token, so the bare
            # form is honoured — the marker heuristic cannot express a
            # ``/* ... */`` continuation line, and the syntax-aware check is
            # the stronger trust boundary (a string literal carrying the
            # token was already rejected above).
            match = _INLINE_IGNORE_TOKEN_RE.search(raw)
            if match is None:
                continue
        raw_rules = match.group("rules")
        if raw_rules is not None and raw_rules.strip():
            rules = _parse_rule_ids(raw_rules)
            if not rules:
                # A selector was written but not a single token is a valid
                # ``IPI###`` id (a typo like ``[IPI99]``, or an internal
                # pattern id like ``INSTR_001``). Suppress NOTHING — an
                # empty set here conventionally means "all rules", which
                # would turn an unrecognized selector into a blanket,
                # silent over-suppression.
                continue
        else:
            rules = frozenset()
        if match.group("file"):
            directives.file_rules = rules
        else:
            directives.lines[line_number] = rules
    return directives


def _decode_text(raw_bytes: bytes) -> str:
    """Decode file bytes for directive scanning (lossy, never raises)."""
    return raw_bytes.decode("utf-8", errors="replace")


def build_suppression_policy(
    repo_path: Path,
    inline_bytes: dict[str, bytes],
    *,
    inline_directive_paths: frozenset[str] = frozenset(),
) -> SuppressionPolicy:
    """Assemble the scan's :class:`SuppressionPolicy`.

    ``inline_bytes`` maps a repository-relative path to the file's *raw bytes*
    for every discovered file and every bundled skill file. A file is only
    decoded when its bytes contain the ``ipi-check:ignore`` marker, so the
    policy stays tiny and the common case costs no extra decoding.

    ``inline_directive_paths`` is the set of paths whose inline directives are
    *honoured* — by construction the source-code files of the scan. Inline
    directives exist so a code author can annotate a deliberate exception next
    to a finding, the way ``# noqa`` does; that annotation context only exists
    in source code. Markdown-family files (agent instructions, dot-directory
    markdown, ``SKILL.md`` and bundled skill files) are *wholly untrusted
    prose*: there ``#`` is a heading and ``<!--`` an HTML comment, so an
    injected payload could otherwise suppress its own findings (spec invariant:
    untrusted content must not be able to suppress its own findings). Those
    files suppress through the repository-root ``.ipi-checkignore`` only. The
    default (empty set) honours no inline directives at all — fail closed.

    Within an honoured source file, a directive only counts when its line is a
    real comment token (Pygments, via
    :func:`ipi_check.scanner.code_extractor.comment_line_numbers`). A directive
    inside a string literal — e.g. ``# ipi-check:ignore-file`` embedded in a
    Python triple-quoted string — is untrusted data, not an author annotation,
    and is ignored; likewise when Pygments cannot tokenize the file, no
    directive is honoured (fail closed).
    """
    entries = load_ignore_entries(repo_path / IGNORE_FILE_NAME)
    marker = _INLINE_DIRECTIVE_MARKER.encode()
    inline: dict[str, FileDirectives] = {}
    for relative_path, raw in inline_bytes.items():
        if relative_path not in inline_directive_paths or marker not in raw:
            continue
        text = _decode_text(raw)
        directives = parse_inline_directives(
            text, comment_lines=comment_line_numbers(relative_path, text)
        )
        if directives.file_rules is not None or directives.lines:
            inline[relative_path] = directives
    return SuppressionPolicy(entries=entries, inline=inline)


@lru_cache(maxsize=512)
def _ignore_pathspec(pattern: str) -> _IgnorePathSpec:
    """Return (and cache) a gitignore PathSpec for a single ignore pattern."""
    return pathspec.PathSpec.from_lines("gitwildmatch", [pattern])


def _entry_matches(entry: IgnoreEntry, relative_path: str, rule_id: str) -> bool:
    """Return True when an ignore-file entry applies to a finding."""
    if entry.rules is not None and rule_id not in entry.rules:
        return False
    if entry.pattern is None:
        return True
    spec = _ignore_pathspec(entry.pattern)
    return spec.match_file(relative_path) or spec.match_file(relative_path + "/")


def _rules_cover(rules: frozenset[str], rule_id: str) -> bool:
    """Return True when a directive rule set covers ``rule_id`` (empty = all)."""
    return not rules or rule_id in rules


def resolve_suppression(
    policy: SuppressionPolicy | None,
    relative_path: str,
    rule_id: str,
    line: int | None,
) -> Suppression | None:
    """Resolve the suppression (if any) for one finding.

    External (``.ipi-checkignore``) entries are evaluated in order -- the last
    matching entry wins, and a ``!`` negation re-includes a finding. Inline
    (``inSource``) directives are applied afterwards and therefore take
    precedence over external entries.
    """
    if policy is None or policy.is_empty:
        return None

    suppressed = False
    kind: SuppressionKind | None = None
    justification: str = ""

    for entry in policy.entries:
        if not _entry_matches(entry, relative_path, rule_id):
            continue
        if entry.negated:
            suppressed = False
            kind = None
            justification = ""
        else:
            suppressed = True
            kind = SuppressionKind.EXTERNAL
            justification = (
                f"{rule_id} suppressed by .ipi-checkignore "
                f"({entry.pattern or 'all paths'})"
            )

    directives = policy.inline.get(relative_path)
    if directives is not None:
        if directives.file_rules is not None and _rules_cover(
            directives.file_rules, rule_id
        ):
            suppressed = True
            kind = SuppressionKind.IN_SOURCE
            justification = f"{rule_id} suppressed by inline ipi-check:ignore-file"
        if line is not None:
            # A line-scoped directive covers its own line and the line directly
            # below it, so both ``code  # ipi-check:ignore[RULE]`` and a
            # directive placed on the preceding line work.
            for directive_line in (line, line - 1):
                line_rules = directives.lines.get(directive_line)
                if line_rules is None or not _rules_cover(line_rules, rule_id):
                    continue
                suppressed = True
                kind = SuppressionKind.IN_SOURCE
                position = (
                    "on the same line" if directive_line == line else "on the preceding line"
                )
                justification = (
                    f"{rule_id} suppressed by inline ipi-check:ignore "
                    f"{position} (directive at line {directive_line})"
                )
                break

    if suppressed and kind is not None:
        return Suppression(kind=kind, justification=justification)
    return None


def run_pipeline(
    repo_path: Path,
    llm_config: LLMConfig | None,
    quiet: bool = False,
    *,
    verbose: bool = False,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
    max_llm_calls: int | None = None,
    llm_cache_dir: Path | None = None,
    jobs: int = 1,
    max_file_size: int | None = None,
) -> tuple[list[FinalVerdict], list[SkillFinalVerdict]]:
    """Run the complete scan pipeline.

    Orchestration:
        1. Discover files and skill units.
        2. Non-skill path: byte analysis → pattern matching → heuristics
           → LLM classification → fusion → ``FinalVerdict`` per file.
        3. Skill path: per-file skill-static analysis → optional LLM
           → fusion → one ``SkillFinalVerdict`` per skill.
        4. Return both file and skill verdicts.

    ``verbose`` adds stderr diagnostics (the resolved LLM configuration and
    the offending file/skill next to each degraded classification); it has no
    effect on the SARIF emitted on stdout. ``quiet`` suppresses all stderr
    output and takes precedence over ``verbose``.

    ``max_llm_calls`` caps the number of LLM API calls attempted for the scan
    (``None``/``0`` = unlimited); once reached, remaining files fall back to
    static analysis. ``llm_cache_dir`` enables the content-addressed response
    cache (also settable via ``IPI_CHECK_LLM_CACHE_DIR``): a repeated scan of
    unchanged files then issues no new API calls. Both are surfaced in the
    end-of-scan ``tokens in / tokens out`` summary unless ``quiet``.

    ``jobs`` controls how many worker processes run the three static-analysis
    passes in parallel (``1`` = in-process/sequential, the default). Results
    are order-independent, so ``jobs > 1`` yields an identical verdict set —
    only wall-clock time changes. ``max_file_size`` is the byte ceiling above
    which discovery skips a file (``None`` = the built-in 10 MB default).

    The function never calls :func:`sys.exit`; unexpected errors propagate
    up to the CLI for centralized error handling.
    """
    _emit(_PROGRESS_SCAN_START.format(repo_path=repo_path), quiet=quiet)

    # Resolve the (opt-in) response-cache directory up front so that a cache
    # placed inside the scanned tree can be excluded from discovery — otherwise
    # its own entries would be re-scanned on every subsequent run.
    cache_dir = resolve_llm_cache_dir(llm_cache_dir)
    effective_excludes: list[str] = list(exclude_patterns) if exclude_patterns else []
    cache_exclude = _cache_dir_exclude_pattern(cache_dir, repo_path)
    if cache_exclude is not None:
        effective_excludes.append(cache_exclude)

    discovered, skill_units = discover_files(
        repo_path,
        respect_gitignore=respect_gitignore,
        exclude_patterns=effective_excludes or None,
        max_file_size=max_file_size if max_file_size is not None else MAX_FILE_SIZE_BYTES,
    )
    _emit(_PROGRESS_DISCOVERED.format(count=len(discovered)), quiet=quiet)
    if skill_units:
        _emit(f"Detected {len(skill_units)} skill(s) for security audit", quiet=quiet)

    llm_enabled: bool = bool(llm_config is not None and is_llm_available(llm_config))

    # Per-scan LLM accounting: call budget, token usage, and (opt-in) response
    # cache. Threaded through every classification call below.
    ledger = LLMLedger(max_calls=max_llm_calls, cache_dir=cache_dir)

    verdicts: list[FinalVerdict] = []

    # ------------------------------------------------------------------
    # Static analysis phase: 3 passes — byte analysis, pattern matching and
    # heuristics — each showing independent progress. Files that fail I/O are
    # excluded early. With --jobs > 1 the passes are fanned out across a
    # process pool; results stay order-preserved, so the verdicts are identical.
    # ------------------------------------------------------------------

    # Pre-read all files.
    file_data: list[tuple[DiscoveredFile, bytes]] = []
    for file in discovered:
        raw_bytes = _read_bytes(file)
        if raw_bytes is None:
            continue
        file_data.append((file, raw_bytes))

    # Suppression policy (T5.3): the repository-root ``.ipi-checkignore`` plus
    # inline ``ipi-check:ignore`` directives. Bytes are reused from the
    # pre-read discovered files, and read for bundled skill files. Inline
    # directives are honoured in source-code files only — markdown-family
    # content is wholly untrusted prose and must suppress via the ignore file
    # (untrusted content must not be able to suppress its own findings).
    inline_bytes: dict[str, bytes] = {
        file.relative_path: raw_bytes for file, raw_bytes in file_data
    }
    for skill in skill_units:
        for skill_file in skill.files:
            relative_path = skill_file.relative_path
            if relative_path in inline_bytes:
                continue
            try:
                inline_bytes[relative_path] = skill_file.path.read_bytes()
            except OSError:
                continue
    inline_directive_paths = frozenset(
        file.relative_path for file, _ in file_data if file.category is FileCategory.SOURCE_CODE
    )
    suppression_policy = build_suppression_policy(
        repo_path, inline_bytes, inline_directive_paths=inline_directive_paths
    )
    if not suppression_policy.is_empty:
        _emit(
            "  [suppress]         "
            f"{len(suppression_policy.entries)} ignore-file rule(s), "
            f"{len(suppression_policy.inline)} file(s) with inline directives",
            quiet=quiet,
        )

    static_executor: ProcessPoolExecutor | None = None
    if jobs > 1 and len(file_data) > 1:
        static_executor = ProcessPoolExecutor(
            max_workers=jobs,
            mp_context=multiprocessing.get_context(_parallel_start_method()),
        )

    try:
        # Pass 1: Byte analysis.
        byte_results = _apply_static_pass(
            static_executor,
            jobs,
            _static_pass_bytes,
            file_data,
            stage=_STAGE_BYTE_ANALYSIS,
            quiet=quiet,
        )

        # Pass 2: Pattern matching.
        # For source code files, match patterns against extracted comments and
        # string literals only — avoiding FPs on code identifiers and Javadoc
        # phrases that coincidentally match injection patterns.
        pattern_results = _apply_static_pass(
            static_executor,
            jobs,
            _static_pass_patterns,
            file_data,
            stage=_STAGE_PATTERN_MATCHING,
            quiet=quiet,
        )

        # Pass 3: Semantic heuristics + assembly.
        heuristic_items: list[
            tuple[DiscoveredFile, bytes, list[ByteFinding], list[PatternFinding]]
        ] = [
            (file, raw_bytes, byte_findings, pattern_findings)
            for (file, raw_bytes), byte_findings, pattern_findings in zip(
                file_data, byte_results, pattern_results, strict=True
            )
        ]
        assembled = _apply_static_pass(
            static_executor,
            jobs,
            _static_pass_heuristics,
            heuristic_items,
            stage=_STAGE_HEURISTICS,
            quiet=quiet,
        )
    finally:
        if static_executor is not None:
            static_executor.shutdown()

    static_results: list[tuple[DiscoveredFile, bytes, StaticResult]] = [
        (file, raw_bytes, static_result)
        for (file, raw_bytes), static_result in zip(file_data, assembled, strict=True)
    ]

    # ------------------------------------------------------------------
    # LLM phase: skip entirely when no LLM is configured. Otherwise:
    #   1. Separate CRITICAL files → fuse with None (invariant I002).
    #   2. Non-code files → per-file classify_with_llm (unchanged flow).
    #   3. Source code files → batch processing:
    #      a. Oversized files (> TARGET_BATCH_TOKENS) → chunked per-file.
    #      b. Normal files → assemble into batches → classify_batch_with_llm.
    #      c. Partial batch failures → retry individual files.
    #      d. Fuse each file individually.
    # ------------------------------------------------------------------
    if not llm_enabled or llm_config is None:
        for _file, _raw, static_result in static_results:
            verdicts.append(fuse_verdicts(static_result, None))
        # A credential without a resolvable model is a misconfiguration, not an
        # intentional static-only scan — report it precisely (IN-13/T3.4).
        llm_reason = llm_unavailable_reason(llm_config) if llm_config is not None else None
        if llm_reason is None:
            _emit(_PROGRESS_LLM_SKIPPED, quiet=quiet)
        else:
            _emit(_WARNING_LLM_NO_MODEL.format(reason=llm_reason), quiet=quiet)
    else:
        if verbose:
            _emit(
                _PROGRESS_LLM_CONFIG.format(
                    model=resolve_model(llm_config) or _CONFIG_UNSET,
                    base_url=llm_config.base_url or _CONFIG_UNSET,
                    api_token="set" if llm_config.api_token else "from environment",
                ),
                quiet=quiet,
            )

        # Split into non-code and source-code streams (both exclude CRITICAL).
        all_non_critical: list[tuple[DiscoveredFile, bytes, StaticResult]] = [
            (f, b, sr) for f, b, sr in static_results if sr.severity != Severity.CRITICAL
        ]
        non_code_files, code_files = _split_static_results(all_non_critical)

        # CRITICAL files get immediate BLOCK via static-only fusion.
        for _file, _raw, sr in static_results:
            if sr.severity == Severity.CRITICAL:
                verdicts.append(fuse_verdicts(sr, None))

        llm_total: int = len(non_code_files) + len(code_files)
        llm_done: int = 0

        # --------------------------------------------------------------
        # Stream A: Non-code — per-file LLM (unchanged).
        # --------------------------------------------------------------
        for file, raw_bytes, sr in non_code_files:
            llm_result = _classify_via_llm(file, raw_bytes, sr, llm_config, ledger=ledger)
            _emit_llm_warning(
                llm_result, quiet=quiet, verbose=verbose, context=file.relative_path
            )
            verdicts.append(fuse_verdicts(sr, llm_result))
            llm_done += 1
            _emit_progress(_progress_bar(_STAGE_LLM, llm_done, llm_total), quiet=quiet)

        # --------------------------------------------------------------
        # Stream B: Source code — batch processing.
        # --------------------------------------------------------------
        if code_files:
            # Separate oversized files (process per-file with chunking).
            oversized: list[tuple[DiscoveredFile, bytes, StaticResult]] = []
            normal: list[tuple[DiscoveredFile, bytes, StaticResult]] = []
            for file, raw_bytes, sr in code_files:
                extracted = extract_comments_and_strings(file, raw_bytes)
                sanitized = sanitize_content(extracted.encode("utf-8"), sr.byte_findings)
                if count_tokens(sanitized) > TARGET_BATCH_TOKENS:
                    oversized.append((file, raw_bytes, sr))
                else:
                    normal.append((file, raw_bytes, sr))

            # Process oversized files individually.
            for file, raw_bytes, sr in oversized:
                llm_result = _process_oversized_file(
                    file, raw_bytes, sr, llm_config, ledger=ledger
                )
                _emit_llm_warning(
                    llm_result, quiet=quiet, verbose=verbose, context=file.relative_path
                )
                verdicts.append(fuse_verdicts(sr, llm_result))
                llm_done += 1
                _emit_progress(_progress_bar(_STAGE_LLM, llm_done, llm_total), quiet=quiet)

            # Assemble normal-sized files into batches.
            batches = _assemble_batches(normal)
            batch_idx = 0
            for batch in batches:
                batch_llm_results = _process_single_batch(
                    batch, normal, batch_idx, llm_config, ledger=ledger
                )
                for i, llm_result in enumerate(batch_llm_results):
                    file, _, sr = normal[batch_idx + i]
                    _emit_llm_warning(
                        llm_result, quiet=quiet, verbose=verbose, context=file.relative_path
                    )
                    verdicts.append(fuse_verdicts(sr, llm_result))
                    llm_done += 1
                    _emit_progress(_progress_bar(_STAGE_LLM, llm_done, llm_total), quiet=quiet)
                batch_idx += len(batch.files)

        _emit_progress(_progress_bar(_STAGE_LLM, llm_done, llm_total), quiet=quiet, final=True)

    # ------------------------------------------------------------------
    # Skill processing phase (Phase C).
    # Each skill unit gets: static analysis → optional LLM → fusion.
    # CRITICAL static severity short-circuits to BLOCK without LLM.
    # ------------------------------------------------------------------
    skill_verdicts: list[SkillFinalVerdict] = []

    if skill_units:
        # --- Skill static analysis ---
        skill_static_results: list[SkillStaticResult] = []
        for i, skill in enumerate(skill_units, 1):
            ssr = compute_skill_static_result(skill)
            skill_static_results.append(ssr)
            _emit_progress(
                _progress_bar(_STAGE_SKILL_STATIC, i, len(skill_units)),
                quiet=quiet,
            )
        _emit_progress(
            _progress_bar(_STAGE_SKILL_STATIC, len(skill_units), len(skill_units)),
            quiet=quiet,
            final=True,
        )

        # --- Skill LLM + fusion ---
        if llm_enabled and llm_config is not None:
            for i, ssr in enumerate(skill_static_results, 1):
                if ssr.aggregate_severity == Severity.CRITICAL:
                    # Invariant I002: CRITICAL → skip LLM, fuse with None.
                    skill_verdicts.append(fuse_skill_verdict(ssr, None))
                else:
                    llm_result = classify_skill_with_llm(ssr.skill, llm_config, ledger=ledger)
                    _emit_llm_warning(
                        llm_result,
                        quiet=quiet,
                        verbose=verbose,
                        context=ssr.skill.frontmatter.name,
                    )
                    skill_verdicts.append(fuse_skill_verdict(ssr, llm_result))
                _emit_progress(
                    _progress_bar(_STAGE_SKILL_LLM, i, len(skill_static_results)),
                    quiet=quiet,
                )
            _emit_progress(
                _progress_bar(
                    _STAGE_SKILL_LLM,
                    len(skill_static_results),
                    len(skill_static_results),
                ),
                quiet=quiet,
                final=True,
            )
        else:
            # No LLM → static-only fusion for all skills.
            for ssr in skill_static_results:
                skill_verdicts.append(fuse_skill_verdict(ssr, None))
            _emit(f"  [{_STAGE_SKILL_LLM}]              SKIPPED (no LLM configured)", quiet=quiet)

    # End-of-scan LLM accounting (call budget / token usage / cache hits).
    if llm_enabled:
        _emit_llm_usage(ledger, quiet=quiet)

    # Attach the suppression policy so the SARIF reporter can mark suppressed
    # findings without re-reading the repository (T5.3). Skipped entirely when
    # nothing can be suppressed, keeping the common case unchanged.
    if not suppression_policy.is_empty:
        for verdict in verdicts:
            verdict.suppression_policy = suppression_policy
        for skill_verdict in skill_verdicts:
            skill_verdict.suppression_policy = suppression_policy

    return verdicts, skill_verdicts
