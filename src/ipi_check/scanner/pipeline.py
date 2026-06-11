"""Pipeline orchestrator — run the complete scan pipeline."""

from __future__ import annotations

import json
import re
import sys
import warnings
from typing import TYPE_CHECKING

from ipi_check.core.types import (
    BatchFileInput,
    BatchRequest,
    ByteFinding,
    DiscoveredFile,
    FileCategory,
    FinalVerdict,
    LLMConfig,
    LLMFinding,
    LLMResult,
    PatternFinding,
    Severity,
    SkillFinalVerdict,
    SkillStaticResult,
    StaticResult,
)
from ipi_check.scanner.byte_analysis import analyze_bytes
from ipi_check.scanner.code_extractor import extract_comments_and_strings
from ipi_check.scanner.confidence_fusion import fuse_skill_verdict, fuse_verdicts
from ipi_check.scanner.file_discovery import discover_files
from ipi_check.scanner.llm_classifier import (
    _strip_code_fence,
    classify_batch_with_llm,
    classify_skill_with_llm,
    classify_with_llm,
    is_llm_available,
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
    from pathlib import Path

# ---------------------------------------------------------------------------
# Progress message templates
# ---------------------------------------------------------------------------

_PROGRESS_SCAN_START: str = "Scanning {repo_path}..."
_PROGRESS_DISCOVERED: str = "Discovered {count} files to scan"
_PROGRESS_LLM_SKIPPED: str = "  [llm]              SKIPPED (no LLM configured)"
_WARNING_FILE_READ_FAILED: str = "Skipping file due to read error: {path} ({err})"
_WARNING_LLM_FALLBACK: str = "LLM API error: {msg} — falling back to static analysis"

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


def _emit_llm_warning(llm_result: LLMResult, *, quiet: bool) -> None:
    """Emit a warning to stderr when an LLM result is compromised."""
    if not llm_result.compromised:
        return
    msg = llm_result.raw_response or "classification failed"
    _emit(_WARNING_LLM_FALLBACK.format(msg=msg), quiet=quiet)


def _classify_via_llm(
    file: DiscoveredFile,
    raw_bytes: bytes,
    static_result: StaticResult,
    llm_config: LLMConfig,
) -> LLMResult:
    """Run code extraction → sanitization → LLM classification."""
    extracted = extract_comments_and_strings(file, raw_bytes)
    sanitized = sanitize_content(extracted.encode("utf-8"), static_result.byte_findings)
    return classify_with_llm(file, sanitized, llm_config)


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
      - If any chunk is compromised, the merged result is compromised.
    """
    if not chunk_results:
        return LLMResult(verdict="safe", confidence=0.0, compromised=True)

    worst_verdict = "safe"
    max_conf = 0.0
    any_compromised = False
    all_findings: list[LLMFinding] = []
    seen: set[tuple[int, str]] = set()

    for result in chunk_results:
        if result.compromised:
            any_compromised = True
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
) -> LLMResult:
    """Detect contradictions between the first and last chunks of an oversized file.

    Only runs when the merged chunk result is ``"safe"`` — a suspicious or
    malicious verdict from any single chunk already wins via merging, so
    there is no need for a second pass.  When the merged verdict is safe
    we extract policy-language sentences from the first and last chunks and
    ask the LLM a focused contradiction question.  On detection the verdict
    is upgraded to ``"suspicious"``; on any failure the original result is
    returned unchanged (graceful degradation, invariant S004).

    The LLM response is parsed as JSON and validated against the expected
    schema (``{"verdict": "CONTRADICTION"|"CONSISTENT"}``). On any parse
    or validation failure, the original result is returned unchanged
    (security invariant S003/S004 compliance).
    """
    del file  # Kept for interface symmetry.

    if merged_result.verdict != "safe":
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

    try:
        import litellm  # noqa: PLC0415 — deferred import

        response = litellm.completion(
            model=llm_config.model,
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=50,
            temperature=0.0,
            timeout=180,
            api_base=llm_config.base_url,
            api_key=llm_config.api_token,
        )

        raw_text = response.choices[0].message.content
        if not isinstance(raw_text, str):
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
    except Exception:  # noqa: BLE001 — graceful degradation
        # Any failure → return the original safe result unchanged.
        pass

    return merged_result


def _process_oversized_file(
    file: DiscoveredFile,
    raw_bytes: bytes,
    static_result: StaticResult,
    llm_config: LLMConfig,
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
        chunk_results.append(classify_with_llm(file, chunk, llm_config))

    merged = _merge_chunk_results(chunk_results)
    return _check_cross_chunk_contradiction(file, chunks, merged, llm_config)


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
) -> list[LLMResult]:
    """Process one batch: classify, handle partial failures with retry.

    ``batch_start_idx`` is the index into ``code_files`` where this batch
    begins. Returns one ``LLMResult`` per file in the batch (same order).
    """
    batch_result = classify_batch_with_llm(batch, llm_config)

    if batch_result.compromised:
        # Entire batch failed — all files get compromised.
        return [LLMResult(verdict="safe", confidence=0.0, compromised=True) for _ in batch.files]

    file_results = batch_result.file_results

    # Retry broken entries individually.
    if batch_result.retry_indices:
        batch_files = [code_files[batch_start_idx + i][0] for i in range(len(batch.files))]
        batch_contents = [f.content for f in batch.files]
        retried = retry_broken_files(
            batch_files, batch_contents, llm_config, batch_result.retry_indices
        )
        for offset, retry_result in enumerate(retried):
            idx = batch_result.retry_indices[offset]
            if idx < len(file_results):
                file_results[idx] = retry_result

    return file_results


def run_pipeline(
    repo_path: Path,
    llm_config: LLMConfig | None,
    quiet: bool = False,
    *,
    respect_gitignore: bool = True,
    exclude_patterns: list[str] | None = None,
) -> tuple[list[FinalVerdict], list[SkillFinalVerdict]]:
    """Run the complete scan pipeline.

    Orchestration:
        1. Discover files and skill units.
        2. Non-skill path: byte analysis → pattern matching → heuristics
           → LLM classification → fusion → ``FinalVerdict`` per file.
        3. Skill path: per-file skill-static analysis → optional LLM
           → fusion → one ``SkillFinalVerdict`` per skill.
        4. Return both file and skill verdicts.

    The function never calls :func:`sys.exit`; unexpected errors propagate
    up to the CLI for centralized error handling.
    """
    _emit(_PROGRESS_SCAN_START.format(repo_path=repo_path), quiet=quiet)

    discovered, skill_units = discover_files(
        repo_path,
        respect_gitignore=respect_gitignore,
        exclude_patterns=exclude_patterns,
    )
    _emit(_PROGRESS_DISCOVERED.format(count=len(discovered)), quiet=quiet)
    if skill_units:
        _emit(f"Detected {len(skill_units)} skill(s) for security audit", quiet=quiet)

    llm_enabled: bool = bool(llm_config is not None and is_llm_available(llm_config))

    verdicts: list[FinalVerdict] = []

    # ------------------------------------------------------------------
    # Static analysis phase: 3 sequential passes so each stage shows
    # independent progress. Files that fail I/O are excluded early.
    # ------------------------------------------------------------------

    # Pre-read all files.
    file_data: list[tuple[DiscoveredFile, bytes]] = []
    for file in discovered:
        raw_bytes = _read_bytes(file)
        if raw_bytes is None:
            continue
        file_data.append((file, raw_bytes))

    readable_total: int = len(file_data)

    # Pass 1: Byte analysis.
    byte_results: list[list[ByteFinding]] = []
    for i, (file, raw_bytes) in enumerate(file_data, 1):
        byte_results.append(analyze_bytes(file, raw_bytes))
        _emit_progress(_progress_bar(_STAGE_BYTE_ANALYSIS, i, readable_total), quiet=quiet)
    _emit_progress(
        _progress_bar(_STAGE_BYTE_ANALYSIS, readable_total, readable_total),
        quiet=quiet,
        final=True,
    )

    # Pass 2: Pattern matching.
    # For source code files, match patterns against extracted comments and
    # string literals only — avoiding FPs on code identifiers and Javadoc
    # phrases that coincidentally match injection patterns.
    pattern_results: list[list[PatternFinding]] = []
    for i, (file, raw_bytes) in enumerate(file_data, 1):
        if file.category == FileCategory.SOURCE_CODE:
            extracted = extract_comments_and_strings(file, raw_bytes)
            pattern_results.append(
                match_patterns(file, raw_bytes, target_text=extracted)
            )
        else:
            pattern_results.append(match_patterns(file, raw_bytes))
        _emit_progress(_progress_bar(_STAGE_PATTERN_MATCHING, i, readable_total), quiet=quiet)
    _emit_progress(
        _progress_bar(_STAGE_PATTERN_MATCHING, readable_total, readable_total),
        quiet=quiet,
        final=True,
    )

    # Pass 3: Semantic heuristics + assembly.
    static_results: list[tuple[DiscoveredFile, bytes, StaticResult]] = []
    for i, ((file, raw_bytes), byte_findings, pattern_findings) in enumerate(
        zip(file_data, byte_results, pattern_results, strict=True), 1
    ):
        visible_text = _get_visible_text(raw_bytes)
        heuristic_scores = compute_heuristics(file, raw_bytes, visible_text, byte_findings)
        static_result = assemble_static_result(
            file, byte_findings, pattern_findings, heuristic_scores
        )
        static_results.append((file, raw_bytes, static_result))
        _emit_progress(_progress_bar(_STAGE_HEURISTICS, i, readable_total), quiet=quiet)
    _emit_progress(
        _progress_bar(_STAGE_HEURISTICS, readable_total, readable_total),
        quiet=quiet,
        final=True,
    )

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
        _emit(_PROGRESS_LLM_SKIPPED, quiet=quiet)
    else:
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
            llm_result = _classify_via_llm(file, raw_bytes, sr, llm_config)
            _emit_llm_warning(llm_result, quiet=quiet)
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
                llm_result = _process_oversized_file(file, raw_bytes, sr, llm_config)
                _emit_llm_warning(llm_result, quiet=quiet)
                verdicts.append(fuse_verdicts(sr, llm_result))
                llm_done += 1
                _emit_progress(_progress_bar(_STAGE_LLM, llm_done, llm_total), quiet=quiet)

            # Assemble normal-sized files into batches.
            batches = _assemble_batches(normal)
            batch_idx = 0
            for batch in batches:
                batch_llm_results = _process_single_batch(batch, normal, batch_idx, llm_config)
                for i, llm_result in enumerate(batch_llm_results):
                    _emit_llm_warning(llm_result, quiet=quiet)
                    _, _, sr = normal[batch_idx + i]
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
                    llm_result = classify_skill_with_llm(ssr.skill, llm_config)
                    _emit_llm_warning(llm_result, quiet=quiet)
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

    return verdicts, skill_verdicts
