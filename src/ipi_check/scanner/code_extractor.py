"""Code Extractor — extract comments and string literals from source code via Pygments."""
from __future__ import annotations

import warnings

from ipi_check.core.types import DiscoveredFile, FileCategory

# Decoding configuration mirrors the rest of the scanner pipeline.
_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# Format used to label every extracted comment / string fragment with its
# starting line number. The ``[L{line}] {token_value}`` shape lets the LLM
# reason about location without re-parsing the source file.
_LINE_LABEL_FORMAT: str = "[L{line}] {value}"

#: Warning emitted when Pygments is not installed.
_PYGMENTS_MISSING_WARNING: str = (
    "Pygments not available — sending full content to LLM"
)

#: Newline used both for counting and for joining extracted fragments.
_NEWLINE: str = "\n"


def _decode(raw_content: bytes) -> str:
    """Decode ``raw_content`` using the scanner's standard UTF-8 strategy."""
    return raw_content.decode(_TEXT_DECODE_ENCODING, errors=_TEXT_DECODE_ERRORS)


def extract_comments_and_strings(
    file: DiscoveredFile, raw_content: bytes
) -> str:
    """Extract comments and string literals from source-code files.

    Behaviour:
        * Non-source-code files return their full decoded content unchanged.
        * For source code, Pygments tokenizes the file and only ``Comment.*``,
          ``String.*``, and ``Literal.String.*`` tokens are retained, each
          prefixed with ``[L<line>]`` to preserve line context.
        * If extraction yields nothing useful (no comments/strings found),
          fall back to the full decoded content (specification rule L009).
        * If Pygments is unavailable, emit a warning and fall back to the
          full decoded content.
    """
    if file.category != FileCategory.SOURCE_CODE:
        return _decode(raw_content)

    try:
        from pygments import lex  # type: ignore[import-untyped]
        from pygments.lexers import (  # type: ignore[import-untyped]
            TextLexer,
            get_lexer_for_filename,
        )
        from pygments.token import (  # type: ignore[import-untyped]
            Comment,
            Literal,
            String,
        )
        from pygments.util import ClassNotFound  # type: ignore[import-untyped]
    except ImportError:
        warnings.warn(_PYGMENTS_MISSING_WARNING, stacklevel=2)
        return _decode(raw_content)

    text = _decode(raw_content)

    try:
        lexer = get_lexer_for_filename(str(file.path))
    except ClassNotFound:
        lexer = TextLexer()

    extracted_fragments: list[str] = []
    current_line = 1

    for token_type, value in lex(text, lexer):
        is_target_token = (
            token_type in Comment
            or token_type in String
            or token_type in Literal.String
        )

        if is_target_token and value:
            extracted_fragments.append(
                _LINE_LABEL_FORMAT.format(line=current_line, value=value)
            )

        # Always advance the line counter using the token's literal text so
        # subsequent fragments retain accurate line numbers.
        current_line += value.count(_NEWLINE)

    extracted = _NEWLINE.join(extracted_fragments).strip()

    # L009 fallback — when no comments or string literals were found, we
    # send the full content so the LLM still receives something to inspect.
    if not extracted:
        return text

    return extracted
