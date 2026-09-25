"""Code Extractor — extract comments and string literals from source code via Pygments."""
from __future__ import annotations

import re
import warnings
from typing import Any

from ipi_check.core.types import DiscoveredFile, FileCategory

# Decoding configuration mirrors the rest of the scanner pipeline.
_TEXT_DECODE_ENCODING: str = "utf-8"
_TEXT_DECODE_ERRORS: str = "replace"

# Format used to label every extracted comment / string fragment with its
# starting line number. The ``[L{line}] {token_value}`` shape lets the LLM
# reason about location without re-parsing the source file.
_LINE_LABEL_FORMAT: str = "[L{line}] {value}"

# Label format for docstring fragments. The ``[DOC]`` tag marks the fragment
# as an *example region* for the pattern-matching layer (FP-5): a docstring is
# documentation text, so injection-like phrases quoted inside it are examples,
# not live instructions.
_DOC_LINE_LABEL_FORMAT: str = "[L{line}] [DOC] {value}"

# Label format for ordinary string literals. The ``[STR]`` tag marks the
# fragment as *data* (FP-11): a string value is not an instruction, so an
# attack string embedded in code keeps at most example-level severity. Comment
# fragments stay untagged, because prose comments are where a live injection
# actually hides.
_STR_LINE_LABEL_FORMAT: str = "[L{line}] [STR] {value}"

#: Warning emitted when Pygments is not installed.
_PYGMENTS_MISSING_WARNING: str = (
    "Pygments not available — sending full content to LLM"
)

#: Newline used both for counting and for joining extracted fragments.
_NEWLINE: str = "\n"

#: Matches a protocol token (``[DOC]`` / ``[STR]`` / ``[L42]``) at the very
#: start of *content* copied from the scanned file. The extractor neutralizes
#: such a prefix with one extra leading space when the emitted line is
#: untagged (a comment line or a fallback line): the matcher's line grammar
#: accepts exactly one space after its own label, so the extra space makes an
#: attacker-forged provenance tag unparseable while preserving the content.
_FORGED_PROTOCOL_PREFIX_RE: re.Pattern[str] = re.compile(
    r"^(?:\[DOC\]|\[STR\]|\[L\d+\])(?=\s|$)"
)


def _neutralize_protocol_prefix(line: str) -> str:
    """Prefix a content-leading protocol token with a space (anti-forgery)."""
    if _FORGED_PROTOCOL_PREFIX_RE.match(line):
        return f" {line}"
    return line


def _import_pygments() -> Any:
    """Return the ``pygments`` package, or ``None`` when it is not installed.

    Deferred import (Pygments is an optional dependency). This is the module's
    *single* Pygments import site: mypy reports an untyped import once per
    module per file, so keeping one site keeps the ``import-untyped``
    suppression — and the "is Pygments available?" fallback — in exactly one
    place.

    The ``lexers`` / ``token`` / ``util`` submodules are imported explicitly:
    a bare ``import pygments`` does **not** bind them as attributes of the
    parent package in a fresh interpreter (the package ``__init__`` does not
    import them itself), and every consumer in this module reaches them via
    ``pygments.<submodule>`` attribute access. Importing a submodule binds it
    on the parent package, which is what the callers below rely on.
    """
    try:
        import pygments  # type: ignore[import-untyped]
        import pygments.lexers  # type: ignore[import-untyped]
        import pygments.token  # type: ignore[import-untyped]
        import pygments.util  # type: ignore[import-untyped]
    except ImportError:
        return None
    return pygments


def comment_line_numbers(filename: str, text: str) -> frozenset[int]:
    """Return the 1-based numbers of lines that belong to real comment tokens.

    Pygments tokenizes ``text`` with the lexer implied by ``filename``; every
    physical line covered by a ``Comment`` token is returned. String literals,
    docstrings and code never qualify. When Pygments is unavailable or no
    lexer matches the filename, the result is empty — callers treat that as
    "no line may carry a trusted annotation" and fail closed: an inline
    ``ipi-check:ignore`` directive is an author annotation only when it sits
    in a real comment; inside a string literal it is untrusted data and must
    not suppress anything.
    """
    pygments = _import_pygments()
    if pygments is None:
        return frozenset()

    try:
        lexer = pygments.lexers.get_lexer_for_filename(filename)
    except pygments.util.ClassNotFound:
        return frozenset()

    comment_token = pygments.token.Comment
    lines: set[int] = set()
    current_line = 1
    for token_type, value in pygments.lex(text, lexer):
        if token_type in comment_token and value:
            # A comment token may END with the newline that terminates its
            # last line — C-family lexers (C/C++/Rust/C#) emit ``// …\n`` as
            # a single token. That trailing newline does NOT open a new
            # comment line: the line below belongs to the next token (often a
            # string literal). Marking it would let an attacker park an
            # inline ``ipi-check:ignore`` directive in a string on the line
            # after a ``//`` comment and have it honoured as a trusted
            # annotation. Count only the physical lines the comment *text*
            # actually occupies.
            occupied = value.rstrip(_NEWLINE)
            if occupied:
                lines.update(
                    range(current_line, current_line + occupied.count(_NEWLINE) + 1)
                )
        current_line += value.count(_NEWLINE)
    return frozenset(lines)


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
          prefixed with ``[L<line>]`` to preserve line context. Comment and
          string fragments alike are emitted one labelled line per physical
          line, so reported line numbers always match the source file and a
          forged ``[L..]``/``[DOC]``/``[STR]`` prefix can never sit at a line
          start (the extractor's own label always does).
        * If extraction yields nothing useful (no comments/strings found),
          fall back to the full decoded content, labelled per line
          (specification rule L009).
        * If Pygments is unavailable, emit a warning and fall back to the
          full decoded content.
    """
    if file.category != FileCategory.SOURCE_CODE:
        return _decode(raw_content)

    pygments = _import_pygments()
    if pygments is None:
        warnings.warn(_PYGMENTS_MISSING_WARNING, stacklevel=2)
        return _decode(raw_content)

    text = _decode(raw_content)

    try:
        lexer = pygments.lexers.get_lexer_for_filename(str(file.path))
    except pygments.util.ClassNotFound:
        lexer = pygments.lexers.TextLexer()

    extracted_fragments: list[str] = []
    current_line = 1

    for token_type, value in pygments.lex(text, lexer):
        is_target_token = (
            token_type in pygments.token.Comment
            or token_type in pygments.token.String
            or token_type in pygments.token.Literal.String
        )

        if is_target_token and value:
            # Every fragment is emitted **one labelled line per physical
            # line**. The leading ``[L{n}]`` label is what makes the
            # extractor→matcher protocol unforgeable: because the extractor
            # itself prefixes every emitted line, attacker-authored text can
            # never appear at a line start, so a payload cannot smuggle a
            # forged ``[L..] [DOC]``/"[STR]`` provenance tag (which the
            # pattern-matching layer would honour as an example-region mark)
            # or desynchronize reported line numbers.
            if token_type in pygments.token.Comment:
                # Comments are prose where a live instruction may be hidden —
                # keep them untagged (full severity; comments are never
                # example regions). A content-leading protocol token is
                # neutralized: a block-comment continuation line is attacker
                # text without a comment marker, and without the extra space
                # a forged "[DOC] " would occupy the tag position.
                for offset, sub_line in enumerate(value.split(_NEWLINE)):
                    extracted_fragments.append(
                        _LINE_LABEL_FORMAT.format(
                            line=current_line + offset,
                            value=_neutralize_protocol_prefix(sub_line),
                        )
                    )
            else:
                # String literals (including docstrings) are *data*, not
                # instructions. Emit one labelled line per physical line,
                # tagged so the pattern-matching layer treats quoted attack
                # strings as example regions.
                label = (
                    _DOC_LINE_LABEL_FORMAT
                    if token_type in pygments.token.String.Doc
                    else _STR_LINE_LABEL_FORMAT
                )
                for offset, sub_line in enumerate(value.split(_NEWLINE)):
                    extracted_fragments.append(
                        label.format(line=current_line + offset, value=sub_line)
                    )

        # Always advance the line counter using the token's literal text so
        # subsequent fragments retain accurate line numbers.
        current_line += value.count(_NEWLINE)

    extracted = _NEWLINE.join(extracted_fragments).strip()

    # L009 fallback — when no comments or string literals were found, we
    # send the full content so the LLM still receives something to inspect.
    # The fallback is labelled per line too: without labels, an attacker
    # could start a line of their (comment-free, string-free) source file
    # with a forged ``[L1] [DOC]`` prefix and have the pattern-matching layer
    # honour it as a string-literal example-region mark. A single trailing
    # empty piece (from the final newline) carries no content and is dropped.
    if not extracted:
        fallback_lines = text.split(_NEWLINE)
        if fallback_lines and fallback_lines[-1] == "":
            fallback_lines.pop()
        return _NEWLINE.join(
            _LINE_LABEL_FORMAT.format(
                line=index, value=_neutralize_protocol_prefix(line)
            )
            for index, line in enumerate(fallback_lines, start=1)
        )

    return extracted
