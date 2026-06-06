"""Pattern Matching — Layer 3: regex-based injection phrase detection."""
from __future__ import annotations

import concurrent.futures
import re

from ipi_check.core.types import (
    DiscoveredFile,
    FileCategory,
    PatternFinding,
    PatternFindingCategory,
    Severity,
)

MAX_MATCHED_TEXT_LENGTH: int = 120
REGEX_TIMEOUT_SECONDS: float = 0.1

# (pattern_id, regex_string, category, severity)
INJECTION_PATTERNS: list[tuple[str, str, PatternFindingCategory, Severity]] = [
    # Instruction Override
    (
        "INSTR_001",
        r"(?:ignore|disregard|forget|override|skip|omit|neglect|discard"
        r"|abandon|erase|clear|wipe|overwrite|supersede|invalidate|nullify"
        r"|rescind)\s+(?:all\s+|any\s+|every\s+|the\s+entire\s+)?"
        r"(?:previous|prior|above|system|earlier|preceding|foregoing"
        r"|existing|original|initial|pre[- ]?established)\s+"
        r"(?:instructions?|prompts?|rules?|context|directives?|guidelines?"
        r"|constraints?|orders?|mandates?|restrictions?)",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Authority Claims
    (
        "AUTH_001",
        r"(?:you\s+(?:must|shall|are\s+required\s+to|have\s+to|need\s+to|will|absolutely\s+must)|these\s+rules?\s+(?:are|supersede|override|take\s+precedence|apply|govern))",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    (
        "AUTH_002",
        r"(?:non-?negotiable|highest\s+priority|cannot\s+be\s+(?:overridden|changed|modified|questioned|disobeyed)|must\s+not\s+be\s+(?:overridden|ignored|disobeyed|questioned)|mandatory|unconditional|absolute\s+(?:rule|command|directive|order))",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Destructive Commands
    (
        "DEST_001",
        r"(?:delete|remove|destroy|nuke|wipe|drop|erase|purge|annihilate|obliterate)\s+(?:all|every|any|the\s+entire)\s+",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    (
        "DEST_002",
        r"(?:rm\s+-rf|rmdir|shutil\.rmtree|os\.remove)",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    # Data Exfiltration
    (
        "EXFIL_001",
        r"(?:curl|wget|fetch|http\.?(?:get|post|request)|\.post\(|\.get\(|requests\.(?:get|post))\s+.*(?:attacker|evil|exfil|malicious|webhook|burp|collaborator|canary)",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    (
        "EXFIL_002",
        r"(?:send|post|upload|exfiltrate|forward|transfer|transmit|relay)\s+.*(?:to|towards)\s+(?:https?://|[a-z]+\.(?:com|io|net|org|dev|app))",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Shell Injection
    (
        "SHELL_001",
        r"(?:run|execute|eval|sh\s+-c|bash\s+-c|system\(|subprocess\.|os\.system|exec\(|popen)\s*[\"']?(?:curl|wget|nc|python|perl|ruby|node|powershell|cmd)",
        PatternFindingCategory.SHELL_INJECTION,
        Severity.CRITICAL,
    ),
    # Jailbreak
    (
        "JAIL_001",
        r"(?:you\s+are\s+now|new\s+persona|act\s+as\s+if|pretend\s+(?:you|that|to\s+be)|from\s+now\s+on\s+you|you\s+will\s+now|assume\s+(?:the\s+)?(?:role|identity|persona)\s+of)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    (
        "JAIL_002",
        r"(?:developer\s+mode|\bDAN\b|\bDUDE\b|do\s+anything\s+now|no\s+restrictions?|no\s+limitations?|unfiltered\s+mode|evil\s+mode|jailbreak\s+mode)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    # Instruction Override — "everything above/below/before/after"
    (
        "INSTR_002",
        r"(?:ignore|disregard|forget|skip|omit|erase|clear|override|discard|abandon)\s+(?:everything|all(?:\s+(?:of\s+)?(?:the\s+)?(?:content|text|instructions?|directives?|context))?)\s+(?:above|below|before|after|preceding|following)",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Multilingual Instruction Override — Russian
    (
        "INSTR_003",
        r"(?:игнорируй|забудь|пропусти|отмени)\s+(?:все|всю)\s+(?:предыдущие|предшествующие|вышеуказанные|прошлые|прежние)\s+(?:инструкции|указания|правила|команды|промпт)",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Authority Impersonation — Bracketed System Messages
    (
        "AUTH_003",
        r"\[(?:developer\s+message|admin|system\s+override|system\s+message|system)\]\s*(?:new\s+priority\s+instruction)?",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Copilot/VSCode CVE-2025-53773
    (
        "AUTH_005",
        r"(?:chat\.tools\.autoApprove|yolo\s+mode|\bauto-?approve\b|\.vscode/settings\.json)",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Expanded Data Exfiltration — Conversation Content
    (
        "EXFIL_003",
        r"(?:send|forward|leak|share|exfiltrate|transmit|relay|copy|dump|extract)\s+(?:(?:all|the|entire)\s+)?(?:conversation|chat|dialog|discussion|message|exchange)\s+(?:data|history|content|log|record|transcript|archive)",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Expanded Data Exfiltration — Last Messages
    (
        "EXFIL_004",
        r"(?:email|paste|output|print|display|copy|echo|cat|show|reveal)\s+(?:the\s+)?(?:last|previous|above|entire|full|complete)\s+(?:messages?|conversations?|chats?|responses?|dialog|exchange|interaction)",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Jailbreak Personas — STAN, Token System, Toxicity
    (
        "JAIL_003",
        r"(?:\bSTAN\b|strive\s+to\s+avoid\s+norms|token\s+system|gain\s+tokens?|run\s+out\s+of\s+tokens?|maximum\s+toxicity|no\s+content\s+filter|censorship\s+bypass)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    # Jailbreak Persona Role-Play
    (
        "JAIL_004",
        r"(?:immers(?:e|ing)\s+(?:yourself|oneself)\s+(?:into|in)\s+(?:the\s+)?(?:role|character|story|narrative)|act\s+as\s+(?:my\s+)?deceased|role-?play\s+as\s+(?:my\s+)?|you\s+are\s+(?:my\s+)?(?:therapist|girlfriend|boyfriend|assistant\s+with\s+no\s+rules))",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    # Social Engineering Pretext — Security Audit / Diagnostic Mode
    (
        "AUTH_004",
        r"(?:security\s+audit\s+in\s+progress|automated\s+security\s+scan|for\s+testing\s+purposes|(?:operating|running)\s+in\s+diagnostic\s+mode|maintenance\s+mode|this\s+is\s+a\s+(?:security|penetration)\s+test|urgent\s+(?:security\s+)?(?:update|patch|fix)\s+required|compliance\s+(?:check|verification|audit)\s+required|mandatory\s+(?:security\s+)?(?:update|review))",
        PatternFindingCategory.SOCIAL_ENGINEERING,
        Severity.MEDIUM,
    ),
    # Obfuscation — Decode Instructions
    (
        "OBFUSC_001",
        r"(?:decode|decrypt|deobfuscate|decipher|unscramble|unpack|reverse)\s+(?:this|the|following|below)\s+(?:base64|encoded|obfuscated|encrypted|hidden|concealed)\s+(?:string|text|content|block|payload|message|data)",
        PatternFindingCategory.OBFUSCATION,
        Severity.MEDIUM,
    ),
    # Obfuscation — Payload Splitting / Combine Codes
    (
        "OBFUSC_002",
        r"(?:combine|concatenate|join|merge|assemble|stitch|compose|splice|chain)\s+(?:all|the|these)\s+(?:codes?|parts?|pieces?|fragments?|strings?|chunks?|segments?|blocks?)\s+(?:and|to|then|together)\s+(?:execute|run|follow|perform|evaluate|apply)",
        PatternFindingCategory.OBFUSCATION,
        Severity.MEDIUM,
    ),
    # Multilingual Instruction Override — Chinese, French, Spanish, German
    (
        "INSTR_004",
        r"(?:忽略\s*所有\s*(?:之前|先前|以前)\s*(?:的\s*)?(?:指令|指示|说明|规则)|ignor(?:e[z]?|a)\s+t(?:outes?|odas?)\s+l(?:es|as?)\s+instruc(?:tions?|ciones)\s+(?:pr[eé]c[eé]dentes?|anteriores)|ignorier(?:e|en)\s+(?:Sie\s+)?alle\s+(?:vorherigen|vorangegangenen)\s+(?:Anweisungen|Befehle|Instruktionen))",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Multilingual Authority Claims — Russian
    (
        "AUTH_006",
        r"(?:эти\s+правила\s+(?:являются|имеют|обладают)\s+(?:обязательными|приоритетными|непреложными|высшим\s+приоритетом)|не\s+подлежит\s+(?:обсуждению|изменению|оспариванию)|необходимо\s+(?:выполнить|следовать|подчиниться)|ты\s+(?:должен|обязан|обязательно)\s+(?:выполнить|следовать|подчиниться))",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Multilingual Authority Claims — Chinese
    (
        "AUTH_007",
        r"(?:这些规则(?:是|具有)(?:强制性的|最高优先级的|不可更改的|不可协商的)|你必须(?:遵守|服从|执行)|绝对(?:规则|命令|指令)|不可(?:协商|更改|推翻))",
        PatternFindingCategory.AUTHORITY_CLAIM,
        Severity.HIGH,
    ),
    # Multilingual Destructive Commands — Russian
    (
        "DEST_003",
        r"(?:удали|сотри|уничтожь|сбрось|очисти|убери)\s+(?:все|всю|всё|весь)\s+",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    # Multilingual Destructive Commands — Chinese
    (
        "DEST_004",
        r"(?:删除|清除|销毁|抹除|移除)\s*(?:所有|全部|一切|整个)\s*",
        PatternFindingCategory.DESTRUCTIVE_COMMAND,
        Severity.CRITICAL,
    ),
    # Multilingual Data Exfiltration — Russian
    (
        "EXFIL_005",
        r"(?:отправь|перешли|загрузи|выгрузи|скопируй|передай|поделись)\s+(?:(?:все|всю|весь)\s+)?(?:разговор|чат|диалог|переписку|сообщения|историю)\s*(?:данных|сообщений)?",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Multilingual Data Exfiltration — Chinese
    (
        "EXFIL_006",
        r"(?:发送|转发|泄露|分享|上传|传输|复制)\s*(?:(?:所有|全部|整个)\s*)?(?:对话|聊天|讨论|消息|记录|历史)",
        PatternFindingCategory.DATA_EXFILTRATION,
        Severity.CRITICAL,
    ),
    # Multilingual Jailbreak — Russian
    (
        "JAIL_005",
        r"(?:ты\s+теперь|новая\s+(?:роль|личность|персона)|притворись|представь\s+(?:что|себя)|действуй\s+как|веди\s+себя\s+как|забудь\s+(?:свои|все)\s+(?:правила|ограничения|запреты)|режим\s+(?:разработчика|без\s+ограничений))",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    # Multilingual Jailbreak — Chinese
    (
        "JAIL_006",
        r"(?:你现在是|新(?:角色|人格|身份)|假装(?:你是|成为)|扮演|作为.*角色|忘记\s*(?:你的\s*)?(?:所有\s*)?(?:规则|限制|约束)|开发者模式|越狱模式|无限制模式)",
        PatternFindingCategory.JAILBREAK,
        Severity.HIGH,
    ),
    # Multilingual Obfuscation — Russian
    (
        "OBFUSC_003",
        r"(?:расшифруй|декодируй|деобфусцируй|расшифровать|декодировать)\s+(?:этот|эту|следующий|ниже)\s+(?:base64|закодированный|зашифрованный)\s+(?:текст|строку|содержимое|блок)",
        PatternFindingCategory.OBFUSCATION,
        Severity.MEDIUM,
    ),
    # Multilingual Obfuscation — Chinese
    (
        "OBFUSC_004",
        r"(?:解码|解密|去混淆|还原)\s*(?:这个|以下|下面的)\s*(?:base64|编码|加密|混淆)\s*(?:字符串|文本|内容|数据)",
        PatternFindingCategory.OBFUSCATION,
        Severity.MEDIUM,
    ),
    # Multilingual Social Engineering — Russian
    (
        "SOC_001",
        r"(?:проводится\s+(?:аудит|проверка)\s+безопасности|автоматическое\s+сканирование\s+безопасности|для\s+(?:тестирования|проверки|диагностики)|режим\s+(?:диагностики|обслуживания|тестирования)|это\s+(?:тест|проверка)\s+безопасности)",
        PatternFindingCategory.SOCIAL_ENGINEERING,
        Severity.MEDIUM,
    ),
    # Multilingual Social Engineering — Chinese
    (
        "SOC_002",
        r"(?:正在进行安全(?:审计|扫描|检查)|自动化安全(?:扫描|检测)|出于(?:测试|诊断)目的|(?:诊断|维护|测试)模式|这是(?:安全|渗透)测试)",
        PatternFindingCategory.SOCIAL_ENGINEERING,
        Severity.MEDIUM,
    ),
    # Multilingual Instruction Override — Japanese
    (
        "INSTR_005",
        r"(?:以前|これまで|上記|上記の)\s*(?:の|すべての)?\s*(?:指示|命令|ルール|プロンプト|ガイドライン)\s*(?:を|は)\s*(?:無視|忘れ|スキップ|破棄|上書き)",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Multilingual Instruction Override — Korean
    (
        "INSTR_006",
        r"(?:이전|위의|앞서|기존)\s*(?:모든|전체)?\s*(?:지시|명령|지침|규칙|프롬프트)\s*(?:를|을)?\s*(?:무시|잊어|건너뛰|폐기|덮어쓰기)(?:하세요|해|합니다)?",
        PatternFindingCategory.INSTRUCTION_OVERRIDE,
        Severity.CRITICAL,
    ),
    # Contradiction Discourse Markers — explicit negation of earlier rules
    (
        "CONTRA_001",
        r"(?:the\s+above\s+rules?\s+(?:do\s+not|don['’]t)\s+apply"
        r"|this\s+restriction\s+is\s+(?:waived|lifted|void|invalid|removed)"
        r"|previous\s+(?:limitations?|restrictions?|rules?|constraints?)\s+"
        r"(?:are|is)\s+(?:void|null|invalid|inapplicable|not\s+(?:applicable|enforced|valid|in\s+effect))"
        r"|all\s+(?:of\s+the\s+)?above\s+(?:is|are)\s+(?:now\s+)?(?:void|overridden|cancelled|invalidated|waived|disregarded)"
        r"|foregoing\s+(?:limitations?\s+)?(?:do\s+not|don['’]t)\s+apply"
        r"|the\s+preceding\s+(?:instructions?|rules?|directives?|limitations?)\s+(?:are|is)\s+(?:now\s+)?(?:void|waived|invalid))",
        PatternFindingCategory.INSTRUCTION_CONTRADICTION,
        Severity.HIGH,
    ),
    # Contradiction Discourse Markers — conditional override markers
    (
        "CONTRA_002",
        r"(?:however[,\s]+(?:these|those|the|all)\s+(?:restrictions?|rules?|limitations?|constraints?)\s+"
        r"(?:are\s+not|aren['’]t)\s+(?:enforced|applicable|valid|in\s+effect|binding|operative)"
        r"|but\s+actually[,\s]+(?:the\s+(?:above|previous|restrictions?|rules?|limitations?))\s+"
        r"(?:do\s+not|don['’]t)\s+(?:apply|matter|count)"
        r"|notwithstanding\s+(?:the\s+)?(?:above|previous|foregoing|anything|any\s+rule|any\s+thing\s+above)"
        r"|that\s+being\s+said[,\s]+(?:these|the|all)\s+(?:rules?|restrictions?|constraints?)\s+"
        r"(?:are\s+(?:no\s+longer|not)\s+(?:in\s+effect|applicable|enforced|valid)))",
        PatternFindingCategory.INSTRUCTION_CONTRADICTION,
        Severity.MEDIUM,
    ),
    # Contradiction Discourse Markers — exception carving in authority context
    (
        "CONTRA_003",
        r"(?:unless\s+(?:otherwise\s+)?(?:specifically\s+)?(?:indicated|stated|noted|specified|instructed|commanded)"
        r"|except\s+(?:when|if|where|as|for)\s+(?:otherwise\s+)?(?:specifically\s+)?(?:indicated|stated|noted|specified|permitted|allowed|authorized)"
        r"|save\s+(?:for|when)\s+(?:otherwise\s+)?(?:indicated|stated|authorized|permitted|allowed))",
        PatternFindingCategory.INSTRUCTION_CONTRADICTION,
        Severity.MEDIUM,
    ),
]

# Compiled patterns (case-insensitive)
_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str], PatternFindingCategory, Severity]] = [
    (pid, re.compile(pattern, re.IGNORECASE), category, severity)
    for pid, pattern, category, severity in INJECTION_PATTERNS
]

# Description templates per category.
_CATEGORY_DESCRIPTIONS: dict[PatternFindingCategory, str] = {
    PatternFindingCategory.INSTRUCTION_OVERRIDE: (
        "Instruction override pattern detected: attempts to bypass existing rules"
    ),
    PatternFindingCategory.AUTHORITY_CLAIM: (
        "Authority claim detected: attempts to establish rule priority"
    ),
    PatternFindingCategory.DESTRUCTIVE_COMMAND: (
        "Destructive command pattern detected: attempts to delete/destroy data"
    ),
    PatternFindingCategory.DATA_EXFILTRATION: (
        "Data exfiltration pattern detected: attempts to send data externally"
    ),
    PatternFindingCategory.SHELL_INJECTION: (
        "Shell injection pattern detected: attempts to execute arbitrary code"
    ),
    PatternFindingCategory.JAILBREAK: (
        "Jailbreak pattern detected: attempts persona/role manipulation"
    ),
    PatternFindingCategory.SOCIAL_ENGINEERING: (
        "Social engineering detected: false urgency or impersonated authority"
    ),
    PatternFindingCategory.OBFUSCATION: (
        "Obfuscation instruction detected: decode, combine, or deobfuscate hidden payloads"
    ),
    PatternFindingCategory.INSTRUCTION_CONTRADICTION: (
        "Instruction contradiction detected: discourse markers that negate or carve "
        "exceptions to earlier rules, potentially creating intra-file contradictions"
    ),
}

# Severity ordering (higher index → more severe).
_SEVERITY_ORDER: dict[Severity, int] = {
    Severity.NONE: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# Invisible character cleanup regex.
# - ANSI escape sequences (CSI/OSC and similar): ESC [ ... <letter>
# - Unicode tag block: U+E0000-U+E007F
# - Zero-width and line/paragraph separators: U+200B-U+200F, U+2028, U+2029
# - Bidi overrides: U+202A-U+202E, U+2066-U+2069
# - Variation selectors: U+FE00-U+FE0F
_INVISIBLE_CHARS_RE: re.Pattern[str] = re.compile(
    "\x1b\\[[^A-Za-z]*[A-Za-z]"
    "|[\U000e0000-\U000e007f]"
    "|[\u200b-\u200f\u2028\u2029]"
    "|[\u202a-\u202e\u2066-\u2069]"
    "|[\ufe00-\ufe0f]"
)

# Collapse runs of horizontal whitespace (anything in \s except '\n')
# to a single space. Newlines are preserved so callers can split by lines.
_HORIZONTAL_WS_RE: re.Pattern[str] = re.compile(r"[^\S\n]+")

# Regex to extract original line numbers from the ``[L{line}]`` prefix that
# ``extract_comments_and_strings`` attaches to each extracted fragment.
# Matches at the start of a line: ``[L42] rest of line...``.
_EXTRACTED_LINE_RE: re.Pattern[str] = re.compile(r"^\[L(\d+)\]\s")


def normalize_str(text: str) -> str:
    """Normalize an already-decoded string for pattern matching.

    Steps:
        1. Strip invisible characters (zero-width, Unicode tags, ANSI
           escapes, bidi overrides, variation selectors).
        2. Lowercase.
        3. Collapse runs of horizontal whitespace to a single space
           (newlines are preserved to allow line-based matching).

    This is the post-decode portion of :func:`normalize_text`, factored
    out so callers can normalize pre-extracted content (e.g., from
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`)
    without redundant decode.
    """
    stripped = _INVISIBLE_CHARS_RE.sub("", text)
    lowered = stripped.lower()
    collapsed = _HORIZONTAL_WS_RE.sub(" ", lowered)
    return collapsed


def normalize_text(raw_bytes: bytes) -> str:
    """Normalize raw bytes for pattern matching.

    Steps:
        1. Decode UTF-8 with ``errors="replace"``.
        2. Delegate to :func:`normalize_str` for the remaining steps
           (strip invisible chars, lowercase, collapse whitespace).
    """
    decoded = raw_bytes.decode("utf-8", errors="replace")
    return normalize_str(decoded)


def _truncate(text: str, limit: int = MAX_MATCHED_TEXT_LENGTH) -> str:
    """Truncate text to ``limit`` characters with an ellipsis suffix."""
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _downgrade_severity(severity: Severity, ceiling: Severity) -> Severity:
    """Cap ``severity`` at ``ceiling`` per ``_SEVERITY_ORDER``."""
    if _SEVERITY_ORDER[severity] > _SEVERITY_ORDER[ceiling]:
        return ceiling
    return severity


def _find_all_with_timeout(
    pattern: re.Pattern[str],
    line: str,
    executor: concurrent.futures.ThreadPoolExecutor,
) -> list[re.Match[str]] | None:
    """Run ``pattern.finditer`` against ``line`` with a thread-based timeout.

    Returns the list of matches on success, or ``None`` if the regex
    exceeded :data:`REGEX_TIMEOUT_SECONDS` (ReDoS protection).
    """
    future = executor.submit(lambda: list(pattern.finditer(line)))
    try:
        return future.result(timeout=REGEX_TIMEOUT_SECONDS)
    except concurrent.futures.TimeoutError:
        future.cancel()
        return None


def _parse_extracted_lines(target_text: str) -> tuple[list[int], str]:
    """Parse ``[L{line}]`` prefixes from extracted comment/string text.

    Returns a tuple of ``(original_line_numbers, clean_text)`` where
    ``original_line_numbers[i]`` is the source line number for the
    ``i``-th fragment line (1-based index) and ``clean_text`` has all
    ``[L{line}]`` prefixes stripped.

    When a line does not start with ``[L{line}]`` (e.g. L009 fallback
    where full content is returned), the fragment index itself is used
    as the line number — which matches the original file lines.
    """
    raw_lines = target_text.split("\n")
    line_numbers: list[int] = []
    clean_lines: list[str] = []
    for i, line in enumerate(raw_lines, start=1):
        m = _EXTRACTED_LINE_RE.match(line)
        if m:
            line_numbers.append(int(m.group(1)))
            clean_lines.append(line[m.end():])
        else:
            line_numbers.append(i)
            clean_lines.append(line)
    return line_numbers, "\n".join(clean_lines)


def match_patterns(
    file: DiscoveredFile,
    raw_bytes: bytes,
    target_text: str | None = None,
) -> list[PatternFinding]:
    """Match injection patterns against normalized file content.

    Each compiled pattern is executed line-by-line under a thread-based
    timeout to provide ReDoS protection. Findings carry 1-indexed line
    and column numbers relative to the normalized text.

    When ``target_text`` is provided (e.g., pre-extracted comments and
    strings from source code), it is normalized via :func:`normalize_str`
    instead of decoding ``raw_bytes``.  If ``target_text`` contains
    ``[L{line}]`` prefixes (produced by
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`),
    the original source line numbers are recovered and used in findings
    instead of the fragment indices.

    Severity downgrade rule: if the file is a Markdown file (``.md``)
    that is *not* categorised as an agent instruction document, the
    severity for every finding is capped at :data:`Severity.MEDIUM`.
    """
    line_numbers: list[int] | None = None

    if target_text is not None:
        line_numbers, clean_text = _parse_extracted_lines(target_text)
        normalized = normalize_str(clean_text)
    else:
        normalized = normalize_text(raw_bytes)
    if not normalized:
        return []

    is_non_agent_markdown = (
        file.category != FileCategory.AGENT_INSTRUCTION
        and file.path.suffix.lower() == ".md"
    )

    findings: list[PatternFinding] = []
    lines = normalized.split("\n")

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
        for line_index, line in enumerate(lines, start=1):
            if not line:
                continue
            actual_line = line_numbers[line_index - 1] if line_numbers else line_index
            for pattern_id, compiled, category, base_severity in _COMPILED_PATTERNS:
                matches = _find_all_with_timeout(compiled, line, executor)
                if matches is None:
                    # Timed out — skip this pattern on this line.
                    continue
                for match in matches:
                    severity = (
                        _downgrade_severity(base_severity, Severity.MEDIUM)
                        if is_non_agent_markdown
                        else base_severity
                    )
                    findings.append(
                        PatternFinding(
                            category=category,
                            severity=severity,
                            line=actual_line,
                            column=match.start() + 1,
                            matched_text=_truncate(match.group(0)),
                            pattern_id=pattern_id,
                            description=_CATEGORY_DESCRIPTIONS[category],
                        )
                    )

    return findings
