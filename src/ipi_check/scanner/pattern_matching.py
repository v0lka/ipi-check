"""Pattern Matching — Layer 3: regex-based injection phrase detection."""
from __future__ import annotations

import re

import regex

from ipi_check.core.invisible import strip_invisible
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

# Skill-specific patterns for IPI401–411.
# These detect *malicious behaviour* in agent skills, not just instruction presence.

# Sensitive credential environment-variable names, defined once and reused by
# every IPI402 sub-pattern so the list cannot drift out of sync.
_CREDENTIAL_ENV_VARS: str = (
    r"AWS_ACCESS_KEY_ID|AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|GH_TOKEN"
    r"|NPM_TOKEN|DOCKER_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY"
    r"|GEMINI_API_KEY|COHERE_API_KEY|HUGGINGFACE_TOKEN"
    r"|JWT_SECRET|SSH_PRIVATE_KEY|PRIVATE_KEY|AZURE_OPENAI_KEY"
)

# Environment accessors that *read* a value (Python: os.environ/os.getenv,
# Node: process.env, C/shell: getenv).
_ENV_ACCESSORS: str = r"(?:os\.environ|os\.getenv|process\.env|getenv)"

# Outbound-transmission sinks, used to detect a credential read that sits right
# next to exfiltration ("reads a secret on its way out").
_CREDENTIAL_EXFIL_SINKS: str = (
    r"(?:curl|wget|(?:requests|urllib)\.(?:post|get|put|patch|request)|https?://)"
)

# IPI402 sub-patterns — credential *harvesting* means the secret value is
# actually read (accessed in code or expanded in shell) or read next to an
# outbound transmission. A bare mention of the variable name is NOT harvesting
# (FP-8: presence ≠ theft), and a read of a *non-credential* variable next to
# a URL is ordinary code (FP-9).
_IPI402_CODE_READ: str = (
    _ENV_ACCESSORS
    + r"\s*(?:\.\s*get\s*)?[\[\(\.]\s*['\"]?(?:"
    + _CREDENTIAL_ENV_VARS
    + r")\b"
)
_IPI402_SHELL_READ: str = r"\$\{?(?:" + _CREDENTIAL_ENV_VARS + r")\b\}?"
#: A *credential* read (either form), used as the anchor of the corroborated
#: read+transmit patterns so that ``os.getenv("BASE_URL", "https://…")`` —
#: an accessor of a non-credential variable that merely contains a URL — is
#: not mistaken for harvesting.
_IPI402_CREDENTIAL_READ: str = r"(?:" + _IPI402_CODE_READ + r"|" + _IPI402_SHELL_READ + r")"
_IPI402_READ_THEN_SINK: str = (
    _IPI402_CREDENTIAL_READ + r"[^\n]{0,160}?" + _CREDENTIAL_EXFIL_SINKS
)
_IPI402_SINK_THEN_READ: str = (
    _CREDENTIAL_EXFIL_SINKS + r"[^\n]{0,160}?" + _IPI402_CREDENTIAL_READ
)

# ---------------------------------------------------------------------------
# Context-sensitive severity model (T1.2 — FP-5 / FP-6 / FP-9 / FP-10)
# ---------------------------------------------------------------------------
#
# A bare ``curl https://…`` or a bare ``sudo`` is not proof of malice: a
# legitimate deployment skill downloads release assets and reads secrets, and a
# build script routinely runs ``rm -rf dist``.  Severity therefore depends on
# *context*, not on the mere presence of a token:
#
# * external transmission (IPI403) is baseline MEDIUM; it rises to CRITICAL only
#   when the destination is a known exfiltration host (``evil``, ``webhook``,
#   ``interact.sh``, …) or when the same file also reads a credential (IPI402);
#   a destination on the trusted-domain allowlist is LOW (informational).
# * credential harvesting (IPI402) is HIGH when the secret is merely *read* and
#   CRITICAL when it is read *and* transmitted (corroboration).
# * privilege escalation (IPI410) is HIGH for a bare privileged invocation and
#   CRITICAL only for an inherently destructive escalation (``chmod 7xx``,
#   ``chown root``, ``pkexec``, or ``sudo`` driving ``rm -rf``/``dd``/``mkfs``).
# * a destructive command (``DEST_002`` / ``rm -rf``) in a build manifest is
#   MEDIUM unless it targets a dangerous root/home/system path.

#: Hosts a legitimate skill may contact: package registries, source hosting,
#: common deployment / LLM APIs, OS package mirrors, and loopback.  A
#: transmission to one of these is informational (``LOW``), not an accusation.
#: Configurable — extend this frozenset to add project-specific trusted hosts.
TRUSTED_DOMAINS: frozenset[str] = frozenset(
    {
        # Package registries
        "registry.npmjs.org",
        "registry.yarnpkg.com",
        "pypi.org",
        "files.pythonhosted.org",
        "rubygems.org",
        "crates.io",
        "static.crates.io",
        "repo.maven.apache.org",
        "plugins.gradle.org",
        "api.nuget.org",
        # Source hosting / release assets. Read/download-oriented hosts only:
        # write-capable API endpoints (``api.github.com`` — gists, issues,
        # …) are deliberately absent, because posting secrets to them is
        # exfiltration (an attacker-controlled gist is a write target, not a
        # package mirror).
        "github.com",
        "codeload.github.com",
        "objects.githubusercontent.com",
        "raw.githubusercontent.com",
        "gitlab.com",
        "bitbucket.org",
        # Common deployment / cloud APIs
        "api.vercel.com",
        "vercel.com",
        "api.netlify.com",
        "api.cloudflare.com",
        "storage.googleapis.com",
        "s3.amazonaws.com",
        # LLM provider APIs (a legitimate skill may call these)
        "api.openai.com",
        "api.anthropic.com",
        "generativelanguage.googleapis.com",
        # OS package mirrors
        "deb.debian.org",
        "archive.ubuntu.com",
        "security.ubuntu.com",
        # Loopback
        "localhost",
        "127.0.0.1",
    }
)

#: Host fragments that mark an outbound destination as a likely exfiltration
#: sink.  A transmission to such a host is CRITICAL regardless of the allowlist.
#: The single-word fragments are label-anchored (``\b…\b`` / ``\boast\.``) so
#: ordinary domains that merely *contain* the fragment (``roast.io``,
#: ``coast.org``, ``stealth.io``, ``toastify.app``, ``photo-transfer.shop``)
#: are not misclassified as exfiltration sinks.
_EXFIL_DOMAIN_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"attacker|exfil|malicious|backdoor|\bbeacon\b|\bc2\b"
    r"|webhook|burpcollaborator|\bburp\b|collaborator"
    r"|canarytoken|requestbin|pipedream|pastebin|ngrok"
    r"|\bevil\b|\bsteal\b"
    r"|\boastify\b|\boast\."
    r"|\binteract\.sh\b|\btransfer\.sh\b"
    r")",
    re.IGNORECASE,
)

#: Extract the host component from every URL in a text (user info and port
#: stripped, lower-cased).
_URL_HOST_RE: re.Pattern[str] = re.compile(
    r"https?://([^/\s'\"<>()]+)", re.IGNORECASE
)

#: Baseline severity for an external transmission to an unclassified host.
EXTERNAL_TRANSMISSION_BASELINE: Severity = Severity.MEDIUM
#: Severity for an external transmission to an allowlisted host.
EXTERNAL_TRANSMISSION_TRUSTED: Severity = Severity.LOW

#: Manifest files where cleanup of *relative* build output is routine.
BUILD_CONFIG_FILENAMES: frozenset[str] = frozenset({"package.json"})
#: Severity applied to ``DEST_002`` (``rm -rf``) inside a build manifest.
DEST_002_BUILD_CONTEXT_SEVERITY: Severity = Severity.MEDIUM
#: A destructive target that is *never* routine: the filesystem root, a root
#: wildcard (``/*``, ``*``, ``./*``), the home directory, a system directory,
#: or a parent directory. Each alternative is anchored to a token boundary so
#: a benign relative path (`dist/`, `build`) is not mistaken for one.
_DANGEROUS_DEST_TARGET_RE: re.Pattern[str] = re.compile(
    r"(?:^|[\s\"'=(,])"
    r"(?:"
    r"/(?![A-Za-z0-9._-])"  # filesystem root "/" or "/*"
    r"|\.?/?\*+(?![\w./-])"  # a wildcard target: "*", "./*", "**"
    r"|~(?![A-Za-z0-9._-])|~\w"  # home directory "~", "~/", "~user"
    r"|\$HOME\b|\$\{HOME\}"
    r"|/(?:etc|usr|var|bin|sbin|lib|boot|opt|root|home|srv|mnt|media|Users)"
    r"(?![A-Za-z0-9_-])"  # a system directory
    r"|\.\.(?![A-Za-z0-9._-])"  # parent directory ".."
    r")",
    re.IGNORECASE,
)

#: Patterns whose match is skipped when the text immediately before it is a
#: *prohibition* — advice against a privileged action is not privilege
#: escalation (FP-10: "не запускай sudo" / "do not use sudo"). English and
#: Russian negations (the FP-10 report cites a Russian-language repo).
_NEGATION_GUARDED_PATTERN_IDS: frozenset[str] = frozenset({"IPI410"})
_NEGATED_PRIVILEGE_RE: re.Pattern[str] = re.compile(
    r"(?:\b(?:not|never|no|avoid|without)\b|\bdon['’]t\b|\bcannot\b|\bcan['’]t\b)"
    r"\s+(?:use|run|invoke|execute|call|require|need|start|launch)?\s*$"
    r"|\b(?:не|никогда|нельзя|избегай)\b"
    r"\s+(?:запускай|запускать|используй|использовать|выполняй|выполнять"
    r"|вызывай|вызывать)?\s*$"
)

#: The destructive payload that turns a bare `sudo` into a CRITICAL escalation.
#: Shared by the CRITICAL IPI410 pattern and the negative look-ahead on the
#: bare-`sudo` HIGH pattern, so the two never both fire on the same span.
_PRIV_DESTRUCTIVE_PAYLOAD: str = (
    r"(?:rm\s+-[a-z]*[rf]|dd\s+if=|mkfs|shred\b|>\s*/dev/sd)"
)

SKILL_PATTERNS: list[tuple[str, str, PatternFindingCategory, Severity]] = [
    # IPI401 — Remote code execution: curl/wget piped to interpreter
    (
        "IPI401",
        r"(?:curl|wget|fetch)\s+.+(?:\||>)\s*(?:bash|sh|zsh|python[23]?|perl|ruby|node)\b",
        PatternFindingCategory.REMOTE_EXECUTION,
        Severity.CRITICAL,
    ),
    (
        "IPI401",
        r"(?:marshal\.loads|pickle\.loads?|eval\s*\(|exec\s*\()"
        r".*(?:b64decode|base64|__import__)",
        PatternFindingCategory.REMOTE_EXECUTION,
        Severity.CRITICAL,
    ),
    # IPI402 — Credential harvesting: a sensitive secret is actually *read*
    # (accessed in code or expanded in shell). A bare mention of the variable
    # name is not harvesting (FP-8).
    (
        "IPI402",
        _IPI402_CODE_READ,
        PatternFindingCategory.CREDENTIAL_HARVESTING,
        Severity.HIGH,
    ),
    (
        "IPI402",
        _IPI402_SHELL_READ,
        PatternFindingCategory.CREDENTIAL_HARVESTING,
        Severity.HIGH,
    ),
    # IPI402 — Credential harvesting combined with transmission: a *credential*
    # read co-located with an outbound sink (either order) on the same line.
    # This is the *corroborated* form — the secret is read **and** sent — so it
    # is CRITICAL, whereas merely reading a secret is HIGH (T1.2 corroboration).
    # A transmission whose every destination host is allowlisted is refined
    # back to HIGH in ``match_skill_patterns`` (FP-9).
    (
        "IPI402",
        _IPI402_READ_THEN_SINK,
        PatternFindingCategory.CREDENTIAL_HARVESTING,
        Severity.CRITICAL,
    ),
    (
        "IPI402",
        _IPI402_SINK_THEN_READ,
        PatternFindingCategory.CREDENTIAL_HARVESTING,
        Severity.CRITICAL,
    ),
    # IPI403 — External data transmission: curl/wget/requests to URLs.
    # Baseline MEDIUM: a skill may legitimately download an asset or call an
    # API. Severity is refined per match in ``match_skill_patterns`` — LOW for
    # an allowlisted host, CRITICAL for a known exfil host or when the file also
    # reads a credential (corroboration, FP-9).
    (
        "IPI403",
        r"(?:curl|wget|fetch)\s+.*https?://",
        PatternFindingCategory.EXTERNAL_TRANSMISSION,
        EXTERNAL_TRANSMISSION_BASELINE,
    ),
    (
        "IPI403",
        r"(?:requests|http|urllib)\.(?:post|get|put|delete|request)"
        r"\s*\(.{0,80}https?://",
        PatternFindingCategory.EXTERNAL_TRANSMISSION,
        EXTERNAL_TRANSMISSION_BASELINE,
    ),
    # IPI404 — Dynamic context abuse: !`command` syntax. This is also a
    # legitimate skill feature, so it is reported as informational (LOW) rather
    # than HIGH by default (FP-7).
    (
        "IPI404",
        r"!`[^`]+`",
        PatternFindingCategory.DYNAMIC_CONTEXT,
        Severity.LOW,
    ),
    # IPI405 — Excessive permissions: wildcard in allowed-tools
    (
        "IPI405",
        r"allowed[-_]tools:\s*.+\*",
        PatternFindingCategory.EXCESSIVE_PERMISSIONS,
        Severity.HIGH,
    ),
    # IPI406 — Obfuscated skill code: base64 decode / atob
    (
        "IPI406",
        r"(?:base64\s+-[dD]|b64decode|atob\s*\(|frombase64string"
        r"|base64\.b64decode)",
        PatternFindingCategory.OBFUSCATED_SKILL_CODE,
        Severity.MEDIUM,
    ),
    # IPI407 — Hidden HTML-comment instructions
    (
        "IPI407",
        r"<!--.*(?:ignore|bypass|secret|hidden|do\s+not\s+tell"
        r"|conceal|covert|backdoor).*-->",
        PatternFindingCategory.HIDDEN_INSTRUCTIONS,
        Severity.HIGH,
    ),
    # IPI408 — Command injection in body: "run this command: ```"
    (
        "IPI408",
        r"(?:run|execute|type|paste)\s+(?:this|the|following|below)"
        r"\s+(?:command|code|script).{0,80}```",
        PatternFindingCategory.COMMAND_INJECTION_SKILL,
        Severity.CRITICAL,
    ),
    # IPI409 — Secrecy/coercion: instructions to hide behaviour from the user.
    # An explicit concealment phrase is required; a bare authority word such as
    # "MANDATORY" (or a bare adverb like "silently") is NOT secrecy (FP-6).
    (
        "IPI409",
        r"(?:do\s+not\s+(?:tell|reveal|mention|inform|share|disclose|notify"
        r"|alert|warn)\s+[^\n]{0,40}?(?:the\s+)?(?:user|anyone|anybody|them)\b"
        r"|(?:do\s+not|don['’]t)\s+let\s+(?:the\s+)?(?:user|anyone|anybody|them)"
        r"\s+know)",
        PatternFindingCategory.SKILL_SECRECY,
        Severity.CRITICAL,
    ),
    (
        "IPI409",
        r"(?:without\s+(?:telling|informing|notifying|alerting|advising|warning)\b"
        r"|(?:do\s+not|don['’]t)\s+(?:disclose|reveal|divulge)\b"
        r"|\bmust\s+not\s+(?:disclose|reveal|divulge)\b"
        r"|\b(?:covertly|secretly|furtively|clandestinely)\b)",
        PatternFindingCategory.SKILL_SECRECY,
        Severity.HIGH,
    ),
    # IPI410 — Privilege escalation: an escalating primitive that is inherently
    # destructive → CRITICAL (chmod 7xx, chown root, pkexec, or `sudo` driving a
    # destructive command such as `rm -rf`). A *bare* privileged invocation is
    # HIGH, not CRITICAL (FP-10).
    (
        "IPI410",
        r"(?:chmod\s+.*[0-7]*7[0-7]*[0-7]*|chown\s+root|pkexec\b"
        r"|sudo\b[^\n]{0,40}?" + _PRIV_DESTRUCTIVE_PAYLOAD + r")",
        PatternFindingCategory.PRIVILEGE_ESCALATION,
        Severity.CRITICAL,
    ),
    # IPI410 — Bare privileged invocation (`sudo`): a privilege-escalation
    # *attempt*, but not proof of malice on its own → HIGH. A prohibition
    # ("do not use sudo") is suppressed by the negation guard, and a destructive
    # sudo (`sudo rm -rf`, `sudo;rm -rf`) is already CRITICAL above — the
    # negative look-ahead exactly complements the CRITICAL pattern's separator
    # (`[^\n]`), so the two never both fire on the same span (FP-10).
    (
        "IPI410",
        r"\bsudo\b(?![^\n]{0,40}?" + _PRIV_DESTRUCTIVE_PAYLOAD + r")",
        PatternFindingCategory.PRIVILEGE_ESCALATION,
        Severity.HIGH,
    ),
    # IPI411 — Filesystem enumeration
    (
        "IPI411",
        r"(?:find\s+/(?:\s|$)|scan\s+(?:the\s+)?filesystem|os\.walk\s*\("
        r"|walk\s*\(\s*['\"]/|listdir\s*\(\s*['\"]/"
        r"|glob\.glob\s*\(\s*['\"]/)",
        PatternFindingCategory.FILE_SYSTEM_ENUMERATION,
        Severity.MEDIUM,
    ),
]

# Compiled patterns (case-insensitive) using the `regex` library for timeout support.
_COMPILED_PATTERNS: list[tuple[str, regex.Pattern[str], PatternFindingCategory, Severity]] = [
    (pid, regex.compile(pattern, regex.IGNORECASE), category, severity)
    for pid, pattern, category, severity in INJECTION_PATTERNS
]

_COMPILED_SKILL_PATTERNS: list[tuple[str, regex.Pattern[str], PatternFindingCategory, Severity]] = [
    (pid, regex.compile(pattern, regex.IGNORECASE), category, severity)
    for pid, pattern, category, severity in SKILL_PATTERNS
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

# Description templates per skill-specific category.
_SKILL_CATEGORY_DESCRIPTIONS: dict[PatternFindingCategory, str] = {
    PatternFindingCategory.REMOTE_EXECUTION: (
        "Remote execution pattern detected: downloads and executes remote code"
    ),
    PatternFindingCategory.CREDENTIAL_HARVESTING: (
        "Credential harvesting detected: a sensitive environment credential is "
        "read or transmitted"
    ),
    PatternFindingCategory.EXTERNAL_TRANSMISSION: (
        "External data transmission detected: sends data to remote URLs"
    ),
    PatternFindingCategory.DYNAMIC_CONTEXT: (
        "Dynamic context usage detected: uses !`command` to inject runtime context "
        "(informational — a legitimate skill feature)"
    ),
    PatternFindingCategory.EXCESSIVE_PERMISSIONS: (
        "Excessive permissions detected: wildcard tool access in allowed-tools"
    ),
    PatternFindingCategory.OBFUSCATED_SKILL_CODE: (
        "Obfuscated code detected: base64 decode or similar deobfuscation"
    ),
    PatternFindingCategory.HIDDEN_INSTRUCTIONS: (
        "Hidden instructions detected: HTML comments containing suspicious directives"
    ),
    PatternFindingCategory.COMMAND_INJECTION_SKILL: (
        "Command injection detected: instructs running arbitrary commands"
    ),
    PatternFindingCategory.SKILL_SECRECY: (
        "Secrecy/coercion detected: instructs hiding behaviour from the user"
    ),
    PatternFindingCategory.PRIVILEGE_ESCALATION: (
        "Privilege escalation detected: sudo, chmod 7xx, or chown root"
    ),
    PatternFindingCategory.FILE_SYSTEM_ENUMERATION: (
        "Filesystem enumeration detected: scanning or walking the filesystem"
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

# Invisible-character cleanup (ANSI escapes + Unicode tags / zero-width /
# separators / bidi controls / variation selectors) is defined exactly once in
# ``ipi_check.core.invisible`` and reused here via ``strip_invisible``.

# Collapse runs of horizontal whitespace (anything in \s except '\n')
# to a single space. Newlines are preserved so callers can split by lines.
_HORIZONTAL_WS_RE: re.Pattern[str] = re.compile(r"[^\S\n]+")

#: Private Use Area codepoints (``U+E000``–``U+F8FF``), stripped during
#: normalization (see :func:`normalize_str`): a single PUA character spliced
#: into a keyword would otherwise defeat every injection regex, while the
#: byte layer still reports the PUA usage independently.
_PUA_RE: re.Pattern[str] = re.compile(r"[\ue000-\uf8ff]")

# Regex to extract original line numbers from the ``[L{line}]`` prefix that
# ``extract_comments_and_strings`` attaches to each extracted fragment.
# Matches at the start of a line: ``[L42] rest of line...`` — with exactly
# ONE space after the label (and after the tag), because the extractor emits
# exactly one space; a content line whose own text begins with a tag-like
# token is emitted with an extra leading space (see the extractor), so the
# grammar below can never mistake attacker text for provenance.
# Fragments that originated from a source-code *string literal* — a docstring
# (``[DOC]``) or any other string value (``[STR]``) — additionally carry a tag
# (``[L42] [DOC] rest of line...`` / ``[L42] [STR] rest of line...``), which
# marks them as an *example region* — see :func:`_detect_example_regions`.
_EXTRACTED_LINE_RE: re.Pattern[str] = re.compile(
    r"^\[L(\d+)\] (?:(?P<example>\[DOC\]|\[STR\]) )?"
)


def normalize_str(text: str) -> str:
    """Normalize an already-decoded string for pattern matching.

    Steps:
        1. Strip invisible characters (zero-width, Unicode tags, ANSI
           escapes, bidi overrides, variation selectors) **and Private Use
           Area codepoints** (``U+E000``–``U+F8FF``). PUA characters have no
           legitimate meaning inside prose or code identifiers, and a single
           one spliced into a keyword (``ign\\ue000ore``) would otherwise
           defeat every injection regex — the byte layer still reports the
           PUA usage independently (IPI004), so nothing is lost.
        2. Lowercase.
        3. Collapse runs of horizontal whitespace to a single space
           (newlines are preserved to allow line-based matching).

    This is the post-decode portion of :func:`normalize_text`, factored
    out so callers can normalize pre-extracted content (e.g., from
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`)
    without redundant decode.
    """
    stripped = _PUA_RE.sub("", strip_invisible(text))
    lowered = stripped.lower()
    collapsed = _HORIZONTAL_WS_RE.sub(" ", lowered)
    return collapsed


def normalize_text(raw_bytes: bytes) -> str:
    """Normalize raw bytes for pattern matching.

    Steps:
        1. Decode UTF-8 with ``errors="replace"``.
        2. Delegate to :func:`normalize_str` for the remaining steps
           (strip invisible/PUA chars, lowercase, collapse whitespace).
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


def _is_build_config_file(file: DiscoveredFile) -> bool:
    """Return ``True`` for a build manifest (e.g. ``package.json``)."""
    return file.path.name.lower() in BUILD_CONFIG_FILENAMES


def _destructive_target_is_dangerous(line: str, match_end: int) -> bool:
    """Return ``True`` when a destructive command targets a dangerous path.

    Inspects the text following the matched command (e.g. ``rm -rf``) for the
    filesystem root, a root wildcard, the home directory, a system directory, or
    a parent-directory reference. Only a benign, relative target may be capped.
    """
    return bool(_DANGEROUS_DEST_TARGET_RE.search(line[match_end : match_end + 80]))


def _url_hosts(text: str) -> list[str]:
    """Return the lower-cased hosts of every URL in ``text``.

    Userinfo and port are stripped: ``user:pw@Host:443`` → ``host``. All URLs
    matter — severity decisions must not be maskable by placing a trusted URL
    in front of the real destination.
    """
    hosts: list[str] = []
    for match in _URL_HOST_RE.finditer(text):
        host = match.group(1).lower()
        host = host.rsplit("@", 1)[-1]
        hosts.append(host.split(":", 1)[0])
    return hosts


def _looks_like_negated_privilege(line: str, start: int) -> bool:
    """Return ``True`` when the text before ``start`` is a prohibition.

    Suppresses IPI410 on advice *against* a privileged action ("do not use
    sudo", "never run sudo"), which is the opposite of privilege escalation
    (FP-10). The prohibition must sit immediately before the command.
    """
    prefix = line[max(0, start - 40) : start]
    return bool(_NEGATED_PRIVILEGE_RE.search(prefix))


def _parse_extracted_lines(target_text: str) -> tuple[list[int], list[bool], str]:
    """Parse ``[L{line}]`` / ``[L{line}] [DOC|STR]`` prefixes from extracted text.

    Returns a tuple ``(original_line_numbers, example_flags, clean_text)``
    where:

    * ``original_line_numbers[i]`` is the source line number for the ``i``-th
      fragment line (1-based index),
    * ``example_flags[i]`` is ``True`` when the ``i``-th fragment line
      originates from a source-code string literal — a docstring (``[DOC]``)
      or any other string value (``[STR]``) — and therefore belongs to an
      example region, and
    * ``clean_text`` has all ``[L{line}]`` / ``[DOC]`` / ``[STR]`` prefixes
      stripped.

    When a line does not start with ``[L{line}]`` (defensive: non-protocol
    input such as the Pygments-unavailable fallback), the fragment index
    itself is used as the line number and the line is never treated as an
    example region — unlabelled input fails closed.
    """
    raw_lines = target_text.split("\n")
    line_numbers: list[int] = []
    example_flags: list[bool] = []
    clean_lines: list[str] = []
    for i, line in enumerate(raw_lines, start=1):
        m = _EXTRACTED_LINE_RE.match(line)
        if m:
            line_numbers.append(int(m.group(1)))
            example_flags.append(m.group("example") is not None)
            clean_lines.append(line[m.end():])
        else:
            line_numbers.append(i)
            example_flags.append(False)
            clean_lines.append(line)
    return line_numbers, example_flags, "\n".join(clean_lines)


# ---------------------------------------------------------------------------
# Example-region detection (FP-5 / FP-11)
# ---------------------------------------------------------------------------
#
# Attack *examples* quoted in documentation (fenced code blocks, markdown
# tables, inline ``code`` spans) and in source-code string literals (string
# values and docstrings) are not live instructions. A ``PatternFinding`` that
# begins inside such an "example region" is capped at
# :data:`EXAMPLE_REGION_SEVERITY_CEILING`, so a quoted example can never
# produce a CRITICAL/BLOCK verdict on its own.
#
# The machinery is deliberately conservative — a region must be *explicit*
# (a code fence, a table, an inline-code span, a string literal / docstring,
# or a list introduced by an "examples: / например: / payload:" cue). Content
# outside these regions — notably source-code *comments*, where a live
# injection actually hides — is matched at full severity, so a real injection
# keeps its CRITICAL rating (recall is preserved). Two scope restrictions
# close the wrap-the-payload evasion paths: fences are not example regions in
# agent-instruction files (the whole file is the instruction channel), and
# markdown framing never applies to extracted source-code content (only the
# extractor's [DOC]/[STR] tags do — a comment cannot frame itself with
# backticks, a fake fence or a fake table).

#: Severity ceiling applied to findings inside an example region.
EXAMPLE_REGION_SEVERITY_CEILING: Severity = Severity.MEDIUM

#: Opening/closing fence of a fenced code block (``` or ~~~), with at most
#: three leading spaces (CommonMark §4.5: four spaces make an indented code
#: block, not a fence). The trailing ``(.*)`` captures the info string; a
#: *backtick* fence whose info string contains a backtick (`` ```x``` ``) is
#: prose, not a fence — this is enforced by the caller, not the regex.
_FENCE_RE: re.Pattern[str] = re.compile(r"^ {0,3}(`{3,}|~{3,})(.*)$")

#: A markdown list item ("- ", "* ", "+ ", "1. ", "1) ").
_LIST_ITEM_RE: re.Pattern[str] = re.compile(r"^\s*(?:[-*+]\s+|\d+[.)]\s+)")

#: A run of one or more backticks (used to pair inline-code delimiters).
_BACKTICK_RUN_RE: re.Pattern[str] = re.compile(r"`+")

#: Cue phrases that introduce a quoted example. Deliberately label-like
#: (":", "such as", "for example", …) so that ordinary prose containing the
#: bare word "example" (e.g. a URL host ``example.com``) is not treated as a
#: cue. Non-English cues follow the same rule: they must be a label
#: ("пример:", "quote:") or a phrase that *introduces* an example
#: ("например", "例如"). Multilingual: RU and CN.
_EXAMPLE_CUE_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"\be\.g\.?"
    r"|\bfor example\b|\bfor instance\b|\bsuch as\b"
    r"|\bexamples?\b[^:：\n]{0,40}[:：]"
    r"|\battack examples?\b|\bexample attacks?\b"
    r"|\bpayloads?\s*[:：]"
    r"|\bquotes?\s*[:：]"
    r"|\bнапример\b|\bпример(?:ы)?\b[^:：\n]{0,40}[:：]"
    r"|\bобразец(?:ы)?\s*[:：]|\bцитат(?:а|ы)?\s*[:：]|\bпейлоад\s*[:：]"
    r"|示例|例如|例子|载荷\s*[:：]"
    r")"
)

#: The *label-like* subset of the cues above — a colon-terminated label
#: (``examples:``, ``payload:``, ``пример:``). A label cue marks its whole
#: line as an example region; a bare phrase cue ("for example, …", "such as")
#: only introduces the list that *follows* — marking the phrase-cue line
#: itself would let an attacker cap a live instruction at ``MEDIUM`` simply by
#: prefixing it with "for example,".
_EXAMPLE_CUE_LABEL_RE: re.Pattern[str] = re.compile(
    r"(?:"
    r"\bexamples?\b[^:：\n]{0,40}[:：]"
    r"|\bpayloads?\s*[:：]"
    r"|\bquotes?\s*[:：]"
    r"|\bнапример\s*[:：]|\bпример(?:ы)?\b[^:：\n]{0,40}[:：]"
    r"|\bобразец(?:ы)?\s*[:：]|\bцитат(?:а|ы)?\s*[:：]|\bпейлоад\s*[:：]"
    r"|载荷\s*[:：]"
    r")"
)


def _is_table_delimiter(line: str) -> bool:
    """Return ``True`` for a markdown table delimiter row (``| --- | --- |``).

    Implemented without a regex (a simple character-set check) to avoid any
    ReDoS exposure on adversarial input: the stripped line must contain both
    a pipe and a dash, and consist only of ``|``, ``-``, ``:`` and spaces.
    """
    stripped = line.strip()
    return "|" in stripped and "-" in stripped and all(c in "|-: " for c in stripped)


def _inline_code_spans(line: str) -> list[tuple[int, int]]:
    """Return ``(start, end)`` spans of inline-code delimiters in ``line``.

    A span covers the opening backtick run through the matching closing run
    of *equal length* (CommonMark's rule), so ``a `b` c`` yields the span
    around ``b``. Unpaired runs are ignored.
    """
    spans: list[tuple[int, int]] = []
    runs = list(_BACKTICK_RUN_RE.finditer(line))
    index = 0
    while index + 1 < len(runs):
        opening, closing = runs[index], runs[index + 1]
        if len(opening.group(0)) == len(closing.group(0)):
            spans.append((opening.start(), closing.end()))
            index += 2
        else:
            index += 1
    return spans


def _mark_cued_list(lines: list[str], block: list[bool], start: int) -> int:
    """Mark the list/indented lines that follow an example cue.

    Starting at ``start + 1`` (the line after the cue), mark contiguous list
    items and indented continuation lines — together with any blank lines
    that separate them — as example regions. Returns the index of the first
    line *not* absorbed, so the caller can resume scanning there.
    """
    total = len(lines)
    index = start + 1
    pending_blanks = 0
    while index < total:
        line = lines[index]
        if not line.strip():
            pending_blanks += 1
            index += 1
            continue
        if _LIST_ITEM_RE.match(line) or line.startswith(" "):
            for blank_index in range(index - pending_blanks, index + 1):
                block[blank_index] = True
            pending_blanks = 0
            index += 1
            continue
        break
    return index


def _is_valid_fence_open(match: re.Match[str]) -> bool:
    """Return ``True`` when a ``_FENCE_RE`` match may open a code fence.

    CommonMark §4.5: the info string of a *backtick* fence must not contain
    backticks — `` ```ignore … ``` `` on one line is an ordinary paragraph, not
    a fence. A tilde fence's info string may contain anything (including
    backticks and tildes).
    """
    return match.group(1)[0] == "~" or "`" not in match.group(2)


def _is_valid_fence_closer(
    match: re.Match[str], fence_char: str, run_length: int
) -> bool:
    """Return ``True`` when a ``_FENCE_RE`` match closes the given fence.

    A closing fence uses the same character, a run at least as long as the
    opener's, and nothing but spaces after the run (CommonMark §4.5).
    """
    return (
        match.group(1)[0] == fence_char
        and len(match.group(1)) >= run_length
        and not match.group(2).strip()
    )


def _detect_example_regions(
    lines: list[str],
    source_example_flags: list[bool] | None = None,
    *,
    fences_are_examples: bool = True,
    markdown_regions: bool = True,
) -> tuple[list[bool], list[list[tuple[int, int]]]]:
    """Classify every line of ``lines`` as inside / outside an example region.

    Returns ``(block_flags, inline_spans)`` where ``block_flags[i]`` marks a
    whole line that lies inside a block example region (fenced code, markdown
    table, cued example list, or a source-code string literal) and
    ``inline_spans[i]`` lists the column spans of inline-code fragments on
    line ``i``.

    ``source_example_flags`` (from :func:`_parse_extracted_lines`) marks
    fragment lines that came from a source-code string literal.

    ``fences_are_examples`` disables the fenced-code-block pass. A fence is
    monospace *formatting*, not a quotation: an agent-instruction file
    (``AGENTS.md``, ``.cursorrules``, …) is itself the live instruction
    channel, so content the author fenced there is still addressed to the
    agent — wrapping a payload in ```` ``` ```` must not cap its severity
    (see :func:`match_patterns`).

    ``markdown_regions`` disables **all** markdown-derived passes (fences,
    tables, cue lists, inline-code spans), leaving only the
    ``source_example_flags`` marks. It is used for extracted source-code
    content, where the extractor has already classified every line: string
    literals carry their ``[DOC]``/``[STR]`` tag (their example-region mark),
    while comment lines must never be capped — a payload between backticks in
    a comment is prose styling, not a quotation (ADR-007: "comments are not
    example regions"), and a block-comment body could otherwise forge fences
    or tables around its own text.
    """
    total = len(lines)
    block_flags = [False] * total
    inline_spans: list[list[tuple[int, int]]] = [[] for _ in lines]

    # Source-code string literals (strings / docstrings) are example regions
    # by construction — they are data, not instructions (FP-11).
    if source_example_flags:
        for index in range(min(total, len(source_example_flags))):
            if source_example_flags[index]:
                block_flags[index] = True

    if not markdown_regions:
        return block_flags, inline_spans

    # 1. Fenced code blocks (``` / ~~~) — unless suppressed for files where a
    #    fence is not a quotation marker (agent-instruction files). A single
    #    O(n) pass: each fence is marked tentatively and committed only when it
    #    actually closes. An *unclosed* fence commits nothing — absorbing the
    #    rest of the file would let an attacker cap every remaining finding at
    #    MEDIUM simply by deleting the closing fence line (and per CommonMark
    #    an unclosed fence's content is literal, with no inner fences of its
    #    own).
    if fences_are_examples:
        tentative_start: int | None = None
        tentative_char = ""
        tentative_run = 0
        for index, line in enumerate(lines):
            match = _FENCE_RE.match(line)
            if tentative_start is None:
                if match is not None and _is_valid_fence_open(match):
                    tentative_start = index
                    tentative_char = match.group(1)[0]
                    tentative_run = len(match.group(1))
                continue
            if match is not None and _is_valid_fence_closer(
                match, tentative_char, tentative_run
            ):
                for fence_line in range(tentative_start, index + 1):
                    block_flags[fence_line] = True
                tentative_start = None
        # An opener still pending at EOF never closed: its lines stay unmarked.

    # 2. Markdown tables: a delimiter row plus the header above and the
    #    contiguous body rows below (any line containing a pipe).
    index = 0
    while index < total:
        if _is_table_delimiter(lines[index]):
            header = index - 1
            if header >= 0 and "|" in lines[header]:
                block_flags[header] = True
            body = index
            while body < total and "|" in lines[body]:
                block_flags[body] = True
                body += 1
            index = body
        else:
            index += 1

    # 3. Example-cue lists ("examples:", "например:", "payload:", "such as", …).
    #    A label cue (or a cue on a list-item line) marks the whole cue line;
    #    a bare *phrase* cue marks only the list items that follow, so a live
    #    instruction sharing the phrase-cue line keeps its full severity.
    index = 0
    while index < total:
        if _EXAMPLE_CUE_RE.search(lines[index]):
            if _EXAMPLE_CUE_LABEL_RE.search(lines[index]) or _LIST_ITEM_RE.match(
                lines[index]
            ):
                block_flags[index] = True
            index = _mark_cued_list(lines, block_flags, index)
        else:
            index += 1

    # 4. Inline-code spans (per line, column-precise).
    inline_spans = [_inline_code_spans(line) for line in lines]

    return block_flags, inline_spans


def _column_in_spans(spans: list[tuple[int, int]], column: int) -> bool:
    """Return ``True`` when ``column`` falls inside any ``(start, end)`` span."""
    return any(start <= column < end for start, end in spans)


def _spans_overlap(a: tuple[int, int, int], b: tuple[int, int, int]) -> bool:
    """Return ``True`` when two ``(line, start, end)`` spans intersect."""
    if a[0] != b[0]:
        return False
    return not (a[2] <= b[1] or a[1] >= b[2])


def match_patterns(
    file: DiscoveredFile,
    raw_bytes: bytes,
    target_text: str | None = None,
) -> list[PatternFinding]:
    """Match injection patterns against normalized file content.

    Each compiled pattern is executed line-by-line with a per-call timeout
    (via the ``regex`` library) to provide ReDoS protection. Findings carry
    1-indexed line and column numbers relative to the normalized text.

    When ``target_text`` is provided (e.g., pre-extracted comments and
    strings from source code), it is normalized via :func:`normalize_str`
    instead of decoding ``raw_bytes``.  If ``target_text`` contains
    ``[L{line}]`` prefixes (produced by
    :func:`~ipi_check.scanner.code_extractor.extract_comments_and_strings`),
    the original source line numbers are recovered and used in findings
    instead of the fragment indices.

    Severity downgrade rules:

    * if the file is a Markdown file (``.md``) that is *not* categorised
      as an agent instruction document, the severity for every finding is
      capped at :data:`Severity.MEDIUM`;
    * additionally, any finding that begins inside an **example region** —
      a markdown table, an inline-code span, a source code string literal
      (``[STR]``) or docstring (``[DOC]``), or a list introduced by an
      "examples: / например: / payload:" cue — is capped at
      :data:`EXAMPLE_REGION_SEVERITY_CEILING`. This keeps quoted attack
      examples from blocking a scan without weakening detection of real
      injections outside those regions (notably source-code comments).
      Two scope restrictions close evasion paths:
      **fenced code blocks are exempt in agent-instruction files**
      (:class:`~ipi_check.core.types.FileCategory.AGENT_INSTRUCTION`): such a
      file *is* the live instruction channel, and a fence there is monospace
      formatting, not a quotation — a CRITICAL payload wrapped in a fence in
      ``AGENTS.md`` / ``.cursorrules`` must keep its severity so the
      deterministic BLOCK (invariant I002) cannot be bypassed by
      fence-wrapping; and **markdown framing never applies to extracted
      source-code content** — there, the extractor's ``[DOC]``/``[STR]``
      tags are the only example-region marks, so a comment line can never
      cap itself by embedding backticks, a fake fence or a fake table
      (comments are not example regions, ADR-007);
    * finally, ``DEST_002`` (``rm -rf``) inside a build manifest
      (:data:`BUILD_CONFIG_FILENAMES`, e.g. ``package.json``) is capped at
      :data:`DEST_002_BUILD_CONTEXT_SEVERITY` when its target is benign
      (relative build output) — a dangerous target (filesystem root, ``~``,
      a system directory, ``..``) stays ``CRITICAL`` (FP-5).
    """
    if file.category == FileCategory.SKILL:
        return []

    line_numbers: list[int] | None = None
    source_example_flags: list[bool] | None = None

    if target_text is not None:
        line_numbers, source_example_flags, clean_text = _parse_extracted_lines(
            target_text
        )
        normalized = normalize_str(clean_text)
    else:
        normalized = normalize_text(raw_bytes)
    if not normalized:
        return []

    is_non_agent_markdown = (
        file.category != FileCategory.AGENT_INSTRUCTION
        and file.path.suffix.lower() == ".md"
    )
    is_build_config = _is_build_config_file(file)

    findings: list[PatternFinding] = []
    lines = normalized.split("\n")
    example_block, example_inline = _detect_example_regions(
        lines,
        source_example_flags,
        # An agent-instruction file is itself the instruction channel: a
        # fenced block there is content the agent reads and follows, not a
        # quoted example, so fences must not cap severity in that category.
        fences_are_examples=file.category != FileCategory.AGENT_INSTRUCTION,
        # Markdown framing (fences, tables, inline-code spans, cue lists)
        # applies only to text the agent reads as prose. Extracted
        # source-code content is already comment/string-classified by the
        # extractor: string lines carry their [DOC]/[STR] example-region tag,
        # and comment lines must never be capped — backticks or a forged
        # fence/table inside a comment are attacker-authored framing, not a
        # quotation (ADR-007: comments are not example regions).
        markdown_regions=target_text is None,
    )

    for line_index, line in enumerate(lines, start=1):
        if not line:
            continue
        actual_line = line_numbers[line_index - 1] if line_numbers else line_index
        line_block_region = example_block[line_index - 1]
        line_inline_spans = example_inline[line_index - 1]
        for pattern_id, compiled, category, base_severity in _COMPILED_PATTERNS:
            try:
                matches = list(compiled.finditer(line, timeout=REGEX_TIMEOUT_SECONDS))
            except TimeoutError:
                # Regex timed out — skip this pattern on this line (ReDoS protection).
                continue
            for match in matches:
                in_example_region = line_block_region or _column_in_spans(
                    line_inline_spans, match.start()
                )
                framed = False
                if is_non_agent_markdown or in_example_region:
                    severity = _downgrade_severity(
                        base_severity, EXAMPLE_REGION_SEVERITY_CEILING
                    )
                    # In an agent-instruction file the framing (a cue list, a
                    # table row, an inline-code span) is attacker-writable in
                    # exactly the same way the prose is, so the cap cannot be
                    # trusted to mean "quotation": mark the finding so
                    # confidence fusion floors the file's verdict at
                    # REVIEW_REQUIRED — a framed payload in the instruction
                    # channel must never fuse to a silent PASS, while benign
                    # quoted examples stay below BLOCK (FP-5 corpus).
                    framed = in_example_region and (
                        file.category == FileCategory.AGENT_INSTRUCTION
                    )
                else:
                    severity = base_severity
                # DEST_002 ("rm -rf …") in a build manifest cleans *relative*
                # build output — cap at MEDIUM unless the target is dangerous
                # (filesystem root, home, a system directory) — FP-5 / T1.2.
                if (
                    pattern_id == "DEST_002"
                    and is_build_config
                    and not _destructive_target_is_dangerous(line, match.end())
                ):
                    severity = _downgrade_severity(
                        severity, DEST_002_BUILD_CONTEXT_SEVERITY
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
                        framed=framed,
                    )
                )

    return findings


def _external_transmission_severity(line: str, base: Severity) -> Severity:
    """Refine an IPI403 severity from *every* destination host on the line.

    Classification is per-URL, so a trusted URL cannot mask an attacker URL
    on the same line:

    * any host matching :data:`_EXFIL_DOMAIN_RE` → ``CRITICAL``;
    * *every* host allowlisted → :data:`EXTERNAL_TRANSMISSION_TRUSTED` (LOW);
    * otherwise → the baseline (``MEDIUM``).
    """
    hosts = _url_hosts(line)
    if not hosts:
        return base
    if any(_EXFIL_DOMAIN_RE.search(host) for host in hosts):
        return Severity.CRITICAL
    if all(host in TRUSTED_DOMAINS for host in hosts):
        return EXTERNAL_TRANSMISSION_TRUSTED
    return base


def _corroborate_external_transmission(
    findings: list[PatternFinding],
    lines: list[str],
) -> list[PatternFinding]:
    """Escalate IPI403 to CRITICAL when the file also reads a credential.

    A lone ``curl`` to an unclassified host is only suspicious (``MEDIUM``);
    once the same file is seen to *read* a secret (IPI402), the transmission is
    corroborated exfiltration → ``CRITICAL``. A transmission whose *every*
    destination host is allowlisted is exempt, so a legitimate skill that
    reads a token and calls a known API stays ``LOW`` — but a trusted URL on
    the same line cannot mask an unclassified or attacker destination.
    """
    if not any(f.pattern_id == "IPI402" for f in findings):
        return findings
    for finding in findings:
        if finding.pattern_id != "IPI403" or finding.severity == Severity.CRITICAL:
            continue
        hosts: list[str] = []
        if 1 <= finding.line <= len(lines):
            hosts = _url_hosts(lines[finding.line - 1])
        if hosts and all(host in TRUSTED_DOMAINS for host in hosts):
            continue
        finding.severity = Severity.CRITICAL
    return findings


def match_skill_patterns(
    file: DiscoveredFile,
    raw_bytes: bytes,
    target_text: str | None = None,
) -> list[PatternFinding]:
    """Match skill-specific patterns against normalized file content.

    Each compiled pattern is executed line-by-line with a per-call timeout
    (via the ``regex`` library) to provide ReDoS protection.  Findings
    carry 1-indexed line and column numbers relative to the normalised
    text.

    When ``target_text`` is provided (e.g., pre-extracted comments and
    strings from source code), it is normalised via :func:`normalize_str`
    instead of decoding ``raw_bytes``.

    Severity is refined from context rather than taken literally from the
    pattern table:

    * ``IPI403`` (external transmission) — ``LOW`` for a ``TRUSTED_DOMAINS``
      host, ``CRITICAL`` for an ``_EXFIL_DOMAIN_RE`` host, otherwise the
      ``EXTERNAL_TRANSMISSION_BASELINE``; escalated to ``CRITICAL`` when the
      file also reads a credential (see :func:`_corroborate_external_transmission`);
    * ``IPI410`` (privilege escalation) — a bare ``sudo`` is ``HIGH``, an
      inherently destructive escalation is ``CRITICAL``, and a match preceded by
      a prohibition ("do not use sudo") is dropped (FP-10).
    """
    if target_text is not None:
        normalized = normalize_str(target_text)
    else:
        normalized = normalize_text(raw_bytes)
    if not normalized:
        return []

    findings: list[PatternFinding] = []
    # Live match spans and corroborated flags, parallel to ``findings`` — used
    # to de-duplicate IPI402: a corroborated read+transmit already reports the
    # credential read, and the two corroboration directions (read→sink,
    # sink→read) describe the same event when they overlap on a line.
    match_spans: list[tuple[int, int, int]] = []
    is_corroborated: list[bool] = []
    lines = normalized.split("\n")

    for line_index, line in enumerate(lines, start=1):
        if not line:
            continue
        for pattern_id, compiled, category, base_severity in _COMPILED_SKILL_PATTERNS:
            try:
                matches = list(compiled.finditer(line, timeout=REGEX_TIMEOUT_SECONDS))
            except TimeoutError:
                # Regex timed out — skip this pattern on this line (ReDoS protection).
                continue
            for match in matches:
                if (
                    pattern_id in _NEGATION_GUARDED_PATTERN_IDS
                    and _looks_like_negated_privilege(line, match.start())
                ):
                    # Advice *against* a privileged action is not escalation (FP-10).
                    continue
                severity = base_severity
                corroborated_match = False
                if pattern_id == "IPI403":
                    severity = _external_transmission_severity(line, base_severity)
                elif pattern_id == "IPI402" and severity == Severity.CRITICAL:
                    # Corroborated read+transmit (see the pattern table): when
                    # every destination host on the line is allowlisted, the
                    # credential is being used with a known API, not
                    # exfiltrated — refine to HIGH (FP-9), same as the HIGH
                    # plain-credential-read pattern.
                    hosts = _url_hosts(line)
                    if hosts and all(host in TRUSTED_DOMAINS for host in hosts):
                        severity = Severity.HIGH
                    corroborated_match = True
                findings.append(
                    PatternFinding(
                        category=category,
                        severity=severity,
                        line=line_index,
                        column=match.start() + 1,
                        matched_text=_truncate(match.group(0)),
                        pattern_id=pattern_id,
                        description=_SKILL_CATEGORY_DESCRIPTIONS[category],
                    )
                )
                match_spans.append((line_index, match.start(), match.end()))
                is_corroborated.append(corroborated_match)

    # One corroborated event per line region: keep the first corroborated
    # match and drop overlapping corroborated duplicates plus the plain
    # credential reads they already report.
    keep = [True] * len(findings)
    accepted_spans: list[tuple[int, int, int]] = []
    for idx in range(len(findings)):
        if not is_corroborated[idx]:
            continue
        if any(_spans_overlap(match_spans[idx], other) for other in accepted_spans):
            keep[idx] = False
        else:
            accepted_spans.append(match_spans[idx])
    for idx in range(len(findings)):
        if (
            keep[idx]
            and not is_corroborated[idx]
            and findings[idx].pattern_id == "IPI402"
            and any(_spans_overlap(match_spans[idx], other) for other in accepted_spans)
        ):
            keep[idx] = False
    findings = [f for f, k in zip(findings, keep, strict=True) if k]

    return _corroborate_external_transmission(findings, lines)
