"""ipi-check: SAST scanner for indirect prompt injection (OWASP LLM01)."""
from __future__ import annotations

from ipi_check.core.types import ToolInfo

__version__ = "0.1.0"

TOOL_INFO = ToolInfo(
    name="ipi-check",
    version=__version__,
    semver=__version__,
)

__all__ = ["TOOL_INFO", "__version__"]
