FROM python:3.12-slim AS builder

WORKDIR /app
COPY pyproject.toml .
COPY src/ src/

# LiteLLM is a core dependency (see pyproject.toml), so the optional LLM
# classifier is available in the published image with no extra install:
#   docker run --rm -v "$PWD:/repo" ipi-check scan /repo \
#     --llm-model gpt-4o-mini --llm-api-token "$OPENAI_API_KEY"
# A self-hosted / proxy endpoint is selected with --llm-base-url.
RUN pip install --no-cache-dir .

FROM python:3.12-slim

LABEL org.opencontainers.image.title="ipi-check" \
      org.opencontainers.image.description="SAST scanner for indirect prompt injection (OWASP LLM01) and agent skill security auditing" \
      org.opencontainers.image.source="https://github.com/v0lka/ipi-check" \
      org.opencontainers.image.licenses="MIT"

# Unbuffered stdout/stderr so the progress summary and the report stream
# promptly when the image is driven from CI or piped to another process.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages
COPY --from=builder /usr/local/bin/ipi-check /usr/local/bin/ipi-check

# Conventional mount point for the repository under scan:
#   docker run --rm -v "$PWD:/repo" ipi-check scan /repo
WORKDIR /repo

ENTRYPOINT ["ipi-check"]
