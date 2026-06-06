#!/usr/bin/env bash
# ipi-check-hook.sh — blocking git-hook wrapper around `ipi-check scan`.
#
# Intended for client-side hooks (post-checkout, post-merge, post-rewrite,
# pre-commit, ...). It runs `ipi-check scan` over the current repository,
# stores the SARIF report under .git/, parses the verdict summary, and
# exits non-zero when a BLOCK verdict is reported. The non-zero exit is
# propagated by Git as the exit status of the triggering command, which
# is what makes the hook "blocking" in practice.
#
# post-checkout invocation:  <prev_HEAD> <new_HEAD> <branch_flag>
#   branch_flag == 0  → file checkout (skip; usually noisy and irrelevant)
#   branch_flag == 1  → branch checkout (run the scan)
#
# Environment variables:
#   IPI_CHECK_HOOK_DISABLE=1     skip the scan entirely.
#   IPI_CHECK_BLOCK_ON_REVIEW=1  also fail on REVIEW_REQUIRED verdicts.
#   IPI_CHECK_BIN                override the ipi-check executable path.

set -euo pipefail

# 1. Opt-out switch — useful for one-off recoveries or non-interactive shells.
if [ "${IPI_CHECK_HOOK_DISABLE:-0}" = "1" ]; then
    exit 0
fi

# 2. When invoked from post-checkout, only act on branch checkouts. The third
#    positional argument is the branch_flag; default to "1" so the hook still
#    runs when used as post-merge / post-rewrite / pre-commit (which pass
#    different or no arguments).
if [ "${3:-1}" = "0" ]; then
    exit 0
fi

# 3. Locate the repository root. Bail out silently outside a git work tree.
if ! REPO_ROOT="$(git rev-parse --show-toplevel 2>/dev/null)"; then
    exit 0
fi

# 4. Resolve the ipi-check binary; fail open when it is not installed so the
#    global hook does not break unrelated repositories.
IPI_CHECK_BIN="${IPI_CHECK_BIN:-ipi-check}"
if ! command -v "$IPI_CHECK_BIN" >/dev/null 2>&1; then
    echo "ipi-check: '$IPI_CHECK_BIN' not found; skipping prompt-injection scan." >&2
    exit 0
fi

SARIF_FILE="$REPO_ROOT/.git/ipi-check-last.sarif"
STDERR_FILE="$(mktemp -t ipi-check-stderr.XXXXXX)"
trap 'rm -f "$STDERR_FILE"' EXIT

# 5. Run the scan. ipi-check itself exits 0 on a clean run regardless of
#    findings — verdicts live in the SARIF report and the stderr summary.
if ! "$IPI_CHECK_BIN" scan "$REPO_ROOT" --output "$SARIF_FILE" 2> "$STDERR_FILE"; then
    cat "$STDERR_FILE" >&2
    echo "ipi-check: scanner failed to run." >&2
    exit 1
fi

# 6. Re-emit the scanner banner + summary so the user sees them in their
#    terminal, then extract the BLOCK / REVIEW_REQUIRED counters.
cat "$STDERR_FILE" >&2

SUMMARY="$(grep -E '^Scanned [0-9]+ files\.' "$STDERR_FILE" | tail -n 1 || true)"
BLOCK_COUNT="$(printf '%s\n' "$SUMMARY" | sed -n 's/.*BLOCK: \([0-9][0-9]*\).*/\1/p')"
REVIEW_COUNT="$(printf '%s\n' "$SUMMARY" | sed -n 's/.*REVIEW_REQUIRED: \([0-9][0-9]*\).*/\1/p')"
BLOCK_COUNT="${BLOCK_COUNT:-0}"
REVIEW_COUNT="${REVIEW_COUNT:-0}"

# 7. Decision matrix.
if [ "$BLOCK_COUNT" -gt 0 ]; then
    echo "ipi-check: BLOCK verdict — prompt-injection findings detected." >&2
    echo "ipi-check: SARIF report: $SARIF_FILE" >&2
    exit 1
fi

if [ "${IPI_CHECK_BLOCK_ON_REVIEW:-0}" = "1" ] && [ "$REVIEW_COUNT" -gt 0 ]; then
    echo "ipi-check: REVIEW_REQUIRED and IPI_CHECK_BLOCK_ON_REVIEW=1 — failing." >&2
    echo "ipi-check: SARIF report: $SARIF_FILE" >&2
    exit 1
fi

if [ "$REVIEW_COUNT" -gt 0 ]; then
    echo "ipi-check: REVIEW_REQUIRED findings present — see $SARIF_FILE" >&2
fi

exit 0
