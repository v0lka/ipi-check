#!/usr/bin/env bash
# ipi-check-hook.sh — blocking git-hook wrapper around `ipi-check scan`.
#
# Intended for client-side hooks (post-checkout, post-merge, post-rewrite,
# pre-commit, ...). It runs `ipi-check scan` over the current repository with an
# explicit `--fail-on` policy and maps the scanner's *exit code* to the hook
# status. It never parses the human-readable stderr summary (no grep/sed over
# the banner or counters), so it keeps working no matter how that text is
# worded, formatted or localized. The non-zero exit is propagated by Git as the
# exit status of the triggering command, which is what makes the hook
# "blocking" in practice.
#
# post-checkout invocation:  <prev_HEAD> <new_HEAD> <branch_flag>
#   branch_flag == 0  → file checkout (skip; usually noisy and irrelevant)
#   branch_flag == 1  → branch checkout (run the scan)
#
# Hook exit codes (non-zero = the hook blocks):
#   0  scan completed with no policy-level findings
#   1  scanner could not run, or the --fail-on policy was tripped
#
# Scanner exit codes this hook consumes (see specs/contracts/cli-interface.md):
#   0  scan completed clean            → hook: 0
#   3  BLOCK verdict present           → hook: 1  (blocking)
#   4  REVIEW_REQUIRED verdict only    → hook: 1  (only under --fail-on review)
#   1  runtime error / 2 usage error   → hook: 1
#
# Environment variables:
#   IPI_CHECK_HOOK_DISABLE=1     skip the scan entirely.
#   IPI_CHECK_BLOCK_ON_REVIEW=1  also fail on REVIEW_REQUIRED verdicts.
#   IPI_CHECK_FAIL_ON            explicit --fail-on value (none|block|review);
#                                overrides the two shortcuts above.
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

# 5. Resolve the --fail-on policy. Default is "block": the hook blocks on BLOCK
#    verdicts exactly as before. IPI_CHECK_BLOCK_ON_REVIEW=1 widens it to
#    REVIEW_REQUIRED; IPI_CHECK_FAIL_ON overrides both.
FAIL_ON="block"
if [ "${IPI_CHECK_BLOCK_ON_REVIEW:-0}" = "1" ]; then
    FAIL_ON="review"
fi
FAIL_ON="${IPI_CHECK_FAIL_ON:-$FAIL_ON}"

SARIF_FILE="$REPO_ROOT/.git/ipi-check-last.sarif"
STDERR_FILE="$(mktemp -t ipi-check-stderr.XXXXXX)"
trap 'rm -f "$STDERR_FILE"' EXIT

# 6. Run the scan, letting the scanner itself decide the policy via --fail-on.
#    Its exit code — not its stderr text — drives the hook. The if/else form
#    keeps `set -e` from aborting and preserves the exact scanner status.
if "$IPI_CHECK_BIN" scan "$REPO_ROOT" --output "$SARIF_FILE" \
        --fail-on "$FAIL_ON" 2> "$STDERR_FILE"; then
    SCAN_STATUS=0
else
    SCAN_STATUS=$?
fi

# 7. Re-emit the scanner banner + summary so the user sees them in their
#    terminal (cosmetic only — nothing here is parsed).
cat "$STDERR_FILE" >&2

# 8. Map the scanner exit code to the hook result (no text matching).
case "$SCAN_STATUS" in
    0)
        exit 0
        ;;
    3)
        echo "ipi-check: --fail-on=$FAIL_ON tripped — BLOCK verdict detected." >&2
        echo "ipi-check: SARIF report: $SARIF_FILE" >&2
        exit 1
        ;;
    4)
        echo "ipi-check: --fail-on=$FAIL_ON tripped — REVIEW_REQUIRED verdict detected." >&2
        echo "ipi-check: SARIF report: $SARIF_FILE" >&2
        exit 1
        ;;
    *)
        echo "ipi-check: scanner failed to run (exit $SCAN_STATUS)." >&2
        exit 1
        ;;
esac
