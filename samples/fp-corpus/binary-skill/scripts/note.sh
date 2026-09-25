#!/bin/bash
set -euo pipefail

printf '%s %s\n' "$(date -u +%FT%TZ)" "${1:-note}" >> notes.log
