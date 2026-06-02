#!/bin/sh
#
# Run one fuzz target. Seeds a mutable working corpus (var/fuzz/<target>, which
# is git-ignored) from the committed read-only seeds (tests/Fuzz/seeds/<target>)
# and points php-fuzzer at it, so the committed seeds are never polluted with
# generated entries.
#
# Usage:
#   tests/Fuzz/run.sh <target> [max-runs]
#
# Targets: jwt_parser | json_decode | base64url_decode | jws_compact | jwe_compact
# Omit max-runs for an unbounded run (Ctrl-C to stop); pass e.g. 200000 for CI.
#
# In Docker:  make fuzz TARGET=jwt_parser RUNS=200000
#
# POSIX sh (the dev container is Alpine — no bash).
set -eu

target="${1:?usage: tests/Fuzz/run.sh <target> [max-runs]}"
max_runs="${2:-}"

root=$(cd "$(dirname "$0")/../.." && pwd)
target_file="$root/tests/Fuzz/targets/$target.php"
seeds="$root/tests/Fuzz/seeds/$target"
work="$root/var/fuzz/$target"

[ -f "$target_file" ] || { echo "Unknown target '$target' ($target_file not found)" >&2; exit 2; }

mkdir -p "$work"
if [ -d "$seeds" ]; then
    cp "$seeds"/* "$work"/ 2>/dev/null || true
fi

if [ -n "$max_runs" ]; then
    exec "$root/vendor/bin/php-fuzzer" fuzz --max-runs="$max_runs" "$target_file" "$work"
fi
exec "$root/vendor/bin/php-fuzzer" fuzz "$target_file" "$work"
