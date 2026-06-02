#!/bin/sh
#
# File a GitHub issue for each fuzzer crash found in the current directory.
# Called by the nightly fuzz workflow when a target produced crash-*.txt files.
#
# Usage: tests/Fuzz/report-crash.sh <target> <run-log>
#
# Every crash here is by construction a contract violation — the target threw
# something outside the JwtException family — so it is filed P0
# (docs/07-testing-strategy.md). Issues are de-duplicated by crash hash so a
# recurring crash across nightly runs does not spam new issues ("no NOVEL
# crashes" is the Phase 5 exit gate).
#
# Requires: gh (authenticated via GH_TOKEN), base64, in a git repo with a remote.
set -eu

target="${1:?usage: report-crash.sh <target> <run-log>}"
log="${2:?usage: report-crash.sh <target> <run-log>}"

# Ensure the labels exist (no-op if already present).
gh label create fuzz-crash --description "Crash found by the nightly fuzzer" --color B60205 2>/dev/null || true
gh label create P0 --description "Highest priority" --color B60205 2>/dev/null || true

found_any=0
for f in crash-*.txt; do
    [ -f "$f" ] || continue
    found_any=1

    hash=$(basename "$f" .txt | sed 's/^crash-//')
    title="fuzz: $target — uncaught non-JwtException (crash $hash)"
    input_b64=$(base64 "$f" | tr -d '\n')

    # De-dup: skip if an open issue already references this crash hash.
    existing=$(gh issue list --state open --search "$hash in:title" --json number --jq 'length' 2>/dev/null || echo 0)
    if [ "$existing" != "0" ]; then
        echo "Crash $hash already has an open issue — skipping."
        continue
    fi

    body=$(cat <<EOF
A nightly fuzz run found an input that **escapes the \`JwtException\` contract** in the \`$target\` target: \`$target\` threw something other than a \`JwtException\` (an \`Error\`/\`TypeError\`/\`ValueError\`/\`JsonException\` or a raw SPL exception).

**Priority: P0** — every fuzz crash is a contract violation by construction (see \`docs/07-testing-strategy.md\`).

### Reproduce locally
\`\`\`sh
printf '%s' '$input_b64' | base64 -d > crash.txt
vendor/bin/php-fuzzer run-single tests/Fuzz/targets/$target.php crash.txt
# or minimise first:
vendor/bin/php-fuzzer minimize-crash tests/Fuzz/targets/$target.php crash.txt
\`\`\`

### Crashing input (base64)
\`\`\`
$input_b64
\`\`\`

### Run log (tail — exception class & stack)
\`\`\`
$(tail -n 40 "$log")
\`\`\`

_Filed automatically by the nightly fuzz workflow._
EOF
)

    url=$(gh issue create --title "$title" --label fuzz-crash --label P0 --body "$body")
    echo "Filed: $url"
done

if [ "$found_any" = "0" ]; then
    echo "No crash-*.txt files found; nothing to report."
fi
