#!/usr/bin/env bash
# Low-noise verification: fmt -> check (all targets) -> unit tests.
# Prints only what needs attention; known dependency noise is filtered (see AGENTS.md).
#
#   scripts/check.sh          # fmt + check + test
#   scripts/check.sh quick    # fmt + check only
set -u
cd "$(dirname "$0")/.."

status=0

if ! out=$(cargo fmt -- --check --color never 2>&1); then
    echo "== fmt: differences (run: cargo fmt)"
    echo "$out" | head -40
    status=1
else
    echo "== fmt ok"
fi

# nom 4 macros emit "trailing semicolon" warnings and a future-incompat note; not actionable here.
noise='trailing semicolon in macro|future version of Rust|future-incompat|generated [0-9]+ warnings?'
out=$(cargo check --all-targets -q --message-format short 2>&1)
check_rc=$?
filtered=$(echo "$out" | grep -Ev "$noise")
if [ "$check_rc" -ne 0 ]; then
    echo "== check: FAILED"
    echo "$filtered"
    exit 1
fi
echo "== check ok ($(echo "$out" | grep -c 'trailing semicolon') known nom warnings hidden)"
[ -n "$filtered" ] && { echo "$filtered"; echo "(above: warnings, fix those you introduced)"; }

[ "${1:-}" = quick ] && exit "$status"

out=$(cargo test -q 2>&1)
if [ $? -ne 0 ]; then
    echo "== test: FAILED"
    echo "$out" | grep -Ev "$noise|^warning|^ *[|=0-9]|^$" | head -60
    exit 1
fi
echo "== test ok: $(echo "$out" | grep -E '^test result' | head -1)"
exit "$status"
