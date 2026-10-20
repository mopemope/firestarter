#!/usr/bin/env bash
# End-to-end smoke test: daemon start -> ctrl commands -> stop.
# Isolated via FIRESTARTER_APP_NAME + TMPDIR, so it is safe next to a real daemon.
# Output is one line per step; the full daemon log is shown only on failure.
#
# NOTE: runs the *release* binary on purpose. With debug assertions on, nix 0.17
# (offset_of! null deref) aborts on rustc >= 1.7x, so a debug daemon cannot start.
#
#   scripts/smoke.sh            # builds (release) and runs
#   RUST_LOG=debug scripts/smoke.sh
set -u

cd "$(dirname "$0")/.."
build=$(cargo build --release -q --message-format short 2>&1) || { echo "$build"; exit 1; }

BIN=$PWD/target/release/firestarter
WORK=$(mktemp -d)
export TMPDIR=$WORK
export FIRESTARTER_APP_NAME=smoke$$
SLEEP_BIN=$(command -v sleep)
SLEEP_ARG=$((300000 + $$ % 1000)) # unique argv so leftover detection cannot match other processes
RUST_LOG=${RUST_LOG:-info}
export RUST_LOG

cat >"$WORK/config.toml" <<EOF
[w1]
exec_start = "$SLEEP_BIN $SLEEP_ARG" # must be an absolute path (no PATH lookup)
numprocesses = 2
start_immediate = true
restart = "none"
ack = "timer"
ack_timeout = 1
EOF

DAEMON_PID=
fail=0

cleanup() {
    [ -n "$DAEMON_PID" ] && kill "$DAEMON_PID" 2>/dev/null
    pkill -f "sleep $SLEEP_ARG" 2>/dev/null
    if [ "$fail" -ne 0 ]; then
        echo "--- daemon log ($WORK/daemon.log) ---"
        tail -n 40 "$WORK/daemon.log"
    else
        rm -rf "$WORK"
    fi
}
trap cleanup EXIT

step() { # step <name> <expected-substring> <cmd...>
    local name=$1 expect=$2
    shift 2
    local out
    out=$("$@" 2>&1)
    if [[ $out == *"$expect"* ]]; then
        echo "ok   $name"
    else
        echo "FAIL $name (expected '$expect')"
        echo "$out" | sed 's/^/     /'
        fail=1
    fi
}

procs() { pgrep -fc "sleep $SLEEP_ARG"; }

"$BIN" run --config "$WORK/config.toml" >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

sock="$WORK/${FIRESTARTER_APP_NAME}-control.socket"
for _ in $(seq 50); do
    [ -S "$sock" ] && break
    sleep 0.1
done
[ -S "$sock" ] || { echo "FAIL daemon did not create $sock"; fail=1; exit 1; }
sleep 0.5 # let the monitor spawn workers

step list "w1" "$BIN" list
step status "[w1] active" "$BIN" ctrl w1 status
[ "$(procs)" = 2 ] && echo "ok   2 workers running" || { echo "FAIL expected 2 workers, got $(procs)"; fail=1; }

step inc "increments worker" "$BIN" ctrl w1 inc
[ "$(procs)" = 3 ] && echo "ok   3 workers after inc" || { echo "FAIL expected 3 workers, got $(procs)"; fail=1; }

step dec "decrements worker" "$BIN" ctrl w1 dec
step restart "restart processes" "$BIN" ctrl w1 restart
step upgrade "upgrade processes" "$BIN" ctrl w1 upgrade
step stop "stop" "$BIN" stop

for _ in $(seq 50); do
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    sleep 0.2
done
if kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "FAIL daemon still alive after stop"
    fail=1
else
    echo "ok   daemon exited"
    DAEMON_PID=
fi
sleep 0.3
[ "$(procs)" = 0 ] && echo "ok   no leftover workers" || { echo "FAIL leftover workers: $(procs)"; fail=1; }

[ "$fail" -eq 0 ] && echo "SMOKE PASSED" || echo "SMOKE FAILED"
exit "$fail"
