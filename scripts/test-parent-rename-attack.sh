#!/usr/bin/env bash

set -euo pipefail

BINARY="${FILE_GUARD_BIN:-target/release/file-guard}"
TEST_ROOT="$(mktemp -d /tmp/fg-parent-rename-test.XXXXXX)"
CREDDIR="$TEST_ROOT/creds"
CREDFILE="$CREDDIR/secret"
DISPLACED_DIR="$TEST_ROOT/creds-displaced"
DISPLACED_FILE="$DISPLACED_DIR/secret"
ATTACKER_DIR="$TEST_ROOT/creds-attacker"
CONFIG="$TEST_ROOT/config.toml"
STORE="$TEST_ROOT/store"
STAGING="$TEST_ROOT/staging"
RULES_DB="$TEST_ROOT/rules.sqlite"
PIDFILE="$TEST_ROOT/daemon.pid"
AGENT_SOCKET="$TEST_ROOT/agent.sock"
CONTROL_SOCKET="$TEST_ROOT/control.sock"
AUDIT_LOG="$TEST_ROOT/audit.log"
DAEMON_LOG="$TEST_ROOT/daemon.log"
RESTORE_LOG="$TEST_ROOT/restore.log"
DAEMON_PID=""

unmount_if_present() {
    local path="$1"
    if mountpoint -q "$path" 2>/dev/null; then
        fusermount3 -u -z "$path" 2>/dev/null || umount -l "$path" 2>/dev/null || true
    fi
}

cleanup() {
    set +e
    if [[ -n "$DAEMON_PID" ]] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill -TERM "$DAEMON_PID" 2>/dev/null
        wait "$DAEMON_PID" 2>/dev/null
    fi
    unmount_if_present "$CREDFILE"
    unmount_if_present "$DISPLACED_FILE"
    case "$TEST_ROOT" in
        /tmp/fg-parent-rename-test.*) rm -rf -- "$TEST_ROOT" ;;
    esac
}
trap cleanup EXIT

fail() {
    printf 'FAIL: %s\n' "$1" >&2
    exit 1
}

[[ "$(id -u)" -eq 0 ]] || fail "run this test as root"
[[ -x "$BINARY" ]] || fail "file-guard binary is not executable at $BINARY"

printf '=== Parent-directory rename adversarial test ===\n'
printf 'Test root: %s\n' "$TEST_ROOT"

mkdir -p "$CREDDIR" "$STORE" "$STAGING"
printf '%s\n' "original-credential-content" > "$CREDFILE"
chmod 600 "$CREDFILE"

{
    printf '%s\n' '[settings]'
    printf '%s\n' 'default_action = "allow"'
    printf '%s\n' 'prompt_timeout = 5'
    printf '%s\n' 'restore_on_stop = true'
    printf 'log_destination = "%s"\n' "$AUDIT_LOG"
    printf '%s\n' '[[watch]]'
    printf 'path = "%s"\n' "$CREDFILE"
} > "$CONFIG"

printf '%s\n' '--- starting daemon ---'
FILE_GUARD_CONFIG="$CONFIG" \
FILE_GUARD_STORE_DIR="$STORE" \
FILE_GUARD_STAGING_DIR="$STAGING" \
FILE_GUARD_RULES_DB="$RULES_DB" \
FILE_GUARD_PID_FILE="$PIDFILE" \
FILE_GUARD_AGENT_SOCKET="$AGENT_SOCKET" \
FILE_GUARD_CONTROL_SOCKET="$CONTROL_SOCKET" \
"$BINARY" start > "$DAEMON_LOG" 2>&1 &
DAEMON_PID=$!

for _ in {1..100}; do
    kill -0 "$DAEMON_PID" 2>/dev/null || break
    mountpoint -q "$CREDFILE" 2>/dev/null && break
    sleep 0.1
done
kill -0 "$DAEMON_PID" 2>/dev/null || fail "daemon failed to start; see $DAEMON_LOG"
mountpoint -q "$CREDFILE" 2>/dev/null || fail "FUSE mount did not become active"

[[ "$(<"$CREDFILE")" == "original-credential-content" ]] \
    || fail "baseline mount read returned unexpected content"

printf '%s\n' '--- replacing the watched parent pathname ---'
mv "$CREDDIR" "$DISPLACED_DIR"
mkdir "$CREDDIR"
printf '%s\n' "attacker-content" > "$CREDFILE"
chmod 600 "$CREDFILE"

mountpoint -q "$DISPLACED_FILE" 2>/dev/null \
    || fail "the live mount did not move with its renamed parent"
mountpoint -q "$CREDFILE" 2>/dev/null \
    && fail "the replacement path unexpectedly became the FUSE mount"
[[ "$(<"$DISPLACED_FILE")" == "original-credential-content" ]] \
    || fail "the displaced mount stopped serving the guarded content"
[[ "$(<"$CREDFILE")" == "attacker-content" ]] \
    || fail "the replacement file was not isolated from the mount"

printf '%s\n' "updated-credential-content" > "$DISPLACED_FILE"
[[ "$(<"$DISPLACED_FILE")" == "updated-credential-content" ]] \
    || fail "a write through the displaced mount did not commit"
[[ "$(<"$CREDFILE")" == "attacker-content" ]] \
    || fail "a mounted write reached the attacker's replacement file"

printf '%s\n' '--- stopping daemon under the mismatched parent binding ---'
set +e
kill -TERM "$DAEMON_PID"
wait "$DAEMON_PID"
STOP_STATUS=$?
set -e
DAEMON_PID=""

[[ "$STOP_STATUS" -ne 0 ]] \
    || fail "daemon reported a clean restore despite the replaced parent"
[[ "$(<"$CREDFILE")" == "attacker-content" ]] \
    || fail "shutdown overwrote the attacker's replacement file"
grep -Eiq 'parent.*(changed|renamed|replaced)|binding' "$DAEMON_LOG" \
    || fail "daemon did not report the parent-binding violation"

for _ in {1..50}; do
    mountpoint -q "$DISPLACED_FILE" 2>/dev/null || break
    sleep 0.1
done
mountpoint -q "$DISPLACED_FILE" 2>/dev/null \
    && fail "the displaced FUSE mount remained after daemon exit"

printf '%s\n' '--- restoring the original parent identity for recovery inspection ---'
mv "$CREDDIR" "$ATTACKER_DIR"
mv "$DISPLACED_DIR" "$CREDDIR"
[[ "$(<"$ATTACKER_DIR/secret")" == "attacker-content" ]] \
    || fail "the attacker file changed during recovery setup"

set +e
FILE_GUARD_CONFIG="$CONFIG" \
FILE_GUARD_STORE_DIR="$STORE" \
FILE_GUARD_STAGING_DIR="$STAGING" \
FILE_GUARD_RULES_DB="$RULES_DB" \
FILE_GUARD_CONTROL_SOCKET="$CONTROL_SOCKET" \
"$BINARY" restore "$CREDFILE" > "$RESTORE_LOG" 2>&1
RESTORE_STATUS=$?
set -e

[[ "$RESTORE_STATUS" -ne 0 ]] \
    || fail "a blocked transaction was restored without operator recovery"
grep -Eiq 'requires manual recovery' "$RESTORE_LOG" \
    || fail "the persisted block was not surfaced by offline restore"

printf '%s\n' '=== TEST PASSED ==='
printf '%s\n' 'The moved mount retained its identity, the replacement stayed untouched,'
printf '%s\n' 'and the parent mismatch produced a durable manual-recovery block.'
