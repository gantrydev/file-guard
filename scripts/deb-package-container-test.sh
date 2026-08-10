#!/usr/bin/env bash
set -Eeuo pipefail

deb=${FILE_GUARD_DEB:-/tmp/file-guard.deb}
expected_version=${FILE_GUARD_EXPECTED_VERSION:-0.1.17}
require_fuse=${FILE_GUARD_REQUIRE_FUSE:-1}

fail() {
    echo "FAIL: $*" >&2
    exit 1
}

pass() {
    echo "PASS: $*"
}

skip() {
    echo "SKIP: $*"
}

functional_failures=0

record_failure() {
    echo "FAIL: $*" >&2
    functional_failures=$((functional_failures + 1))
}

[[ -r "$deb" ]] || fail "release package is not readable at $deb"

package_name=$(dpkg-deb --field "$deb" Package)
package_version=$(dpkg-deb --field "$deb" Version)
package_arch=$(dpkg-deb --field "$deb" Architecture)
package_depends=$(dpkg-deb --field "$deb" Depends)
package_without_epoch=${package_version#*:}
package_upstream=${package_without_epoch%-*}
[[ "$package_name" == file-guard ]] || fail "metadata Package is $package_name"
[[ "$package_upstream" == "$expected_version" ]] || \
    fail "metadata upstream version is $package_upstream (expected $expected_version)"
[[ "$package_arch" == amd64 ]] || fail "metadata Architecture is $package_arch"
[[ "$package_depends" == *fuse3* ]] || \
    fail "metadata Depends omits direct fuse3 dependency: $package_depends"
pass "package metadata: $package_name $package_version $package_arch"

expected_archive_paths=(
    ./usr/bin/file-guard
    ./etc/file-guard/config.toml
    ./etc/default/file-guard
    ./lib/systemd/system/file-guard.service
    ./lib/systemd/system/file-guard-agent@.socket
    ./lib/systemd/system/file-guard-agent@.service
    ./usr/lib/tmpfiles.d/file-guard.conf
    ./usr/share/doc/file-guard/docs/storage-v2.md
)
archive_contents=$(dpkg-deb --contents "$deb")
for path in "${expected_archive_paths[@]}"; do
    grep -Fq " $path" <<<"$archive_contents" || fail "package omits $path"
done
pass "package archive contains binary, defaults, units, and tmpfiles rule"

apt-get update >/dev/null
apt-get install --yes --no-install-recommends "$deb" >/dev/null
dpkg_status=$(dpkg-query --show --showformat='${Status}' file-guard)
[[ "$dpkg_status" == "install ok installed" ]] || fail "package is not installed: $dpkg_status"
installed_version=$(dpkg-query --show --showformat='${Version}' file-guard)
[[ "$installed_version" == "$package_version" ]] || fail "installed version differs from package metadata"
pass "installed downloaded package with apt/dpkg"
dpkg-query --show --showformat='${Status}' libfuse3-3 | \
    grep -Fq 'install ok installed' || fail "libfuse3-3 was not installed transitively"
pass "fuse runtime dependency"

assert_mode() {
    local path=$1 expected=$2 actual
    [[ -e "$path" ]] || fail "missing installed file $path"
    actual=$(stat -c '%a' "$path")
    [[ "$actual" == "$expected" ]] || fail "$path mode is $actual (expected $expected)"
}

assert_mode /usr/bin/file-guard 755
for path in \
    /etc/file-guard/config.toml \
    /etc/default/file-guard \
    /lib/systemd/system/file-guard.service \
    '/lib/systemd/system/file-guard-agent@.socket' \
    '/lib/systemd/system/file-guard-agent@.service' \
    /usr/lib/tmpfiles.d/file-guard.conf; do
    assert_mode "$path" 644
done
pass "installed file modes"

grep -Eq '^default_action[[:space:]]*=[[:space:]]*"deny"' /etc/file-guard/config.toml || \
    fail "config default_action is not deny"
grep -Eq '^prompt_timeout[[:space:]]*=[[:space:]]*30$' /etc/file-guard/config.toml || \
    fail "config prompt_timeout is not 30"
grep -Eq '^prompt_method[[:space:]]*=[[:space:]]*"gui"' /etc/file-guard/config.toml || \
    fail "config prompt_method is not gui"
grep -Fq 'log_destination = "/var/lib/file-guard/access.log"' /etc/file-guard/config.toml || \
    fail "config log_destination is not the packaged state path"
pass "packaged configuration defaults"

systemd-analyze verify \
    /lib/systemd/system/file-guard.service \
    '/lib/systemd/system/file-guard-agent@.socket' \
    '/lib/systemd/system/file-guard-agent@.service'
pass "systemd unit syntax"

systemd-tmpfiles --create /usr/lib/tmpfiles.d/file-guard.conf
assert_mode /run/file-guard 755
[[ "$(stat -c '%U:%G' /run/file-guard)" == root:root ]] || fail "/run/file-guard ownership"
pass "tmpfiles rule creates root-owned rendezvous directory"

export FILE_GUARD_CONFIG=/etc/file-guard/config.toml
packaged_config_valid=1
if rules_output=$(/usr/bin/file-guard rules 2>&1); then
    [[ -z "$rules_output" ]] || {
        record_failure "packaged config unexpectedly contains persistent rules"
        packaged_config_valid=0
    }
else
    record_failure "packaged config is rejected by the CLI: $rules_output"
    packaged_config_valid=0
fi
if status_output=$(/usr/bin/file-guard status 2>&1); then
    grep -Fq 'daemon:  not running' <<<"$status_output" || {
        record_failure "status did not report no daemon"
        packaged_config_valid=0
    }
    grep -Fq '(none configured)' <<<"$status_output" || {
        record_failure "status did not report no watches"
        packaged_config_valid=0
    }
else
    record_failure "status rejected the packaged config: $status_output"
    packaged_config_valid=0
fi
if ! /usr/bin/file-guard log --lines 1 >/dev/null 2>&1; then
    record_failure "log command rejected the packaged config"
    packaged_config_valid=0
fi
[[ "$packaged_config_valid" -eq 1 ]] && pass "status, rules, and log CLI commands"

cli_dir=/tmp/file-guard-cli-test
rm -rf "$cli_dir"
mkdir -p "$cli_dir"
cp /etc/file-guard/config.toml "$cli_dir/config.toml"
FILE_GUARD_CONFIG="$cli_dir/config.toml" /usr/bin/file-guard rules add \
    --file /tmp/example-credential \
    --binary /usr/bin/true \
    --action allow \
    --access read >/dev/null
FILE_GUARD_CONFIG="$cli_dir/config.toml" /usr/bin/file-guard rules | \
    grep -Fq '/usr/bin/true' || fail "rules add did not persist"
FILE_GUARD_CONFIG="$cli_dir/config.toml" /usr/bin/file-guard rules remove 0 >/dev/null
[[ -z "$(FILE_GUARD_CONFIG="$cli_dir/config.toml" /usr/bin/file-guard rules)" ]] || \
    fail "rules remove did not remove the rule"
pass "rules add/remove CLI commands"

store_dir="$cli_dir/store"
secret="$cli_dir/secret"
printf 'package-harness-secret\n' >"$secret"
chmod 0600 "$secret"
captured_mode=$(stat -c '%a' "$secret")
FILE_GUARD_STORE_DIR="$store_dir" /usr/bin/file-guard store "$secret" >/dev/null
[[ ! -e "$secret" ]] || fail "store command left the source file on disk"
FILE_GUARD_STORE_DIR="$store_dir" /usr/bin/file-guard restore "$secret" >/dev/null
[[ "$(cat "$secret")" == 'package-harness-secret' ]] || fail "restore did not recover stored contents"
restored_mode=$(stat -c '%a' "$secret")
if [[ "$restored_mode" == "$captured_mode" ]]; then
    pass "store/restore CLI commands preserve file mode"
else
    record_failure "restore created $secret with mode $restored_mode (expected $captured_mode)"
fi

daemon_pid=''
cleanup_daemon() {
    if [[ -n "$daemon_pid" ]] && kill -0 "$daemon_pid" 2>/dev/null; then
        kill -TERM "$daemon_pid" 2>/dev/null || true
        wait "$daemon_pid" 2>/dev/null || true
    fi
}
trap cleanup_daemon EXIT

daemon_log="$cli_dir/daemon.log"
export FILE_GUARD_CONFIG="$cli_dir/config.toml"
rm -f /run/file-guard/daemon.pid /run/file-guard/config
FILE_GUARD_STORE_DIR="$store_dir/daemon-store" \
    /usr/bin/file-guard start >"$daemon_log" 2>&1 &
daemon_pid=$!
for _ in $(seq 1 50); do
    [[ -e /run/file-guard/daemon.pid ]] && break
    kill -0 "$daemon_pid" 2>/dev/null || fail "daemon exited during no-watch lifecycle test"
    sleep 0.1
done
[[ -e /run/file-guard/daemon.pid ]] || fail "daemon did not publish its PID file"
kill -TERM "$daemon_pid"
wait "$daemon_pid"
daemon_pid=''
[[ ! -e /run/file-guard/daemon.pid ]] || fail "daemon did not remove its PID file on stop"
pass "no-watch daemon start/stop lifecycle"

if [[ ! -c /dev/fuse ]]; then
    if [[ "$require_fuse" == 1 ]]; then
        fail "required /dev/fuse device is unavailable"
    fi
    skip "real SQLite/FUSE lifecycle (FILE_GUARD_REQUIRE_FUSE=$require_fuse)"
else
    fuse_dir="$cli_dir/fuse"
    fuse_config="$fuse_dir/config.toml"
    fuse_store="$fuse_dir/store"
    fuse_pid_file="$fuse_dir/daemon.pid"
    fuse_log="$fuse_dir/daemon.log"
    guarded="$fuse_dir/credential"
    mkdir -p "$fuse_dir"
    printf 'initial-fuse-secret\n' >"$guarded"
    chmod 0600 "$guarded"
    guarded_mode=$(stat -c '%a' "$guarded")
    cat >"$fuse_config" <<EOF
[settings]
default_action = "allow"
prompt_timeout = 1
prompt_method = "notification"
log_destination = "$fuse_dir/access.log"
restore_on_stop = true

[[watch]]
path = "$guarded"
EOF

    start_fuse_daemon() {
        FILE_GUARD_CONFIG="$fuse_config" \
        FILE_GUARD_STORE_DIR="$fuse_store" \
        FILE_GUARD_PID_FILE="$fuse_pid_file" \
            /usr/bin/file-guard start >>"$fuse_log" 2>&1 &
        daemon_pid=$!
        for _ in $(seq 1 100); do
            mountpoint -q "$guarded" && return 0
            kill -0 "$daemon_pid" 2>/dev/null || {
                tail -100 "$fuse_log" >&2 || true
                fail "daemon exited before mounting the guarded file"
            }
            sleep 0.1
        done
        tail -100 "$fuse_log" >&2 || true
        fail "daemon did not mount the guarded file"
    }

    start_fuse_daemon
    [[ "$(cat "$guarded")" == 'initial-fuse-secret' ]] || fail "mounted FUSE file returned wrong contents"
    printf 'updated-fuse-secret\n' >"$guarded"
    [[ "$(cat "$guarded")" == 'updated-fuse-secret' ]] || fail "mounted FUSE write was not visible"
    if chmod 0644 "$guarded" 2>/dev/null; then
        fail "unsupported chmod unexpectedly succeeded through FUSE"
    fi
    [[ "$(stat -c '%a' "$guarded")" == "$guarded_mode" ]] || fail "failed chmod changed FUSE mode"

    kill -KILL "$daemon_pid"
    wait "$daemon_pid" 2>/dev/null || true
    daemon_pid=''

    start_fuse_daemon
    [[ "$(cat "$guarded")" == 'updated-fuse-secret' ]] || fail "crash recovery lost the committed FUSE write"
    kill -TERM "$daemon_pid"
    wait "$daemon_pid"
    daemon_pid=''

    mountpoint -q "$guarded" && fail "graceful stop left the FUSE mount installed"
    [[ "$(cat "$guarded")" == 'updated-fuse-secret' ]] || fail "graceful stop did not restore committed contents"
    [[ "$(stat -c '%a' "$guarded")" == "$guarded_mode" ]] || fail "graceful restore changed file mode"
    pass "real SQLite/FUSE write, crash-restart, and restore lifecycle"
fi
if [[ "$(readlink /proc/1/exe 2>/dev/null || true)" == */systemd ]]; then
    skip "systemd service start is not exercised by this image's PID 1"
else
    skip "systemd service start requires a systemd PID 1; units were syntax-checked only"
fi

if [[ "$functional_failures" -ne 0 ]]; then
    echo "FAIL: Debian package integration checks found $functional_failures functional defect(s)" >&2
    exit 1
fi

echo "Debian package integration checks completed"
