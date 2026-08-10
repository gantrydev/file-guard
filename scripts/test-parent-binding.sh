#!/usr/bin/env bash
#
# Focused adversarial test: parent-directory rename during restore.
#
# This targets the specific security boundary: verify_parent_binding() in
# secure_file.rs and resolve_bound_path() in transaction.rs. The daemon
# must detect that the parent inode changed between capture and restore,
# and block the transaction rather than write to an attacker-controlled
# directory.
#
# This test uses the transaction manager directly (no FUSE mount) to
# isolate the parent-binding verification path.
#
set -euo pipefail

echo "=== Parent-directory binding verification test ==="
echo ""
echo "This test verifies that the transaction manager detects parent"
echo "directory replacement and blocks the restore operation."
echo ""
echo "Key code paths tested:"
echo "  - secure_file.rs: ResolvedPath::verify_parent_binding()"
echo "  - transaction.rs: TransactionManager::resolve_bound_path()"
echo "  - secure_file.rs: validate_trusted_ancestor()"
echo ""

# Build the test binary first
echo "Building test binary..."
cargo test --no-run --release 2>&1 | tail -5

echo ""
echo "Running the specific parent-replacement test..."
echo ""

# Run the existing unit test that exercises this exact scenario
cargo test --release parent_replacement_during_restore_keeps_the_snapshot -- --nocapture 2>&1

EXIT_CODE=$?

echo ""
if [ $EXIT_CODE -eq 0 ]; then
    echo "=== TEST PASSED ==="
    echo ""
    echo "The transaction manager correctly:"
    echo "  1. Detected the parent directory was replaced"
    echo "  2. Blocked the transaction (persisted blocked_reason)"
    echo "  3. Preserved the original snapshot content"
    echo "  4. Did NOT write to the attacker-controlled directory"
else
    echo "=== TEST FAILED ==="
    echo "Parent directory replacement was not detected!"
fi

exit $EXIT_CODE
