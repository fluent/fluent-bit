#!/bin/sh

# --dry-run validates the configuration and tears the pipeline down without
# initializing any plugin. The azure_blob output's worker exit callback used to
# dereference its (then NULL) plugin context and crash.

FLB_ROOT=${FLB_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
FLB_RUNTIME_SHELL_CONF=${FLB_RUNTIME_SHELL_CONF:-$FLB_ROOT/tests/runtime_shell/conf}

echo "Using Fluent Bit at: $FLB_BIN"

CONFIG_FILE="$FLB_RUNTIME_SHELL_CONF/dry_run_azure_blob.conf"
OUTPUT_FILE="/tmp/dry_run_azure_blob_output.txt"

echo "Running Fluent Bit with --dry-run and an azure_blob output..."
echo "Config:"
cat "$CONFIG_FILE"

"$FLB_BIN" --dry-run -c "$CONFIG_FILE" > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?
echo "Fluent Bit --dry-run exited with code: $EXIT_CODE"

echo "Output file content:"
cat "$OUTPUT_FILE"

SIGNAL=$(grep -c "caught signal" "$OUTPUT_FILE" || true)
SUCCESS=$(grep -c "configuration test is successful" "$OUTPUT_FILE" || true)

rm -f "$OUTPUT_FILE"

if [ "$EXIT_CODE" -eq 0 ] && [ "$SIGNAL" -eq 0 ] && [ "$SUCCESS" -gt 0 ]; then
    echo "Test passed: --dry-run with an azure_blob output succeeded"
    exit 0
fi

echo "Test failed: --dry-run with an azure_blob output should succeed"
echo "Exit code: $EXIT_CODE (expected 0)"
echo "Caught signal count: $SIGNAL (expected 0)"
echo "Success message count: $SUCCESS (expected > 0)"
exit 1
