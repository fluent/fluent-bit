#!/bin/sh

FLB_ROOT=${FLB_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
FLB_RUNTIME_SHELL_CONF=${FLB_RUNTIME_SHELL_CONF:-$FLB_ROOT/tests/runtime_shell/conf}

echo "Using Fluent Bit at: $FLB_BIN"

CONFIG_FILE="$FLB_RUNTIME_SHELL_CONF/dry_run_invalid_property.yaml"
OUTPUT_FILE="/tmp/dry_run_invalid_property_output.txt"

echo "Running Fluent Bit with --dry-run and invalid property config..."
echo "YAML Config:"
cat "$CONFIG_FILE"

"$FLB_BIN" --dry-run -c "$CONFIG_FILE" > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?
echo "Fluent Bit --dry-run exited with code: $EXIT_CODE"

echo "Output file content:"
cat "$OUTPUT_FILE"

UNKNOWN_PROPERTY=$(grep -c \
    "unknown configuration property 'invalid_property_that_does_not_exist'" \
    "$OUTPUT_FILE" || true)
RELOAD_ERROR=$(grep -c \
    "check properties for input plugins is failed" "$OUTPUT_FILE" || true)

rm -f "$OUTPUT_FILE"

if [ "$EXIT_CODE" -ne 0 ] && [ "$UNKNOWN_PROPERTY" -gt 0 ] && \
   [ "$RELOAD_ERROR" -gt 0 ]; then
    echo "Test passed: Fluent Bit --dry-run correctly detected invalid property and failed"
    exit 0
fi

echo "Test failed: Fluent Bit --dry-run should detect invalid properties and fail"
echo "Exit code: $EXIT_CODE (expected non-zero)"
echo "Unknown property message count: $UNKNOWN_PROPERTY (expected > 0)"
echo "Reload error message count: $RELOAD_ERROR (expected > 0)"
exit 1
