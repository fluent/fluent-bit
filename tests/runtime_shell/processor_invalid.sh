#!/bin/sh

FLB_ROOT=${FLB_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
FLB_RUNTIME_SHELL_CONF=${FLB_RUNTIME_SHELL_CONF:-$FLB_ROOT/tests/runtime_shell/conf}

echo "Using Fluent Bit at: $FLB_BIN"

CONFIG_FILE="$FLB_RUNTIME_SHELL_CONF/processor_invalid.yaml"
OUTPUT_FILE="/tmp/processor_invalid_output.txt"

echo "Running Fluent Bit with invalid processor YAML config..."
echo "YAML Config:"
cat "$CONFIG_FILE"

"$FLB_BIN" -c "$CONFIG_FILE" -o stdout > "$OUTPUT_FILE" 2>&1
EXIT_CODE=$?
echo "Fluent Bit exited with code: $EXIT_CODE"

echo "Output file content:"
cat "$OUTPUT_FILE"

INVALID_PROCESSOR=$(grep -c \
    "error creating processor 'non_existent_processor': plugin doesn't exist or failed to initialize" \
    "$OUTPUT_FILE" || true)
FAILED_INIT=$(grep -c "error initializing processor" "$OUTPUT_FILE" || true)

rm -f "$OUTPUT_FILE"

if [ "$EXIT_CODE" -ne 0 ] && \
   { [ "$INVALID_PROCESSOR" -gt 0 ] || [ "$FAILED_INIT" -gt 0 ]; }; then
    echo "Test passed: Fluent Bit failed with error about invalid processor"
    exit 0
fi

echo "Test failed: Fluent Bit should fail when an invalid processor is configured"
echo "Exit code: $EXIT_CODE (expected non-zero)"
echo "Invalid processor message count: $INVALID_PROCESSOR (expected > 0)"
echo "Failed init message count: $FAILED_INIT (expected > 0)"
exit 1
