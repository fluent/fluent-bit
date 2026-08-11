#!/bin/sh

FLB_ROOT=${FLB_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
FLB_RUNTIME_SHELL_CONF=${FLB_RUNTIME_SHELL_CONF:-$FLB_ROOT/tests/runtime_shell/conf}

echo "Using Fluent Bit at: $FLB_BIN"

CONFIG_FILE="$FLB_RUNTIME_SHELL_CONF/processor_conditional.yaml"
OUTPUT_FILE="/tmp/processor_conditional_output.txt"

echo "Running Fluent Bit with conditional processor YAML config..."
echo "YAML Config:"
cat "$CONFIG_FILE"

"$FLB_BIN" -c "$CONFIG_FILE" -o stdout > "$OUTPUT_FILE" 2>&1 &
FLB_PID=$!
echo "Fluent Bit started with PID: $FLB_PID"

echo "Waiting for processing to complete..."
sleep 5

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Output file not found"
    kill -15 "$FLB_PID" || true
    exit 1
fi

echo "Output file content:"
cat "$OUTPUT_FILE"

GET_FIELD=$(grep -c "modified_if_get" "$OUTPUT_FILE")
POST_FIELD=$(grep -c "modified_if_post" "$OUTPUT_FILE")

kill -15 "$FLB_PID" || true
rm -f "$OUTPUT_FILE"

if [ "$GET_FIELD" -gt 0 ] && [ "$POST_FIELD" -eq 0 ]; then
    echo "Test passed: GET condition applied, POST condition not applied"
else
    echo "Test failed: GET=$GET_FIELD, POST=$POST_FIELD"
    exit 1
fi

CONFIG_FILE="$FLB_RUNTIME_SHELL_CONF/processor_conditional_grep.yaml"
OUTPUT_FILE="/tmp/processor_conditional_grep_output.txt"

echo "Running Fluent Bit with conditional grep processor YAML config..."
echo "YAML Config:"
cat "$CONFIG_FILE"

"$FLB_BIN" -c "$CONFIG_FILE" -o stdout > "$OUTPUT_FILE" 2>&1 &
FLB_PID=$!
echo "Fluent Bit started with PID: $FLB_PID"

echo "Waiting for processing to complete..."
sleep 5

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Output file not found"
    kill -15 "$FLB_PID" || true
    exit 1
fi

echo "Output file content:"
cat "$OUTPUT_FILE"

LOCALHOST_COUNT=$(grep -c -E '"endpoint"=>"localhost"([^0-9]|$)' "$OUTPUT_FILE")
LOCALHOST2_COUNT=$(grep -c '"endpoint"=>"localhost2"' "$OUTPUT_FILE")
FARHOST_COUNT=$(grep -c '"endpoint"=>"farhost"' "$OUTPUT_FILE")

kill -15 "$FLB_PID" || true
rm -f "$OUTPUT_FILE"

if [ "$LOCALHOST_COUNT" -gt 0 ] && [ "$LOCALHOST2_COUNT" -gt 0 ] &&
   [ "$FARHOST_COUNT" -eq 0 ]; then
    echo "Test passed: conditional grep processor drops only condition-matched records"
    exit 0
fi

echo "Test failed: localhost=$LOCALHOST_COUNT, localhost2=$LOCALHOST2_COUNT, farhost=$FARHOST_COUNT"
exit 1
