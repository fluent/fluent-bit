#!/bin/sh

# Setup environment if not already set
if [ -z "$FLB_BIN" ]; then
    FLB_ROOT=${FLB_ROOT:-$(cd $(dirname $0)/../.. && pwd)}
    FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
fi

echo "Using Fluent Bit at: $FLB_BIN"

# Create a temporary YAML config file
cat > /tmp/processor_invalid.yaml << EOL
service:
  log_level: debug
  flush: 1
pipeline:
  inputs:
    - name: dummy
      dummy: '{"message": "test message"}'
      tag: test
      processors:
        logs:
          - name: non_existent_processor
            action: invalid

  outputs:
    - name: stdout
      match: '*'
EOL

echo "Running Fluent Bit with invalid processor YAML config..."
echo "YAML Config:"
cat /tmp/processor_invalid.yaml

# Redirect stdout and stderr to a file for analysis
OUTPUT_FILE="/tmp/processor_invalid_output.txt"
$FLB_BIN -c /tmp/processor_invalid.yaml -o stdout > $OUTPUT_FILE 2>&1

# Check exit code - we expect it to fail
EXIT_CODE=$?
echo "Fluent Bit exited with code: $EXIT_CODE"

# Show the output
echo "Output file content:"
cat $OUTPUT_FILE

# Check if the output contains an error related to invalid processor
INVALID_PROCESSOR=$(grep -c "error creating processor 'non_existent_processor': plugin doesn't exist or failed to initialize" $OUTPUT_FILE || true)
FAILED_INIT=$(grep -c "error initializing processor" $OUTPUT_FILE || true)

# Clean up
echo "Cleaning up..."
rm -f /tmp/processor_invalid.yaml
rm -f $OUTPUT_FILE

# Check results - we expect Fluent Bit to fail (non-zero exit code)
# and have an error message about the invalid processor
if [ "$EXIT_CODE" -ne 0 ] && ([ "$INVALID_PROCESSOR" -gt 0 ] || [ "$FAILED_INIT" -gt 0 ]); then
    echo "Test passed: Fluent Bit failed with error about invalid processor"
    exit 0
else
    echo "Test failed: Fluent Bit should fail when an invalid processor is configured"
    echo "Exit code: $EXIT_CODE (expected non-zero)"
    echo "Invalid processor message count: $INVALID_PROCESSOR (expected > 0)"
    echo "Failed init message count: $FAILED_INIT (expected > 0)"
    exit 1
fi