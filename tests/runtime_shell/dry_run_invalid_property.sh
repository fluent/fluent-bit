#!/bin/sh

# Setup environment if not already set
if [ -z "$FLB_BIN" ]; then
    FLB_ROOT=${FLB_ROOT:-$(cd $(dirname $0)/../.. && pwd)}
    FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
fi

echo "Using Fluent Bit at: $FLB_BIN"

# Create a temporary YAML config file with an invalid property
cat > /tmp/dry_run_invalid_property.yaml << EOL
service:
  log_level: debug
  flush: 1
pipeline:
  inputs:
    - name: dummy
      tag: test
      invalid_property_that_does_not_exist: some_value
  outputs:
    - name: stdout
      match: '*'
EOL

echo "Running Fluent Bit with --dry-run and invalid property config..."
echo "YAML Config:"
cat /tmp/dry_run_invalid_property.yaml

# Redirect stdout and stderr to a file for analysis
OUTPUT_FILE="/tmp/dry_run_invalid_property_output.txt"
$FLB_BIN --dry-run -c /tmp/dry_run_invalid_property.yaml > $OUTPUT_FILE 2>&1

# Check exit code - we expect it to fail
EXIT_CODE=$?
echo "Fluent Bit --dry-run exited with code: $EXIT_CODE"

# Show the output
echo "Output file content:"
cat $OUTPUT_FILE

# Check if the output contains an error about the unknown configuration property
UNKNOWN_PROPERTY=$(grep -c "unknown configuration property 'invalid_property_that_does_not_exist'" $OUTPUT_FILE || true)
RELOAD_ERROR=$(grep -c "check properties for input plugins is failed" $OUTPUT_FILE || true)

# Clean up
echo "Cleaning up..."
rm -f /tmp/dry_run_invalid_property.yaml
rm -f $OUTPUT_FILE

# Check results - we expect:
# 1. Fluent Bit to fail (non-zero exit code)
# 2. Error message about unknown configuration property
# 3. Error message from reload validation
if [ "$EXIT_CODE" -ne 0 ] && [ "$UNKNOWN_PROPERTY" -gt 0 ] && [ "$RELOAD_ERROR" -gt 0 ]; then
    echo "Test passed: Fluent Bit --dry-run correctly detected invalid property and failed"
    exit 0
else
    echo "Test failed: Fluent Bit --dry-run should detect invalid properties and fail"
    echo "Exit code: $EXIT_CODE (expected non-zero)"
    echo "Unknown property message count: $UNKNOWN_PROPERTY (expected > 0)"
    echo "Reload error message count: $RELOAD_ERROR (expected > 0)"
    exit 1
fi
