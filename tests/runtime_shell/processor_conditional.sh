#!/bin/sh

# Setup environment if not already set
if [ -z "$FLB_BIN" ]; then
    FLB_ROOT=${FLB_ROOT:-$(cd $(dirname $0)/../.. && pwd)}
    FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
fi

echo "Using Fluent Bit at: $FLB_BIN"

# Create a temporary YAML config file
cat > /tmp/processor_conditional.yaml << EOL
service:
  log_level: trace
  flush: 1
pipeline:
  inputs:
    - name: dummy
      dummy: '{"request": {"method": "GET", "path": "/api/v1/resource", "headers": {"Authorization": "Bearer valid-token"}, "access": "granted"}}'
      tag: error.msg
      processors:
        logs:
          - name: content_modifier
            action: insert
            key: modified_if_post
            value: true
            condition:
              op: and
              rules:
                - field: \$request['method']
                  op: eq
                  value: POST

          - name: content_modifier
            action: insert
            key: modified_if_get
            value: true
            condition:
              op: and
              rules:
                - field: \$request['method']
                  op: eq
                  value: GET

  outputs:
    - name: stdout
      match: '*'
EOL

echo "Running Fluent Bit with conditional processor YAML config..."
echo "YAML Config:"
cat /tmp/processor_conditional.yaml

# Redirect stdout to a file for analysis
OUTPUT_FILE="/tmp/processor_conditional_output.txt"
$FLB_BIN -c /tmp/processor_conditional.yaml -o stdout > $OUTPUT_FILE 2>&1 &
FLB_PID=$!
echo "Fluent Bit started with PID: $FLB_PID"

# Wait for output to be generated
echo "Waiting for processing to complete..."
sleep 5

# Check for output
if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Output file not found"
    kill -15 $FLB_PID || true
    exit 1
fi

echo "Output file content:"
cat $OUTPUT_FILE

# Verify that the GET condition was applied but not the POST condition
GET_FIELD=$(grep -c "modified_if_get" $OUTPUT_FILE)
POST_FIELD=$(grep -c "modified_if_post" $OUTPUT_FILE)

# Clean up
echo "Cleaning up..."
kill -15 $FLB_PID || true
rm -f /tmp/processor_conditional.yaml
rm -f $OUTPUT_FILE

# Check results
if [ "$GET_FIELD" -gt 0 ] && [ "$POST_FIELD" -eq 0 ]; then
    echo "Test passed: GET condition applied, POST condition not applied"
    exit 0
else
    echo "Test failed: GET=$GET_FIELD, POST=$POST_FIELD"
    exit 1
fi