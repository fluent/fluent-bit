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
else
    echo "Test failed: GET=$GET_FIELD, POST=$POST_FIELD"
    exit 1
fi

# Create a temporary YAML config file for grep filter used as processor
cat > /tmp/processor_conditional_grep.yaml << EOL
service:
  log_level: trace
  flush: 1
pipeline:
  inputs:
    - name: dummy
      dummy: '{"endpoint":"localhost", "value":"something"}'
      tag: dummy
      processors:
        logs:
          - name: grep
            logical_op: and
            regex:
              - value something
            condition:
              op: and
              rules:
                - field: \$endpoint
                  op: eq
                  value: farhost
    - name: dummy
      dummy: '{"endpoint":"localhost2", "value":"something"}'
      tag: dummy
      processors:
        logs:
          - name: grep
            logical_op: and
            regex:
              - value something
            condition:
              op: and
              rules:
                - field: \$endpoint
                  op: eq
                  value: farhost
    - name: dummy
      dummy: '{"endpoint":"farhost", "value":"nothing"}'
      tag: dummy
      processors:
        logs:
          - name: grep
            logical_op: and
            regex:
              - value something
            condition:
              op: and
              rules:
                - field: \$endpoint
                  op: eq
                  value: farhost

  outputs:
    - name: stdout
      match: '*'
EOL

echo "Running Fluent Bit with conditional grep processor YAML config..."
echo "YAML Config:"
cat /tmp/processor_conditional_grep.yaml

OUTPUT_FILE="/tmp/processor_conditional_grep_output.txt"
$FLB_BIN -c /tmp/processor_conditional_grep.yaml -o stdout > $OUTPUT_FILE 2>&1 &
FLB_PID=$!
echo "Fluent Bit started with PID: $FLB_PID"

echo "Waiting for processing to complete..."
sleep 5

if [ ! -f "$OUTPUT_FILE" ]; then
    echo "Output file not found"
    kill -15 $FLB_PID || true
    exit 1
fi

echo "Output file content:"
cat $OUTPUT_FILE

LOCALHOST_COUNT=$(grep -c -E "\"endpoint\"=>\"localhost\"([^0-9]|$)" $OUTPUT_FILE)
LOCALHOST2_COUNT=$(grep -c "\"endpoint\"=>\"localhost2\"" $OUTPUT_FILE)
FARHOST_COUNT=$(grep -c "\"endpoint\"=>\"farhost\"" $OUTPUT_FILE)

echo "Cleaning up..."
kill -15 $FLB_PID || true
rm -f /tmp/processor_conditional_grep.yaml
rm -f $OUTPUT_FILE

if [ "$LOCALHOST_COUNT" -gt 0 ] && [ "$LOCALHOST2_COUNT" -gt 0 ] &&
   [ "$FARHOST_COUNT" -eq 0 ]; then
    echo "Test passed: conditional grep processor drops only condition-matched records"
    exit 0
fi

echo "Test failed: localhost=$LOCALHOST_COUNT, localhost2=$LOCALHOST2_COUNT, farhost=$FARHOST_COUNT"
exit 1
