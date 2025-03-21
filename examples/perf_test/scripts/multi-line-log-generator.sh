#!/bin/bash
set -eu


OUTPUT_LOGFILE=${OUTPUT_LOGFILE:-/logs/test.log}
rm -fv "$OUTPUT_LOGFILE"

LOG_RATE=${LOG_RATE:-0.2}
LINE_COUNT=${LINE_COUNT:-100}

echo "Sleep for $LOG_RATE and create $OUTPUT_LOGFILE with $LINE_COUNT+1 lines per entry"

while true; do
    cat >> "$OUTPUT_LOGFILE" << EOF
Exception in thread "main" java.lang.RuntimeException: A test exception
EOF
    for _ in $(seq "$LINE_COUNT"); do
cat >> "$OUTPUT_LOGFILE" << EOF
  at com.stackify.stacktrace.StackTraceExample.methodB(StackTraceExample.java:13)
EOF
    done
    sleep "$LOG_RATE"
done
