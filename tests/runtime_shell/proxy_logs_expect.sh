#!/bin/sh

# Setup environment if not already set
FLB_ROOT=${FLB_ROOT:-$(CDPATH= cd "$(dirname "$0")/../.." && pwd)}
if [ -z "$FLB_BIN" ]; then
    FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
fi

echo "Using Fluent Bit at: $FLB_BIN"

. "$FLB_RUNTIME_SHELL_PATH/go_plugins/build_test_plugins.sh"

test_proxy_logs_compatibility() {
    export SIGNAL_FILE_PATH="/tmp/flb_signal_logs_$$.txt"
    STDOUT_OUTPUT_FILE="/tmp/test_logs_stdout_$$.txt"
    EXPECTED_BYTES="message:[116 101 115 116 32 108 111 103 32 101 110 116 114 121]"
    
    rm -f "$STDOUT_OUTPUT_FILE" "$SIGNAL_FILE_PATH"
    
    "$FLB_BIN" -e "$FLB_ROOT/build/test_logs_go.so" -c "$FLB_RUNTIME_SHELL_CONF/proxy_logs_test.conf" > "$STDOUT_OUTPUT_FILE" 2>&1 &
    FLB_PID=$!
    
    RECORD_WAIT=0
    until grep -Fq "message:test log entry" "$STDOUT_OUTPUT_FILE" ||
          grep -Fq "$EXPECTED_BYTES" "$STDOUT_OUTPUT_FILE"; do
        if ! kill -0 "$FLB_PID" 2>/dev/null || [ "$RECORD_WAIT" -ge 30 ]; then
            break
        fi
        RECORD_WAIT=$((RECORD_WAIT + 1))
        sleep 1
    done

    FLB_STATUS=0
    kill "$FLB_PID" 2>/dev/null || FLB_STATUS=1
    SHUTDOWN_WAIT=0
    while kill -0 "$FLB_PID" 2>/dev/null; do
        if [ "$SHUTDOWN_WAIT" -ge 15 ]; then
            echo "FAIL: Go plugin shutdown exceeded 15 seconds"
            FLB_STATUS=1
            kill -KILL "$FLB_PID" 2>/dev/null || :
            break
        fi
        SHUTDOWN_WAIT=$((SHUTDOWN_WAIT + 1))
        sleep 1
    done
    wait "$FLB_PID" 2>/dev/null || FLB_STATUS=1
    
    if [ "$FLB_STATUS" -eq 0 ] &&
        { grep -Fq "message:test log entry" "$STDOUT_OUTPUT_FILE" ||
          grep -Fq "$EXPECTED_BYTES" "$STDOUT_OUTPUT_FILE"; }; then
        echo "SUCCESS: Go output plugin received the test record"
    else
        echo "FAIL: Go output plugin did not process the record and shut down cleanly"
        FLB_STATUS=1
    fi
    if [ -f "$STDOUT_OUTPUT_FILE" ]; then
        cat "$STDOUT_OUTPUT_FILE"
    fi
    
    # Clean up
    rm -f "$STDOUT_OUTPUT_FILE" "$SIGNAL_FILE_PATH"
    return "$FLB_STATUS"
}

# Load the runtime shell environment
. "$FLB_RUNTIME_SHELL_PATH/runtime_shell.env"
