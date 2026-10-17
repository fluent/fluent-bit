#!/bin/sh

# Setup environment if not already set
if [ -z "$FLB_BIN" ]; then
    FLB_ROOT=${FLB_ROOT:-$(cd $(dirname $0)/../.. && pwd)}
    FLB_BIN=${FLB_BIN:-$FLB_ROOT/build/bin/fluent-bit}
fi

echo "Using Fluent Bit at: $FLB_BIN"

. $FLB_RUNTIME_SHELL_PATH/go_plugins/build_test_plugins.sh

test_proxy_logs_compatibility() {
    export SIGNAL_FILE_PATH="/tmp/flb_signal_logs_$$.txt"
    STDOUT_OUTPUT_FILE="/tmp/test_logs_stdout_$$.txt"

    rm -f "$STDOUT_OUTPUT_FILE" "$SIGNAL_FILE_PATH"

    $FLB_BIN -e $FLB_ROOT/build/test_logs_go.so -c $FLB_RUNTIME_SHELL_CONF/proxy_logs_test.conf > "$STDOUT_OUTPUT_FILE" 2>&1 &
    FLB_PID=$!

    # the Go output prints every record it receives: wait for the 3 samples
    records=0
    for retry in `seq 20`
    do
        records=$(grep -c '^map\[level:' "$STDOUT_OUTPUT_FILE" 2>/dev/null || true)
        records=${records:-0}
        if [ "$records" -ge 3 ]; then
            break
        fi
        sleep 0.5
    done

    # stop Fluent Bit, it does not exit by itself
    kill -15 "$FLB_PID" 2>/dev/null || true
    wait "$FLB_PID" 2>/dev/null || true

    echo "Output contents:"
    cat "$STDOUT_OUTPUT_FILE"

    rm -f "$STDOUT_OUTPUT_FILE" "$SIGNAL_FILE_PATH"

    assertEquals "records printed by the Go output" 3 "$records"
}

# Load the runtime shell environment
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
