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
    
    sleep 3
    
    if [ -f "$STDOUT_OUTPUT_FILE" ]; then
        echo "SUCCESS: Captured Fluent Bit output"
        echo "Output contents:"
        cat "$STDOUT_OUTPUT_FILE"
    else
        echo "FAIL: No stdout output captured"
        return 1
    fi
    
    # Clean up
    rm -f "$STDOUT_OUTPUT_FILE" "$SIGNAL_FILE_PATH"
}

# Load the runtime shell environment
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
