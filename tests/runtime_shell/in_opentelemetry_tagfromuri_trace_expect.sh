#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        # sample data from https://github.com/open-telemetry/opentelemetry-proto/blob/main/examples/trace.json
        curl \
            --header "Content-Type: application/json" \
            --request POST \
            --data '{"resourceSpans":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"my.service"}}]},"scopeSpans":[{"scope":{"name":"my.library","version":"1.0.0","attributes":[{"key":"my.scope.attribute","value":{"stringValue":"somescopeattribute"}}]},"spans":[{"traceId":"5B8EFFF798038103D269B633813FC60C","spanId":"EEE19B7EC3C1B174","parentSpanId":"EEE19B7EC3C1B173","name":"I'\''maserverspan","startTimeUnixNano":"1544712660000000000","endTimeUnixNano":"1544712661000000000","kind":2,"attributes":[{"key":"my.span.attr","value":{"stringValue":"somevalue"}}]}]}]}]}' \
            http://${LISTENER_HOST}:${LISTENER_PORT}/v1/traces
    fi
}

test_in_opentelemetry_tagfromuri_trace_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_HOST=127.0.0.1
    export LISTENER_PORT=4318

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_opentelemetry_tagfromuri_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
