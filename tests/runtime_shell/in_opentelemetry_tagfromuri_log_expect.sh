#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        # sample data from https://github.com/open-telemetry/opentelemetry-proto/blob/main/examples/logs.json
        curl \
            --header "Content-Type: application/json" \
            --request POST \
            --data '{"resourceLogs":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"my.service"}}]},"scopeLogs":[{"scope":{"name":"my.library","version":"1.0.0","attributes":[{"key":"my.scope.attribute","value":{"stringValue":"somescopeattribute"}}]},"logRecords":[{"timeUnixNano":"1544712660300000000","observedTimeUnixNano":"1544712660300000000","severityNumber":10,"severityText":"Information","traceId":"5B8EFFF798038103D269B633813FC60C","spanId":"EEE19B7EC3C1B174","body":{"stringValue":"Examplelogrecord"},"attributes":[{"key":"string.attribute","value":{"stringValue":"somestring"}},{"key":"boolean.attribute","value":{"boolValue":true}},{"key":"int.attribute","value":{"intValue":"10"}},{"key":"double.attribute","value":{"doubleValue":637.704}},{"key":"array.attribute","value":{"arrayValue":{"values":[{"stringValue":"many"},{"stringValue":"values"}]}}},{"key":"map.attribute","value":{"kvlistValue":{"values":[{"key":"some.map.key","value":{"stringValue":"somevalue"}}]}}}]}]}]}]}' \
            http://${LISTENER_HOST}:${LISTENER_PORT}/v1/logs
    fi
}

test_in_opentelemetry_tagfromuri_log_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_HOST=127.0.0.1
    export LISTENER_PORT=4318

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_opentelemetry_tagfromuri_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
