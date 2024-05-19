#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        # sample data from https://github.com/open-telemetry/opentelemetry-proto/blob/main/examples/metrics.json
        curl \
            --header "Content-Type: application/json" \
            --request POST \
            --data '{"resourceMetrics":[{"resource":{"attributes":[{"key":"service.name","value":{"stringValue":"my.service"}}]},"scopeMetrics":[{"scope":{"name":"my.library","version":"1.0.0","attributes":[{"key":"my.scope.attribute","value":{"stringValue":"somescopeattribute"}}]},"metrics":[{"name":"my.counter","unit":"1","description":"IamaCounter","sum":{"aggregationTemporality":1,"isMonotonic":true,"dataPoints":[{"asDouble":5,"startTimeUnixNano":"1544712660300000000","timeUnixNano":"1544712660300000000","attributes":[{"key":"my.counter.attr","value":{"stringValue":"somevalue"}}]}]}},{"name":"my.gauge","unit":"1","description":"IamaGauge","gauge":{"dataPoints":[{"asDouble":10,"timeUnixNano":"1544712660300000000","attributes":[{"key":"my.gauge.attr","value":{"stringValue":"somevalue"}}]}]}},{"name":"my.histogram","unit":"1","description":"IamaHistogram","histogram":{"aggregationTemporality":1,"dataPoints":[{"startTimeUnixNano":"1544712660300000000","timeUnixNano":"1544712660300000000","count":2,"sum":2,"bucketCounts":[1,1],"explicitBounds":[1],"min":0,"max":2,"attributes":[{"key":"my.histogram.attr","value":{"stringValue":"somevalue"}}]}]}}]}]}]}' \
            http://${LISTENER_HOST}:${LISTENER_PORT}/v1/metrics
    fi
}

test_in_opentelemetry_tagfromuri_metric_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_HOST=127.0.0.1
    export LISTENER_PORT=4318

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_opentelemetry_tagfromuri_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
