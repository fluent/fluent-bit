#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit)

    if test "$result" -eq "0"
    then
        curl -s -k \
            -H 'content-type: application/json' \
            -d '{"message": "Hello!"}' \
            "https://${LISTENER_HOST}:${LISTENER_PORT}"
    fi
}

test_in_http_tls_filter_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_VHOST=leo.vcap.me
    export LISTENER_HOST=127.0.0.1 
    export LISTENER_PORT=50000

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_http_tls_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
