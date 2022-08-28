#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/in_syslog_common.sh

input_generator() {
    result=$(wait_for_fluent_bit)

    if test "$result" -eq "0"
    then
        logger -u $SOCKET_PATH 'Hello!'
    fi
}

test_in_syslog_uds_stream_plaintext_filter_expect() {
    export SOCKET_PATH=/tmp/fluent_bit_syslog_uds_stream.sock

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_syslog_uds_stream_plaintext_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
