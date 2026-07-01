#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        echo '<13>Jan  1 00:00:00 testuser:  Hello!' | nc -w 1 -U $SOCKET_PATH
    fi
}

test_in_syslog_uds_stream_plaintext_filter_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export SOCKET_PATH=/tmp/fluent_bit_syslog_uds_stream.sock

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_syslog_uds_stream_plaintext_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
