#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/in_syslog_common.sh

syslog_udp_plaintext_input_generator() {
    result=$(wait_for_fluent_bit)

    if test "$result" -eq "0"
    then
        logger -d -n $LISTENER_HOST -P $LISTENER_PORT 'Hello!'
    fi
}

# logger -u /tmp/fb_syslog_uds_dgram.sock '{"a": "b"}'

test_in_syslog_tcp_plaintext_filter_expect() {
    export LISTENER_HOST=127.0.0.1 
    export LISTENER_PORT=9999 

    syslog_udp_plaintext_input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_syslog_udp_plaintext_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
