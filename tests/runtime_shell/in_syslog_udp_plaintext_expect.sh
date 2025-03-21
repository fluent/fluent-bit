#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        echo '<13>1 1970-01-01T00:00:00.000000+00:00 testhost testuser - - [] Hello!' | \
            nc -w 1 -u $LISTENER_HOST $LISTENER_PORT
    fi
}

test_in_syslog_tcp_plaintext_filter_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_HOST=127.0.0.1 
    export LISTENER_PORT=50003 

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_syslog_udp_plaintext_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
