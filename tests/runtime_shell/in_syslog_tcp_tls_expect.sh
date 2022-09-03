#!/bin/sh

. ${FLB_RUNTIME_SHELL_PATH}/common.sh

input_generator() {
    result=$(wait_for_fluent_bit ${SIGNAL_FILE_PATH})

    if test "$result" -eq "0"
    then
        echo '<13>1 1970-01-01T00:00:00.000000+00:00 testhost testuser - - [] Hello!' | \
            openssl s_client -connect $LISTENER_HOST:$LISTENER_PORT 2>&1 >/dev/null
    fi
}

test_in_syslog_tcp_plaintext_filter_expect() {
    export SIGNAL_FILE_PATH="/tmp/fb_signal_$$"
    export LISTENER_VHOST=leo.vcap.me
    export LISTENER_HOST=127.0.0.1 
    export LISTENER_PORT=50002

    input_generator &

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_syslog_tcp_tls_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
