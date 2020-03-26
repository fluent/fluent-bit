#!/bin/sh

test_in_tail_filter_expect() {
    rm -rf /tmp/flb_*

    # Monitor this file
    echo "{\"key\": \"val\"}" > /tmp/flb_tail_expect_1.log

    # Excluded file
    echo "{\"nokey\": \"\"}" > /tmp/flb_tail_expect_2.log

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_tail_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
