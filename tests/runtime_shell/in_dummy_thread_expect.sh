#!/bin/sh

test_in_dummy_thread_filter_expect() {
    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_dummy_thread_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
