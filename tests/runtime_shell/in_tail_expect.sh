#!/bin/sh

test_in_tail_filter_expect() {
    rm -rf /tmp/flb_*

    export TAIL_TEST_GLOB="/tmp/flb_tail_expect*.log"
    export TAIL_TEST_EXCLUDE="/tmp/flb_*2.log"
    export TAIL_TEST_FILE="/tmp/flb_tail_expect_1.log"
    export TAIL_TEST_DB="/tmp/flb_tail_expect.db"

    # Monitor this file
    echo "{\"key\": \"val\"}" > "$TAIL_TEST_FILE"

    # Excluded file
    echo "{\"nokey\": \"\"}" > /tmp/flb_tail_expect_2.log

    $FLB_BIN -c $FLB_RUNTIME_SHELL_CONF/in_tail_expect.conf
}

# The following command launch the unit test
. $FLB_RUNTIME_SHELL_PATH/runtime_shell.env
