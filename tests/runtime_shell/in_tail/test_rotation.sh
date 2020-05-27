#!/bin/sh

# Environment variables
FLB_BIN=`realpath ../../../build/bin/fluent-bit`
FLB_RUNTIME_SHELL_PATH=`realpath $(pwd)/../`
FLB_RUN_TEST=`realpath $FLB_RUNTIME_SHELL_PATH/../lib/shunit2/shunit2`

# 1. Normal Rotation
# ------------------
# Run the logger tool that creates 5 different files, write 100000 messages to each one
# while rotating at 256KB.
#
# This test enable the database backend for Tail so it also helps to validate expected
# entries into the 'in_tail_files' table.
#
# Configuration file used: conf/normal_rotation.conf

test_normal_rotation() {
    # Helper function to check monitored files
    sqlite_check()
    {
        # Incoming parameters:
        #   $1: temporal directory to store data
        #   $2: database file name
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required
        sqlite3 $1/$2 -batch \
                ".headers off" ".width 20" "SELECT inode FROM in_tail_files" > \
                $1/$2.inodes

        rows=`cat $1/$2.inodes | wc -l`
        if [ $rows != "1" ]; then
            echo "> database file $1/$2 contains $rows rows, inodes:"
            cat $1/$2.inodes
        else
            echo "> database file $1/$2 is OK"
        fi
        assertEquals "1" $rows
    }

    #sqlite_check "tmp_test" "a.db"
    #return

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    for logfile in a b c d e ; do
        touch $TEST_DIR/$logfile.log
    done

    # Run Fluent Bit
    $FLB_BIN -c conf/normal_rotation.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Start the Logger: 5 files = 500000 log lines in total
    python logger_file.py -l 100000 -s 256 -b 100 \
           -f $TEST_DIR/a.log \
           -f $TEST_DIR/b.log \
           -f $TEST_DIR/c.log \
           -f $TEST_DIR/d.log \
           -f $TEST_DIR/e.log

    echo "Logger finished...wait 10 seconds"
    sleep 10

    # Stop Fluent Bit (SIGSTOP)
    kill -3 $FLB_PID

    # Count number of processed lines
    write_lines=`cat $TEST_DIR/[abcdefghij].log* | wc -l`
    read_lines=`cat $TEST_DIR/[abcdefghij] | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    assertEquals $write_lines $read_lines

    # Validate our database files has only one remaining entry per database file
    for logfile in a b c d e; do
        sqlite_check $TEST_DIR "$logfile.db"
    done
}

# Launch the tests
. $FLB_RUN_TEST
