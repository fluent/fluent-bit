#!/bin/sh

# Environment variables
FLB_BIN=`realpath ../../../build/bin/fluent-bit`
FLB_RUNTIME_SHELL_PATH=`realpath $(pwd)/../`
FLB_RUN_TEST=`realpath $FLB_RUNTIME_SHELL_PATH/../lib/shunit2/shunit2`

# Colorize shunit2
bold=$(tput bold)
normal=$(tput sgr0)
SHUNIT_TEST_PREFIX="$bold==========> UNIT TEST: $normal"

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
        #   $3: Fluent Bit PID
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required
        sqlite3 $1/$2 -batch \
                ".headers off" ".width 20" "SELECT inode FROM in_tail_files" > \
                $1/$2.inodes

        rows=`cat $1/$2.inodes | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "1" ]; then
            echo "> database file $1/$2 contains $rows rows, inodes:"
            cat $1/$2.inodes
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> database file $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "1" $rows
    }

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
    python logger_file.py -l 100000 -s 256 -b 100 -d 0.1 \
           -f $TEST_DIR/a.log \
           -f $TEST_DIR/b.log \
           -f $TEST_DIR/c.log \
           -f $TEST_DIR/d.log \
           -f $TEST_DIR/e.log

    echo "Logger finished...wait 10 seconds"
    sleep 10

    # Count number of processed lines
    write_lines=`cat $TEST_DIR/[abcdefghij].log* | wc -l`
    read_lines=`cat $TEST_DIR/[abcdefghij] | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    # Validate our database files has only one remaining entry per database file
    for logfile in a b c d e; do
        sqlite_check $TEST_DIR "$logfile.db" $FLB_PID
    done

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# 2. Single Static Rotation (static process mode + rotation)
# ----------------------------------------------------------
# Run the logger tool that creates 1 big file and let Fluent Bit process it in
# the static mode, before to promote it to 'events' and it gets rotated.
#
# Configuration file used: conf/single_static_rotation.conf

test_single_static_rotation() {
    # Write a log file of 200000 lines

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    touch $TEST_DIR/a.log

    # Start the Logger: 1 file with 400000 lines, we use a big size (-s) to
    # avoid rotation
    python logger_file.py -l 400000 -s 200000 -b 100 -d 0 \
           -f $TEST_DIR/a.log
    lines=`cat $TEST_DIR/a.log | wc -l`
    echo "Logger done, written lines "$lines

    # Run Fluent Bit
    $FLB_BIN -c conf/single_static_rotation.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Wait 3 seconds before rotation
    sleep 2
    mv $TEST_DIR/a.log $TEST_DIR/a.log.1

    lines=`cat $TEST_DIR/a | wc -l`
    echo "file Rotated, mid-check: processed lines $lines"
    sleep 30

    # Count number of processed lines
    write_lines=`cat $TEST_DIR/a.log.1 | wc -l`
    read_lines=`cat $TEST_DIR/a | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    # Validate our database files has only one remaining entry per database file
    #sqlite_check $TEST_DIR "$logfile.db" $FLB_PID

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# 3. Truncate
# -----------
# Some environments still rely on truncation mode or well known as copytruncate,
# this is the definition by logrotate(8):
#
#  "Truncate the original log file to zero size in place after creating a copy,
#   instead of moving the old log file and optionally creating a new one.  It
#   can be used when some program cannot  be told  to  close its logfile and
#   thus might continue writing (appending) to the previous log file forever.
#
#   Note that there is a very  small  time  slice between copying the file and
#   truncating it, so some logging data might be lost.   When  this  option is
#   used, the create option will have no effect, as the old log file stays in
#   place."
#
# This test checks that after a truncation the new lines added are properly
# processed.
#
# Configuration file used: conf/truncate_rotation.conf

test_truncate() {
    # Helper function to check monitored files
    sqlite_check()
    {
        # Incoming parameters:
        #   $1: temporal directory to store data
        #   $2: database file name
        #   $3: Fluent Bit PID
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required

        # Get the last size of the 'a.log' file and check we have the same value
        # in the database
        offset=`wc -c < $TEST_DIR/a.log`

        sqlite3 $1/$2 -batch \
                ".headers off" "SELECT inode FROM in_tail_files WHERE offset=$offset" > \
                $1/$2.offset

        rows=`cat $1/$2.offset | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "1" ]; then
            echo "> invalid database content:"
            cat $1/$2.offset
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> database file $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "1" $rows
    }

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    touch $TEST_DIR/a.log

    # Start the Logger: 1 file with 200 lines, we use a big size limit (-s) to
    # avoid rotation
    python logger_file.py -l 200 -s 200000 -b 100 -d 0 -f $TEST_DIR/a.log
    lines=`cat $TEST_DIR/a.log | wc -l`
    echo "Logger done, written lines "$lines

    # Run Fluent Bit
    $FLB_BIN -c conf/truncate_rotation.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Wait 2 seconds before truncation
    sleep 2
    pre_lines=`cat $TEST_DIR/a.log | wc -l`
    truncate -s 0 $TEST_DIR/a.log

    lines=`cat $TEST_DIR/a | wc -l`
    echo "file truncated, mid-check: processed lines $lines"

    # Append 100 more lines
    python logger_file.py -l 100 -s 200000 -b 100 -d 0 -f $TEST_DIR/a.log

    sleep 3

    # Count number of processed lines
    write_lines=300
    read_lines=`cat $TEST_DIR/a | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    sqlite_check $TEST_DIR a.db $FLB_PID

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# 4. Rotate Link
# --------------
# This case checks that a monitored link, upon rotation, keeps the proper offset
# and database status for the real file.
#
# Example:
#
# - file with data:  data.log
# - monitored link:  test.log
#
# Check the behavior upon test.log -> test.log.1 behavior
#
# Configuration file used: conf/rotate_link.conf

test_rotate_link() {
    # Helper function to check monitored files
    sqlite_check()
    {
        # Incoming parameters:
        #   $1: temporal directory to store data
        #   $2: database file name
        #   $3: Fluent Bit PID
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required

        # Get the last size of the file pointed by 'a.log.1' and check we have the
        # same value in the database
        offset=`wc -c < $TEST_DIR/a.log.1`

        sqlite3 $1/$2 -batch \
                ".headers off" "SELECT inode FROM in_tail_files WHERE offset=$offset \
                                  AND rotated=1" > $1/$2.offset

        rows=`cat $1/$2.offset | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "1" ]; then
            echo "> invalid database content:"
            cat $1/$2.offset
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> offset database check $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "1" $rows

        # After rotate_wait (5 secs + watcher) we expect an empty database
        sleep 6
        sqlite3 $1/$2 -batch \
                ".headers off" "SELECT inode FROM in_tail_files WHERE offset=$offset \
                                  AND rotated=1" > $1/$2.offset

        rows=`cat $1/$2.offset | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "0" ]; then
            echo "> invalid database content:"
            cat $1/$2.offset
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> empty database check $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "0" $rows
    }

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    touch $TEST_DIR/data.log

    # Start the Logger: 1 file with 100 lines, we use a big size limit (-s) to
    # avoid rotation
    python logger_file.py -l 100 -s 200000 -b 100 -d 0 -f $TEST_DIR/data.log
    lines=`cat $TEST_DIR/data.log | wc -l`
    ln -s data.log $TEST_DIR/a.log
    echo "Logger done, written lines "$lines

    # Run Fluent Bit
    $FLB_BIN -c conf/rotate_link.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Wait 2 seconds and rotate file
    sleep 2
    pre_lines=`cat $TEST_DIR/a.log | wc -l`
    mv $TEST_DIR/a.log $TEST_DIR/a.log.1

    lines=`cat $TEST_DIR/a | wc -l`
    echo "file rotated, mid-check: processed lines $lines"

    # Append 200 more lines to the rotated link
    python logger_file.py -l 200 -s 200000 -b 100 -d 0 -f $TEST_DIR/a.log.1

    # Count number of processed lines
    sleep 3
    write_lines=300
    read_lines=`cat $TEST_DIR/a | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    # Check that database file have the right offset and mark the file as rotated
    sqlite_check $TEST_DIR a.db $FLB_PID

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# 5. Truncate Link
#
# Test a link that gets a truncation and Fluent Bit properly use the new offset
#
# Configuration file used: conf/truncate_link.conf

test_truncate_link() {
    # Helper function to check monitored files
    sqlite_check()
    {
        # Incoming parameters:
        #   $1: temporal directory to store data
        #   $2: database file name
        #   $3: Fluent Bit PID
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required

        # Get the last size of the 'a.log' file and check we have the same value
        # in the database
        offset=`wc -c < $TEST_DIR/a.log`

        sqlite3 $1/$2 -batch \
                ".headers off" "SELECT inode FROM in_tail_files WHERE offset=$offset" > \
                $1/$2.offset

        rows=`cat $1/$2.offset | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "1" ]; then
            echo "> invalid database content:"
            cat $1/$2.offset
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> database file $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "1" $rows
    }

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    touch $TEST_DIR/data.log

    # Start the Logger: 1 file with 100 lines, we use a big size limit (-s) to
    # avoid rotation
    python logger_file.py -l 100 -s 200000 -b 100 -d 0 -f $TEST_DIR/data.log
    lines=`cat $TEST_DIR/data.log | wc -l`
    ln -s data.log $TEST_DIR/a.log
    echo "Logger done, written lines "$lines

    # Run Fluent Bit
    $FLB_BIN -c conf/truncate_link.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Wait 1 second before truncation
    sleep 1
    pre_lines=`cat $TEST_DIR/a.log | wc -l`
    truncate -s 0 $TEST_DIR/a.log

    sleep 2
    lines=`cat $TEST_DIR/a | wc -l`
    echo "file truncated, mid-check: processed lines $lines"

    # Append 200 more lines
    python logger_file.py -l 200 -s 200000 -b 100 -d 0 -f $TEST_DIR/a.log

    sleep 4

    # Count number of processed lines
    write_lines=300
    read_lines=`cat $TEST_DIR/a | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# 6. Multiline + rotation
# ------------------
# Run the logger tool that creates 5 different files, write 100000 messages to each one
# while rotating at 256KB.
#
# This test for issue 4190
#
# Configuration file used: conf/multiline_rotation.conf

test_multiline_rotation() {
    # Helper function to check monitored files
    sqlite_check()
    {
        # Incoming parameters:
        #   $1: temporal directory to store data
        #   $2: database file name
        #   $3: Fluent Bit PID
        #
        # This function store the remaining monitored files listed in the database,
        # we send the output to an .inodes for troubleshooting purposes if required
        sqlite3 $1/$2 -batch \
                ".headers off" ".width 20" "SELECT inode FROM in_tail_files" > \
                $1/$2.inodes

        rows=`cat $1/$2.inodes | wc -l | tr -d -C '[0-9]'`
        if [ $rows != "1" ]; then
            echo "> database file $1/$2 contains $rows rows, inodes:"
            cat $1/$2.inodes
            echo "> open files"
            ls -l /proc/$3/fd/ | grep \\.log
        else
            echo "> database file $1/$2 is OK"
        fi
        ${_ASSERT_EQUALS_} "1" $rows
    }

    # Prepare test directory
    export TEST_DIR=tmp_test
    rm -rf $TEST_DIR
    mkdir $TEST_DIR

    # Create empty files so Fluent Bit will enqueue them on start
    for logfile in a b c d e ; do
        touch $TEST_DIR/$logfile.log
    done

    # Run Fluent Bit
    $FLB_BIN -c conf/multiline_rotation.conf &
    FLB_PID=$!
    echo "Fluent Bit started, pid=$FLB_PID"

    # Start the Logger: 5 files = 500000 log lines in total
    python logger_file.py -l 100000 -s 256 -b 100 -d 0.1 \
           -f $TEST_DIR/a.log \
           -f $TEST_DIR/b.log \
           -f $TEST_DIR/c.log \
           -f $TEST_DIR/d.log \
           -f $TEST_DIR/e.log

    echo "Logger finished...wait 10 seconds"
    sleep 10

    # Count number of processed lines
    write_lines=`cat $TEST_DIR/[abcdefghij].log* | wc -l`
    read_lines=`cat $TEST_DIR/[abcdefghij] | wc -l`

    echo "> write lines: $write_lines"
    echo "> read lines : $read_lines"

    # Check we processed same number of records
    ${_ASSERT_EQUALS_} $write_lines $read_lines

    # Validate our database files has only one remaining entry per database file
    for logfile in a b c d e; do
        sqlite_check $TEST_DIR "$logfile.db" $FLB_PID
    done

    # Stop Fluent Bit (SIGTERM)
    kill -15 $FLB_PID
}

# Launch the tests
. $FLB_RUN_TEST
