#!/bin/sh

# This function is meant to be used alongside with
# in_expect_base.conf or a similar setup where 
# fluent-bit is set up to create a file as soon
# as it starts.
#
# I would rather use pidof but it's not viable.
#
wait_for_fluent_bit() {
    result=1

    for retry in `seq 10` 
    do
        if test -f $1
        then
            sleep 1
            result=0
            break
        fi

        sleep 1
    done

    echo "$result"
}
