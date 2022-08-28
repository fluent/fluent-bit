#!/bin/sh

wait_for_fluent_bit() {
    result=1

    for retry in `seq 10` 
    do
        pidof fluent-bit >/dev/null 2>&1

        if test "$?" -eq "0"
        then
            result=0
            break
        fi

        sleep 1
    done

    echo "$result"
}
