#!/bin/bash
#

[[ -z "$DELETE_TOPICS" ]] && DELETE_TOPICS=y

if [[ -z $ZK_ADDRESS ]]; then
    ZK_ADDRESS="localhost"
fi

set -e

ARGS=
while [[ $1 == -* ]]; do
    ARGS="$ARGS $1"
    shift
done

modes=$*
if [[ -z "$modes" ]]; then
   modes="valgrind"
fi

if [[ -z "$TESTS" ]]; then
    tests=$(echo 0???-*.c 0???-*.cpp)
else
    tests="$TESTS"
fi

iter=0
while true ; do
    iter=$(expr $iter + 1)

    for t in $tests ; do
        # Strip everything after test number (0001-....)
        t=$(echo $t | cut -d- -f1)

        for mode in $modes ; do

            echo "##################################################"
            echo "##################################################"
            echo "############ Test iteration $iter ################"
            echo "############ Test $t in mode $mode ###############"
            echo "##################################################"
            echo "##################################################"

            if [[ $t == all ]]; then
                unset TESTS
            else
                export TESTS=$t
            fi
            ./run-test.sh $ARGS ./merged $mode || (echo "Failed on iteration $iter, test $t, mode $mode" ; exit 1)
        done
    done


    if [[ "$DELETE_TOPICS" == "y" ]]; then
        # Delete topics using Admin API, which is very fast
        # leads to sub-sequent test failures because of the background
        # deletes in Kafka still taking a long time:
        #
        #make delete_topics

        # Delete topic-by-topic using kafka-topics for each one,
        # very slow but topics are properly deleted before the script
        # returns.
        ./delete-test-topics.sh $ZK_ADDRESS ~/src/kafka/bin/kafka-topics.sh || true
    fi
done


