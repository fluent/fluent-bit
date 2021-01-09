#!/bin/bash
#
#
# This script runs all tests with valgrind, one by one, forever, to
# make sure there aren't any memory leaks.

ALL=$(seq 0 15)
CNT=0
while true ; do
    for T in $ALL; do
	echo "#################### Test $T run #$CNT #################"
	TESTS=$(printf %04d $T)	./run-test.sh -p valgrind || exit 1
	CNT=$(expr $CNT + 1)
    done
    echo "################## Cleaning up"
    rm -f *.offset
    ./delete-test-topics.sh 0 ~/src/kafka/bin/kafka-topics.sh
done
done

