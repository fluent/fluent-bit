#!/bin/bash
#

if [[ -z $KAFKA_DIR ]]; then
    KAFKA_DIR=~/src/kafka
fi

CLASSPATH=. $KAFKA_DIR/bin/kafka-run-class.sh "$@"

