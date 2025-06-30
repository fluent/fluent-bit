#!/bin/bash
#

if [[ -z $KAFKA_PATH ]]; then
    echo "$0: requires \$KAFKA_PATH to point to the kafka release top directory"
    exit 1
fi

JAVA_TESTS_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

CLASSPATH=$JAVA_TESTS_DIR $KAFKA_PATH/bin/kafka-run-class.sh "$@"
