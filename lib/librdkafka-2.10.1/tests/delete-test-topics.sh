#!/bin/bash
#

set -e

if [[ "$1" == "-n" ]]; then
    DO_DELETE=0
    shift
else
    DO_DELETE=1
fi

ZK=$1
KATOPS=$2
RE=$3

if [[ -z "$ZK" ]]; then
    ZK="$ZK_ADDRESS"
fi

if [[ -z "$KATOPS" ]]; then
    if [[ -d "$KAFKA_PATH" ]]; then
        KATOPS="$KAFKA_PATH/bin/kafka-topics.sh"
    fi
fi

if [[ -z "$RE" ]]; then
    RE="^rdkafkatest_"
fi

if [[ -z "$KATOPS" ]]; then
    echo "Usage: $0 [-n] <zookeeper-address> <kafka-topics.sh> [<topic-name-regex>]"
    echo ""
    echo "Deletes all topics matching regex $RE"
    echo ""
    echo "  -n  - Just collect, dont actually delete anything"
    exit 1
fi

set -u
echo -n "Collecting list of matching topics... "
TOPICS=$($KATOPS --zookeeper $ZK --list 2>/dev/null | grep "$RE") || true
N_TOPICS=$(echo "$TOPICS" | wc -w)
echo "$N_TOPICS topics found"


for t in $TOPICS; do
    if [[ $DO_DELETE == 1 ]]; then
	echo -n "Deleting topic $t... "
	($KATOPS --zookeeper $ZK --delete --topic "$t" 2>/dev/null && echo "deleted") || echo "failed"
    else
	echo "Topic $t"
    fi
done

echo "Done"
