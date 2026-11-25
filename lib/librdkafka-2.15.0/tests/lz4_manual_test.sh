#!/bin/bash
#

#
# Manual test (verification) of LZ4
# See README for details
#

set -e
# Debug what commands are being executed:
#set -x

TOPIC=lz4

if [[ $TEST_KAFKA_VERSION == "trunk" ]]; then
    RDK_ARGS="$RDK_ARGS -X api.version.request=true"
else
    if [[ $TEST_KAFKA_VERSION == 0.8.* ]]; then
	BROKERS=$(echo $BROKERS | sed -e 's/PLAINTEXT:\/\///g')
    fi
    RDK_ARGS="$RDK_ARGS -X broker.version.fallback=$TEST_KAFKA_VERSION"
fi

# Create topic
${KAFKA_PATH}/bin/kafka-topics.sh --zookeeper $ZK_ADDRESS --create \
	     --topic $TOPIC --partitions 1 --replication-factor 1

# Produce messages with rdkafka
echo "### Producing with librdkafka: ids 1000-1010"
seq 1000 1010 | ../examples/rdkafka_example -P -b $BROKERS -t $TOPIC \
					    -z lz4 $RDK_ARGS

# Produce with Kafka
echo "### Producing with Kafka: ids 2000-2010"
seq 2000 2010 | ${KAFKA_PATH}/bin/kafka-console-producer.sh \
			     --broker-list $BROKERS --compression-codec lz4 \
			     --topic $TOPIC

# Consume with rdkafka
echo "### Consuming with librdkafka: expect 1000-1010 and 2000-2010"
../examples/rdkafka_example -C -b $BROKERS -t $TOPIC -p 0 -o beginning -e -q -A \
			    $RDK_ARGS

# Consume with Kafka
echo "### Consuming with Kafka: expect 1000-1010 and 2000-2010"
if [[ $TEST_KAFKA_VERSION == "trunk" ]]; then
    ${KAFKA_PATH}/bin/kafka-console-consumer.sh -new-consumer \
		 --bootstrap-server $BROKERS --from-beginning --topic $TOPIC \
		 --timeout-ms 1000
else
    ${KAFKA_PATH}/bin/kafka-console-consumer.sh \
		 --zookeeper $ZK_ADDRESS --from-beginning --topic $TOPIC \
		 --max-messages 22
fi


echo ""
echo "### $TEST_KAFKA_VERSION: Did you see messages 1000-1010 and 2000-2010 from both consumers?"

