# Misc Java tools

## Murmur2 CLI

Build:

    $ KAFKA_JARS=/your/kafka/libs make

Run:

    $ KAFKA_JARS=/your/kafka/libs ./run-class.sh Murmur2Cli "a sentence" and a word

If KAFKA_JARS is not set it will default to $KAFKA_PATH/libs

