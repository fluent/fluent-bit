
KAFKA_JARS?=$(KAFKA_PATH)/libs

CLASSES=Murmur2Cli.class TransactionProducerCli.class IncrementalRebalanceCli.class

all: $(CLASSES)

%.class: %.java
	javac -classpath $(KAFKA_JARS)/kafka-clients-*.jar $^

clean:
	rm -f *.class
