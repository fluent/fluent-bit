
KAFKA_JARS?=$(KAFKA_PATH)/libs

CLASSES=Murmur2Cli.class TransactionProducerCli.class IncrementalRebalanceCli.class

all: $(CLASSES)

%.class: %.java
	CLIENTS_JAR=$$(ls $(KAFKA_JARS)/kafka-clients-*.jar); \
	javac -classpath $$CLIENTS_JAR:$(KAFKA_PATH)/clients/build/classes/java/main $^

clean:
	rm -f *.class
