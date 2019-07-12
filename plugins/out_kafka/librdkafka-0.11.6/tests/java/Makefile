
KAFKA_JARS?=$(KAFKA_PATH)/libs

Murmur2Cli.class: Murmur2Cli.java
	javac -classpath $(KAFKA_JARS)/kafka-clients-*.jar $^

clean:
	rm -f *.class
