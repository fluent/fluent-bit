EXAMPLES ?= rdkafka_example rdkafka_performance rdkafka_example_cpp \
	rdkafka_complex_consumer_example rdkafka_complex_consumer_example_cpp \
	kafkatest_verifiable_client \
	producer consumer idempotent_producer transactions \
	delete_records \
	openssl_engine_example_cpp

all: $(EXAMPLES)

include ../mklove/Makefile.base

CFLAGS += -I../src
CXXFLAGS += -I../src-cpp

# librdkafka must be compiled with -gstrict-dwarf, but rdkafka_example must not,
# due to some clang bug on OSX 10.9
CPPFLAGS := $(subst strict-dwarf,,$(CPPFLAGS))

rdkafka_example: ../src/librdkafka.a rdkafka_example.c
	$(CC) $(CPPFLAGS) $(CFLAGS) rdkafka_example.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)
	@echo "# $@ is ready"
	@echo "#"
	@echo "# Run producer (write messages on stdin)"
	@echo "./$@ -P -t <topic> -p <partition>"
	@echo ""
	@echo "# or consumer"
	@echo "./$@ -C -t <topic> -p <partition>"
	@echo ""
	@echo "#"
	@echo "# More usage options:"
	@echo "./$@ -h"

producer: ../src/librdkafka.a producer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

producer_cpp: ../src-cpp/librdkafka++.a ../src/librdkafka.a producer.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) producer.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)

consumer: ../src/librdkafka.a consumer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

idempotent_producer: ../src/librdkafka.a idempotent_producer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

transactions: ../src/librdkafka.a transactions.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

transactions-older-broker.c: ../src/librdkafka.a transactions-older-broker.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

delete_records: ../src/librdkafka.a delete_records.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

rdkafka_complex_consumer_example: ../src/librdkafka.a rdkafka_complex_consumer_example.c
	$(CC) $(CPPFLAGS) $(CFLAGS) rdkafka_complex_consumer_example.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)
	@echo "# $@ is ready"
	@echo "#"
	@echo "./$@ <topic[:part]> <topic2[:part]> .."
	@echo ""
	@echo "#"
	@echo "# More usage options:"
	@echo "./$@ -h"

rdkafka_performance: ../src/librdkafka.a rdkafka_performance.c
	$(CC) $(CPPFLAGS) $(CFLAGS) rdkafka_performance.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)
	@echo "# $@ is ready"
	@echo "#"
	@echo "# Run producer"
	@echo "./$@ -P -t <topic> -p <partition> -s <msgsize>"
	@echo ""
	@echo "# or consumer"
	@echo "./$@ -C -t <topic> -p <partition>"
	@echo ""
	@echo "#"
	@echo "# More usage options:"
	@echo "./$@ -h"


rdkafka_example_cpp: ../src-cpp/librdkafka++.a ../src/librdkafka.a rdkafka_example.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) rdkafka_example.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)

kafkatest_verifiable_client: ../src-cpp/librdkafka++.a ../src/librdkafka.a kafkatest_verifiable_client.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) kafkatest_verifiable_client.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)


rdkafka_complex_consumer_example_cpp: ../src-cpp/librdkafka++.a ../src/librdkafka.a rdkafka_complex_consumer_example.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) rdkafka_complex_consumer_example.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)

rdkafka_consume_batch: ../src-cpp/librdkafka++.a ../src/librdkafka.a rdkafka_consume_batch.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) rdkafka_consume_batch.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)

openssl_engine_example_cpp: ../src-cpp/librdkafka++.a ../src/librdkafka.a openssl_engine_example.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) openssl_engine_example.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS)

clean:
	rm -f $(EXAMPLES)

