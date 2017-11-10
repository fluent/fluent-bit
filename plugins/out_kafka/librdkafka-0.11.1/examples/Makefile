EXAMPLES ?= rdkafka_example rdkafka_performance rdkafka_example_cpp \
	rdkafka_consumer_example rdkafka_consumer_example_cpp \
	kafkatest_verifiable_client rdkafka_simple_producer

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

rdkafka_simple_producer: ../src/librdkafka.a rdkafka_simple_producer.c
	$(CC) $(CPPFLAGS) $(CFLAGS) $@.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS)

rdkafka_consumer_example: ../src/librdkafka.a rdkafka_consumer_example.c
	$(CC) $(CPPFLAGS) $(CFLAGS) rdkafka_consumer_example.c -o $@ $(LDFLAGS) \
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
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS) -lstdc++

kafkatest_verifiable_client: ../src-cpp/librdkafka++.a ../src/librdkafka.a kafkatest_verifiable_client.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) kafkatest_verifiable_client.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS) -lstdc++


rdkafka_consumer_example_cpp: ../src-cpp/librdkafka++.a ../src/librdkafka.a rdkafka_consumer_example.cpp
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) rdkafka_consumer_example.cpp -o $@ $(LDFLAGS) \
		../src-cpp/librdkafka++.a ../src/librdkafka.a $(LIBS) -lstdc++

rdkafka_zookeeper_example: ../src/librdkafka.a rdkafka_zookeeper_example.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -I/usr/include/zookeeper rdkafka_zookeeper_example.c -o $@ $(LDFLAGS) \
		../src/librdkafka.a $(LIBS) -lzookeeper_mt -ljansson
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

clean:
	rm -f $(EXAMPLES)

