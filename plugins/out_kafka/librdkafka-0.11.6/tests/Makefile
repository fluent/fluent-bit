TESTSRCS_C = $(wildcard [08]*-*.c)
TESTSRCS_CXX= $(wildcard [08]*-*.cpp)
OBJS	  = $(TESTSRCS_C:%.c=%.o) $(TESTSRCS_CXX:%.cpp=%.o)

BIN	  = merged
LIBS	 += -lrdkafka++ -lrdkafka -lstdc++
OBJS	 += test.o testcpp.o tinycthread.o tinycthread_extra.o rdlist.o sockem.o
CFLAGS += -I../src
CXXFLAGS += -I../src -I../src-cpp
LDFLAGS += -rdynamic -L../src -L../src-cpp

KAFKA_VERSION?=1.1.0

-include ../Makefile.config

all: $(BIN) run_par

broker: $(BIN)
	./broker_version_tests.py --conf '{"parallel":1}' $(KAFKA_VERSION)

sasl: $(BIN)
	./sasl_test.py --conf '{"parallel":1}' --no-ssl --debug $(KAFKA_VERSION)

# Run the full test suite(s)
full: broker sasl



run_par: $(BIN)
	@echo "Running tests in parallel"
	./run-test.sh -p5 ./$(BIN)

run_seq: $(BIN)
	@echo "Running tests sequentially"
	./run-test.sh -p1 ./$(BIN)

run_local: $(BIN)
	@echo "Running local broker-less tests"
	./run-test.sh -p5 -l ./$(BIN)

# Delete all test topics (based on prefix)
delete_topics:
	TESTS=none ./run-test.sh -D ./$(BIN) bare

.PHONY: interceptor_test

build: $(BIN) interceptor_test

test.o: ../src/librdkafka.a ../src-cpp/librdkafka++.a interceptor_test



include ../mklove/Makefile.base

ifeq ($(_UNAME_S),Darwin)
interceptor_test:
else
interceptor_test:
	$(MAKE) -C $@
endif


tinycthread.o: ../src/tinycthread.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

tinycthread_extra.o: ../src/tinycthread_extra.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<

rdlist.o: ../src/rdlist.c
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $<


clean:
	rm -f *.test $(OBJS) $(BIN)
	$(MAKE) -C interceptor_test clean

clean-output:
	# Clean test output files
	rm -f stats_*.json *.offset

realclean: clean clean-output
	rm -f test_report_*.json

00%:
	TESTS=$@ ./run-test.sh ./$(BIN)
