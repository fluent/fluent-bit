TESTSRCS_C = $(wildcard [08]*-*.c)
TESTSRCS_CXX= $(wildcard [08]*-*.cpp)
OBJS	  = $(TESTSRCS_C:%.c=%.o) $(TESTSRCS_CXX:%.cpp=%.o)

BIN	  = merged
LIBS	 += -lrdkafka++ -lrdkafka -lstdc++
OBJS	 += test.o testcpp.o tinycthread.o tinycthread_extra.o rdlist.o sockem.o sockem_ctrl.o
CFLAGS += -I../src
CXXFLAGS += -I../src -I../src-cpp
LDFLAGS += -rdynamic -L../src -L../src-cpp

KAFKA_VERSION?=2.2.0

-include ../Makefile.config

all: $(BIN) run_par

#
# These targets spin up a cluster and runs the test suite
# with different parameters.
#

broker: $(BIN)
	./broker_version_tests.py --conf '{"parallel":1, "args":"-Q"}' $(KAFKA_VERSION)

broker_idempotent: $(BIN)
	./broker_version_tests.py --conf '{"parallel":1, "args":"-P -L -Q"}' $(KAFKA_VERSION)

non_sparse_connections: $(BIN)
	./broker_version_tests.py --brokers 5 \
		--conf '{"parallel":1, "args": "-L -Q", "sparse_connections": "false"}' $(KAFKA_VERSION)

sasl: $(BIN)
	./sasl_test.py --conf '{"parallel":1, "args":"-L -Q"}' --debug $(KAFKA_VERSION)

# Run the full test suite(s)
full: broker broker_idempotent sasl


#
# The following targets require an existing cluster running (test.conf)
#
quick:
	@echo "Running quick(er) test suite (without sockem)"
	./run-test.sh -p5 -Q -E ./$(BIN)

run_par: $(BIN)
	@echo "Running tests in parallel"
	./run-test.sh -p5 ./$(BIN)

run_seq: $(BIN)
	@echo "Running tests sequentially"
	./run-test.sh -p1 ./$(BIN)

run_local: $(BIN)
	@echo "Running local broker-less tests with idempotent producer"
	./run-test.sh -p5 -l -P ./$(BIN)

idempotent_par: $(BIN)
	./run-test.sh -p5 -P ./$(BIN)

idempotent_seq: $(BIN)
	./run-test.sh -p1 -P ./$(BIN)

idempotent: idempotent_par


# Delete all test topics (based on prefix)
delete_topics:
	TESTS=none ./run-test.sh -D ./$(BIN) bare

.PHONY:

build: $(BIN) interceptor_test

test.o: ../src/librdkafka.a ../src-cpp/librdkafka++.a interceptor_test



include ../mklove/Makefile.base

ifeq ($(_UNAME_S),Darwin)
interceptor_test: .PHONY
else
interceptor_test: .PHONY
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

0%:
	TESTS=$@ ./run-test.sh ./$(BIN)

java: .PHONY
	make -C java
