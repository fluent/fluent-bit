
PROGS?=test test-static testcpp testcpp-static

all: $(PROGS)

test: test.c
	$(CC) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs rdkafka)

test-static: test.c
	$(CC) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs --static rdkafka-static)

testcpp: test.cpp
	$(CXX) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs rdkafka++)

testcpp-static: test.cpp
	$(CXX) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs rdkafka++-static)

run:
	@(for p in $(PROGS); do \
		echo "# Running $$p" ; \
		./$$p || (echo $$p failed ; exit 1) ; \
	done)

clean:
	rm -f $(PROGS)
