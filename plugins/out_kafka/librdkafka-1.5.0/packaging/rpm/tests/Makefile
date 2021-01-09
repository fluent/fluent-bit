
all: test testcpp

test: test.c
	$(CC) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs rdkafka)

testcpp: test.cpp
	$(CXX) -O2 -Werror -Wall $^ -o $@ $$(pkg-config --libs rdkafka++)


clean:
	rm -f test testcpp
