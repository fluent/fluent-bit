PROGRAMS?=fuzz_regex

all: $(PROGRAMS)


fuzz_%:
	$(CC) -fsanitize=address -D WITH_MAIN -g -Wall \
		-I../../src $@.c -o $@ ../../src/librdkafka.a


clean:
	rm -f $(PROGRAMS)
