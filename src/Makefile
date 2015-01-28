CC     = gcc
CFLAGS = -g -Wall
INCDIR = -I../include/ -I../lib/
SOURCE = ../lib/mk_config/mk_config.c \
	 ../lib/mk_config/mk_string.c \
	 in_kmsg.c \
	 fluent-bit.c

all:
	$(CC) $(CFLAGS) $(INCDIR) $(SOURCE) -o ../bin/fluent-bit

clean:
	rm -rf ../bin/fluent-bit *.o *~ ../lib/mk_config/*.o
