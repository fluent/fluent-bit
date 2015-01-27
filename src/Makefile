CC     = gcc
CFLAGS = -g -Wall
INCDIR = -I../include/
SOURCE = in_kmsg.c fluent-bit.c

all:
	$(CC) $(CFLAGS) $(INCDIR) $(SOURCE) -o ../bin/fluent-bit

clean:
	rm -rf ../bin/fluent-bit *.o *~
