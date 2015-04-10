PROG?=main

all: $(PROG)

new: clean all

clean:
	-rm $(PROG)

$(PROG): $(PROG).c
	gcc $(filter %.c,$^) -g -o $@ -lxbee -lpthread -lrt
