PROG?=main

all: $(PROG)

run: all
	LD_LIBRARY_PATH=../../../lib ./$(PROG)

new: clean all

clean:
	-rm $(PROG)

$(PROG): $(PROG).cpp ../../../lib/libxbee.so ../../../lib/libxbeep.so
	g++ $(filter %.cpp,$^) -g -o $@ -I ../../.. -L ../../../lib -lxbeep
