.PHONY: all

all: libxbee.jar libxbee_java.so

libxbee.jar: uk/co/attie/libxbee.class
	jar -cvf $@ `find uk -name '*.class' -o -name '*.java'` 

libxbee_java.so: libxbee.o
	gcc -shared $^ -o $@

libxbee.o: libxbee.c uk_co_attie_libxbee.h
	gcc -I`readlink -f /usr/bin/javac | sed 's:/bin/javac::'`/include $(filter %.c,$^) -c -o $@

uk_co_attie_libxbee.h: uk/co/attie/libxbee.class
	javah `echo -n $(patsubst %.class,%,$^) | sed 's:/:.:g'`

%.class: %.java
	javac $^
