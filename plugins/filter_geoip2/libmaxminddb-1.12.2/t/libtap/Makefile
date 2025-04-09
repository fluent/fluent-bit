CC ?= gcc
CFLAGS += -Wall -I. -fPIC
PREFIX ?= $(DESTDIR)/usr/local
TESTS = $(patsubst %.c, %, $(wildcard t/*.c))

ifdef ANSI
	# -D_BSD_SOURCE for MAP_ANONYMOUS
	CFLAGS += -ansi -D_BSD_SOURCE
	LDLIBS += -lbsd-compat
endif

%:
	$(CC) $(LDFLAGS) $(TARGET_ARCH) $(filter %.o %.a %.so, $^) $(LDLIBS) -o $@

%.o:
	$(CC) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c $(filter %.c, $^) $(LDLIBS) -o $@

%.a:
	$(AR) rcs $@ $(filter %.o, $^)

%.so:
	$(CC) -shared $(LDFLAGS) $(TARGET_ARCH) $(filter %.o, $^) $(LDLIBS) -o $@

all: libtap.a libtap.so tap.pc tests

tap.pc:
	@echo generating tap.pc
	@echo 'prefix='$(PREFIX) > tap.pc
	@echo 'exec_prefix=$${prefix}' >> tap.pc
	@echo 'libdir=$${prefix}/lib' >> tap.pc
	@echo 'includedir=$${prefix}/include' >> tap.pc
	@echo '' >> tap.pc
	@echo 'Name: libtap' >> tap.pc
	@echo 'Description: Write tests in C' >> tap.pc
	@echo 'Version: 0.1.0' >> tap.pc
	@echo 'URL: https://github.com/zorgnax/libtap' >> tap.pc
	@echo 'Libs: -L$${libdir} -ltap' >> tap.pc
	@echo 'Cflags: -I$${includedir}' >> tap.pc

libtap.a: tap.o

libtap.so: tap.o

tap.o: tap.c tap.h

tests: $(TESTS)

$(TESTS): %: %.o libtap.a

$(patsubst %, %.o, $(TESTS)): %.o: %.c tap.h
	$(CC) $(CFLAGS) -O0 $(CPPFLAGS) $(TARGET_ARCH) -c $(filter %.c, $^) $(LDLIBS) -o $@

clean:
	rm -rf *.o t/*.o tap.pc libtap.a libtap.so $(TESTS)

install: libtap.a tap.h libtap.so tap.pc
	mkdir -p $(PREFIX)/lib $(PREFIX)/include $(PREFIX)/lib/pkgconfig
	install -c libtap.a $(PREFIX)/lib
	install -c libtap.so $(PREFIX)/lib
	install -c tap.pc $(PREFIX)/lib/pkgconfig
	install -c tap.h $(PREFIX)/include

uninstall:
	rm $(PREFIX)/lib/libtap.a $(PREFIX)/lib/libtap.so $(PREFIX)/include/tap.h

dist:
	rm libtap.zip
	zip -r libtap *

check test: all
	./t/test

.PHONY: all clean install uninstall dist check test tests
