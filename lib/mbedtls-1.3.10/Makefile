
DESTDIR=/usr/local
PREFIX=mbedtls_
OLDPREFIX=polarssl_

.SILENT:

all:
	cd library  && $(MAKE) all && cd ..
	cd programs && $(MAKE) all && cd ..
	cd tests    && $(MAKE) all && cd ..

no_test:
	cd library  && $(MAKE) all && cd ..
	cd programs && $(MAKE) all && cd ..

lib:
	cd library  && $(MAKE) all && cd ..

install:
	mkdir -p $(DESTDIR)/include/polarssl
	cp -r include/polarssl $(DESTDIR)/include
	
	mkdir -p $(DESTDIR)/lib
	cp library/libpolarssl.* library/libmbedtls.* $(DESTDIR)/lib
	
	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        o=$(OLDPREFIX)`basename $$p` ;  \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	        ln -sf $$f $(DESTDIR)/bin/$$o ; \
	    fi                                  \
	done

uninstall:
	rm -rf $(DESTDIR)/include/polarssl
	rm -f $(DESTDIR)/lib/libpolarssl.*
	rm -f $(DESTDIR)/lib/libmbedtls.*
	
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        o=$(OLDPREFIX)`basename $$p` ;  \
	        rm -f $(DESTDIR)/bin/$$f ;      \
	        rm -f $(DESTDIR)/bin/$$o ;      \
	    fi                                  \
	done

clean:
	cd library  && $(MAKE) clean && cd ..
	cd programs && $(MAKE) clean && cd ..
	cd tests    && $(MAKE) clean && cd ..
	find . \( -name \*.gcno -o -name \*.gcda -o -name *.info \) -exec rm {} +

check: lib
	( cd tests && $(MAKE) && $(MAKE) check )

test-ref-configs:
	tests/scripts/test-ref-configs.pl

# note: for coverage testing, build with:
# CFLAGS='--coverage' make OFLAGS='-g3 -O0'
covtest:
	make check
	programs/test/selftest
	( cd tests && ./compat.sh )
	( cd tests && ./ssl-opt.sh )

lcov:
	rm -rf Coverage
	lcov --capture --initial --directory library -o files.info
	lcov --capture --directory library -o tests.info
	lcov --add-tracefile files.info --add-tracefile tests.info -o all.info
	lcov --remove all.info -o final.info '*.h'
	gendesc tests/Descriptions.txt -o descriptions
	genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --no-branch-coverage -o Coverage final.info
	rm -f files.info tests.info all.info final.info descriptions

apidoc:
	mkdir -p apidoc
	doxygen doxygen/mbedtls.doxyfile

apidoc_clean:
	if [ -d apidoc ] ;			\
	then				    	\
		rm -rf apidoc ;			\
	fi
