DESTDIR=/usr/local
PREFIX=mbedtls_

.SILENT:

.PHONY: all no_test programs lib tests install uninstall clean test check covtest lcov apidoc apidoc_clean

all: programs tests
	$(MAKE) post_build

no_test: programs

programs: lib mbedtls_test
	$(MAKE) -C programs

lib:
	$(MAKE) -C library

tests: lib mbedtls_test
	$(MAKE) -C tests

mbedtls_test:
	$(MAKE) -C tests mbedtls_test

ifndef WINDOWS
install: no_test
	mkdir -p $(DESTDIR)/include/mbedtls
	cp -rp include/mbedtls $(DESTDIR)/include
	mkdir -p $(DESTDIR)/include/psa
	cp -rp include/psa $(DESTDIR)/include

	mkdir -p $(DESTDIR)/lib
	cp -RP library/libmbedtls.*    $(DESTDIR)/lib
	cp -RP library/libmbedx509.*   $(DESTDIR)/lib
	cp -RP library/libmbedcrypto.* $(DESTDIR)/lib

	mkdir -p $(DESTDIR)/bin
	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        cp $$p $(DESTDIR)/bin/$$f ;     \
	    fi                                  \
	done

uninstall:
	rm -rf $(DESTDIR)/include/mbedtls
	rm -rf $(DESTDIR)/include/psa
	rm -f $(DESTDIR)/lib/libmbedtls.*
	rm -f $(DESTDIR)/lib/libmbedx509.*
	rm -f $(DESTDIR)/lib/libmbedcrypto.*

	for p in programs/*/* ; do              \
	    if [ -x $$p ] && [ ! -d $$p ] ;     \
	    then                                \
	        f=$(PREFIX)`basename $$p` ;     \
	        rm -f $(DESTDIR)/bin/$$f ;      \
	    fi                                  \
	done
endif

WARNING_BORDER      =*******************************************************\n
NULL_ENTROPY_WARN_L1=****  WARNING!  MBEDTLS_TEST_NULL_ENTROPY defined! ****\n
NULL_ENTROPY_WARN_L2=****  THIS BUILD HAS NO DEFINED ENTROPY SOURCES    ****\n
NULL_ENTROPY_WARN_L3=****  AND IS *NOT* SUITABLE FOR PRODUCTION USE     ****\n

NULL_ENTROPY_WARNING=\n$(WARNING_BORDER)$(NULL_ENTROPY_WARN_L1)$(NULL_ENTROPY_WARN_L2)$(NULL_ENTROPY_WARN_L3)$(WARNING_BORDER)

WARNING_BORDER_LONG      =**********************************************************************************\n
CTR_DRBG_128_BIT_KEY_WARN_L1=****  WARNING!  MBEDTLS_CTR_DRBG_USE_128_BIT_KEY defined!                      ****\n
CTR_DRBG_128_BIT_KEY_WARN_L2=****  Using 128-bit keys for CTR_DRBG limits the security of generated         ****\n
CTR_DRBG_128_BIT_KEY_WARN_L3=****  keys and operations that use random values generated to 128-bit security ****\n

CTR_DRBG_128_BIT_KEY_WARNING=\n$(WARNING_BORDER_LONG)$(CTR_DRBG_128_BIT_KEY_WARN_L1)$(CTR_DRBG_128_BIT_KEY_WARN_L2)$(CTR_DRBG_128_BIT_KEY_WARN_L3)$(WARNING_BORDER_LONG)

# Post build steps
post_build:
ifndef WINDOWS

	# If 128-bit keys are configured for CTR_DRBG, display an appropriate warning
	-scripts/config.py get MBEDTLS_CTR_DRBG_USE_128_BIT_KEY && ([ $$? -eq 0 ]) && \
	    echo '$(CTR_DRBG_128_BIT_KEY_WARNING)'

	# If NULL Entropy is configured, display an appropriate warning
	-scripts/config.py get MBEDTLS_TEST_NULL_ENTROPY && ([ $$? -eq 0 ]) && \
	    echo '$(NULL_ENTROPY_WARNING)'
endif

clean:
	$(MAKE) -C library clean
	$(MAKE) -C programs clean
	$(MAKE) -C tests clean
ifndef WINDOWS
	find . \( -name \*.gcno -o -name \*.gcda -o -name \*.info \) -exec rm {} +
endif

check: lib tests
	$(MAKE) -C tests check

test: check

ifndef WINDOWS
# note: for coverage testing, build with:
# make CFLAGS='--coverage -g3 -O0'
covtest:
	$(MAKE) check
	programs/test/selftest
	tests/compat.sh
	tests/ssl-opt.sh

lcov:
	rm -rf Coverage
	lcov --capture --initial --directory library -o files.info
	lcov --rc lcov_branch_coverage=1 --capture --directory library -o tests.info
	lcov --rc lcov_branch_coverage=1 --add-tracefile files.info --add-tracefile tests.info -o all.info
	lcov --rc lcov_branch_coverage=1 --remove all.info -o final.info '*.h'
	gendesc tests/Descriptions.txt -o descriptions
	genhtml --title "mbed TLS" --description-file descriptions --keep-descriptions --legend --branch-coverage -o Coverage final.info
	rm -f files.info tests.info all.info final.info descriptions

apidoc:
	mkdir -p apidoc
	cd doxygen && doxygen mbedtls.doxyfile

apidoc_clean:
	rm -rf apidoc
endif

## Editor navigation files
C_SOURCE_FILES = $(wildcard \
	3rdparty/*/include/*/*.h 3rdparty/*/include/*/*/*.h 3rdparty/*/include/*/*/*/*.h \
	3rdparty/*/*.c 3rdparty/*/*/*.c 3rdparty/*/*/*/*.c 3rdparty/*/*/*/*/*.c \
	include/*/*.h \
	library/*.[hc] \
	programs/*/*.[hc] \
	tests/include/*/*.h tests/include/*/*/*.h \
	tests/src/*.c tests/src/*/*.c \
	tests/suites/*.function \
)
# Exuberant-ctags invocation. Other ctags implementations may require different options.
CTAGS = ctags --langmap=c:+.h.function -o
tags: $(C_SOURCE_FILES)
	$(CTAGS) $@ $(C_SOURCE_FILES)
TAGS: $(C_SOURCE_FILES)
	etags -o $@ $(C_SOURCE_FILES)
global: GPATH GRTAGS GSYMS GTAGS
GPATH GRTAGS GSYMS GTAGS: $(C_SOURCE_FILES)
	ls $(C_SOURCE_FILES) | gtags -f - --gtagsconf .globalrc
cscope: cscope.in.out cscope.po.out cscope.out
cscope.in.out cscope.po.out cscope.out: $(C_SOURCE_FILES)
	cscope -bq -u -Iinclude -Ilibrary $(patsubst %,-I%,$(wildcard 3rdparty/*/include)) -Itests/include $(C_SOURCE_FILES)
.PHONY: cscope global
