#!/bin/sh

# Run all available tests (mostly).
#
# Warning: includes various build modes, so it will mess with the current
# CMake configuration. After this script is run, the CMake cache is lost and
# CMake is not initialised any more!
#
# Assumes gcc and clang (recent enough for using ASan with gcc and MemSan with
# clang, or valgrind) are available, as well as cmake and a "good" find.

# Abort on errors (and uninitiliased variables)
set -eu

if [ -d library -a -d include -a -d tests ]; then :; else
    echo "Must be run from mbed TLS root" >&2
    exit 1
fi

CONFIG_H='include/mbedtls/config.h'
CONFIG_BAK="$CONFIG_H.bak"

MEMORY=0

while [ $# -gt 0 ]; do
    case "$1" in
        -m*)
            MEMORY=${1#-m}
            ;;
        *)
            echo "Unknown argument: '$1'" >&2
            echo "Use the source, Luke!" >&2
            exit 1
            ;;
    esac
    shift
done

# remove built files as well as the cmake cache/config
cleanup()
{
    make clean

    find . -name yotta -prune -o -iname '*cmake*' -not -name CMakeLists.txt -exec rm -rf {} \+
    rm -f include/Makefile include/mbedtls/Makefile programs/*/Makefile
    git update-index --no-skip-worktree Makefile library/Makefile programs/Makefile tests/Makefile
    git checkout -- Makefile library/Makefile programs/Makefile tests/Makefile

    if [ -f "$CONFIG_BAK" ]; then
        mv "$CONFIG_BAK" "$CONFIG_H"
    fi
}

trap cleanup INT TERM HUP

msg()
{
    echo ""
    echo "******************************************************************"
    echo "* $1 "
    printf "* "; date
    echo "******************************************************************"
}

# The test ordering tries to optimize for the following criteria:
# 1. Catch possible problems early, by running first tests that run quickly
#    and/or are more likely to fail than others (eg I use Clang most of the
#    time, so start with a GCC build).
# 2. Minimize total running time, by avoiding useless rebuilds
#
# Indicative running times are given for reference.

msg "test: recursion.pl" # < 1s
tests/scripts/recursion.pl library/*.c

msg "test: freshness of generated source files" # < 1s
tests/scripts/check-generated-files.sh

msg "test: doxygen markup outside doxygen blocks" # < 1s
tests/scripts/check-doxy-blocks.pl

msg "test/build: declared and exported names" # < 3s
cleanup
tests/scripts/check-names.sh

msg "build: create and build yotta module" # ~ 30s
cleanup
tests/scripts/yotta-build.sh

msg "build: cmake, gcc, ASan" # ~ 1 min 50s
cleanup
CC=gcc cmake -D CMAKE_BUILD_TYPE:String=Asan .
make

msg "test: main suites and selftest (ASan build)" # ~ 50s
make test
programs/test/selftest

msg "test: ssl-opt.sh (ASan build)" # ~ 1 min
tests/ssl-opt.sh

msg "test/build: ref-configs (ASan build)" # ~ 6 min 20s
tests/scripts/test-ref-configs.pl

# Most frequent issues are likely to be caught at this point

msg "build: with ASan (rebuild after ref-configs)" # ~ 1 min
make

msg "test: compat.sh (ASan build)" # ~ 6 min
tests/compat.sh

msg "build: cmake, full config, clang" # ~ 50s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # too slow for tests
CC=clang cmake -D CMAKE_BUILD_TYPE:String=Check .
make

msg "test: main suites (full config)" # ~ 5s
make test

msg "test: ssl-opt.sh default (full config)" # ~ 1s
tests/ssl-opt.sh -f Default

msg "test: compat.sh RC4, DES & NULL (full config)" # ~ 2 min
tests/compat.sh -e '3DES\|DES-CBC3' -f 'NULL\|DES\|RC4\|ARCFOUR'

msg "test/build: curves.pl (gcc)" # ~ 5 min (?)
cleanup
cmake -D CMAKE_BUILD_TYPE:String=Debug .
tests/scripts/curves.pl

msg "build: Unix make, -Os (gcc)" # ~ 30s
cleanup
CC=gcc CFLAGS='-Werror -Os' make

# this is meant to cath missing #define mbedtls_printf etc
# disable fsio to catch some more missing #include <stdio.h>
msg "build: full config except platform/fsio, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_PLATFORM_C
scripts/config.pl unset MBEDTLS_PLATFORM_MEMORY
scripts/config.pl unset MBEDTLS_PLATFORM_PRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_FPRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_SNPRINTF_ALT
scripts/config.pl unset MBEDTLS_PLATFORM_EXIT_ALT
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C
scripts/config.pl unset MBEDTLS_FS_IO
CC=gcc CFLAGS='-Werror -O0' make

# catch compile bugs in _uninit functions
msg "build: full config with NO_STD_FUNCTION, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl set MBEDTLS_PLATFORM_NO_STD_FUNCTIONS
CC=gcc CFLAGS='-Werror -O0' make

msg "build: full config except ssl_srv.c, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_SSL_SRV_C
CC=gcc CFLAGS='-Werror -O0' make

msg "build: full config except ssl_cli.c, make, gcc" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_SSL_CLI_C
CC=gcc CFLAGS='-Werror -O0' make

msg "build: full config except net.c, make, gcc -std=c99 -pedantic" # ~ 30s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C # getaddrinfo() undeclared, etc.
scripts/config.pl set MBEDTLS_NO_PLATFORM_ENTROPY # uses syscall() on GNU/Linux
CC=gcc CFLAGS='-Werror -O0 -std=c99 -pedantic' make lib

if uname -a | grep -F Linux >/dev/null; then
msg "build/test: make shared" # ~ 40s
cleanup
make SHARED=1 all check
fi

if uname -a | grep -F x86_64 >/dev/null; then
msg "build: i386, make, gcc" # ~ 30s
cleanup
CC=gcc CFLAGS='-Werror -m32' make
fi # x86_64

if which arm-none-eabi-gcc >/dev/null; then
msg "build: arm-none-eabi-gcc, make" # ~ 10s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C
scripts/config.pl unset MBEDTLS_TIMING_C
scripts/config.pl unset MBEDTLS_FS_IO
# following things are not in the default config
scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
scripts/config.pl unset MBEDTLS_THREADING_C
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
CC=arm-none-eabi-gcc AR=arm-none-eabi-ar LD=arm-none-eabi-ld CFLAGS=-Werror make lib
fi # arm-gcc

if which armcc >/dev/null && armcc --help >/dev/null 2>&1; then
msg "build: armcc, make"
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl full
scripts/config.pl unset MBEDTLS_NET_C
scripts/config.pl unset MBEDTLS_TIMING_C
scripts/config.pl unset MBEDTLS_FS_IO
scripts/config.pl unset MBEDTLS_HAVE_TIME
scripts/config.pl unset MBEDTLS_HAVE_TIME_DATE
# following things are not in the default config
scripts/config.pl unset MBEDTLS_DEPRECATED_WARNING
scripts/config.pl unset MBEDTLS_HAVEGE_C # depends on timing.c
scripts/config.pl unset MBEDTLS_THREADING_PTHREAD
scripts/config.pl unset MBEDTLS_THREADING_C
scripts/config.pl unset MBEDTLS_MEMORY_BACKTRACE # execinfo.h
scripts/config.pl unset MBEDTLS_MEMORY_BUFFER_ALLOC_C # calls exit
CC=armcc WARNING_CFLAGS= make lib 2> armcc.stderr
if [ -s armcc.stderr ]; then
    cat armcc.stderr
    exit 1;
fi
rm armcc.stderr
fi # armcc

if which i686-w64-mingw32-gcc >/dev/null; then
msg "build: cross-mingw64, make" # ~ 30s
cleanup
CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS=-Werror WINDOWS_BUILD=1 make
WINDOWS_BUILD=1 make clean
CC=i686-w64-mingw32-gcc AR=i686-w64-mingw32-ar LD=i686-w64-minggw32-ld CFLAGS=-Werror WINDOWS_BUILD=1 SHARED=1 make
WINDOWS_BUILD=1 make clean
fi

# MemSan currently only available on Linux 64 bits
if uname -a | grep 'Linux.*x86_64' >/dev/null; then

msg "build: MSan (clang)" # ~ 1 min 20s
cleanup
cp "$CONFIG_H" "$CONFIG_BAK"
scripts/config.pl unset MBEDTLS_AESNI_C # memsan doesn't grok asm
CC=clang cmake -D CMAKE_BUILD_TYPE:String=MemSan .
make

msg "test: main suites (MSan)" # ~ 10s
make test

msg "test: ssl-opt.sh (MSan)" # ~ 1 min
tests/ssl-opt.sh

# Optional part(s)

if [ "$MEMORY" -gt 0 ]; then
    msg "test: compat.sh (MSan)" # ~ 6 min 20s
    tests/compat.sh
fi

else # no MemSan

msg "build: Release (clang)"
cleanup
CC=clang cmake -D CMAKE_BUILD_TYPE:String=Release .
make

msg "test: main suites valgrind (Release)"
make memcheck

# Optional part(s)
# Currently broken, programs don't seem to receive signals
# under valgrind on OS X

if [ "$MEMORY" -gt 0 ]; then
    msg "test: ssl-opt.sh --memcheck (Release)"
    tests/ssl-opt.sh --memcheck
fi

if [ "$MEMORY" -gt 1 ]; then
    msg "test: compat.sh --memcheck (Release)"
    tests/compat.sh --memcheck
fi

fi # MemSan

msg "Done, cleaning up"
cleanup

