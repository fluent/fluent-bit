#!/bin/sh

set -eu

if [ -d include/mbedtls ]; then :; else
    echo "$0: must be run from root" >&2
    exit 1
fi

if grep -i cmake Makefile >/dev/null; then
    echo "$0: not compatible with cmake" >&2
    exit 1
fi

cp include/mbedtls/config.h{,.bak}
scripts/config.pl full
CFLAGS=-fno-asynchronous-unwind-tables make clean lib >/dev/null 2>&1
mv include/mbedtls/config.h{.bak,}
nm -gUj library/libmbedtls.a 2>/dev/null | sed -n -e 's/^_//p' | sort > exported-symbols
make clean

wc -l exported-symbols
