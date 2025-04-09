#!/bin/bash
set -e
# Disable all flags to make sure it
# compiles correctly in all cases
./configure --install-deps --disable-ssl --disable-gssapi \
--disable-curl --disable-zlib \
--disable-zstd --disable-lz4-ext --disable-regex-ext \
--disable-c11threads --disable-syslog
make -j
make -j -C tests run_local_quick
