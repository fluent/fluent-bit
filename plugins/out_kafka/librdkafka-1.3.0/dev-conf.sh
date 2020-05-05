#!/bin/bash
#
# librdkafka - Apache Kafka C library
#
# Copyright (c) 2018 Magnus Edenhill
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
#    this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

#
# Configure librdkafka for development
#
# Usage:
#   ./dev-conf.sh             - Build with settings in dev-conf.sh
#   ./dev-conf.sh asan|tsan   - ... and ASAN or TSAN
#   ./dev-conf.sh clean       - Non-development clean build
#

set -e

build () {
    local btype="$1"
    local opts="$2"

    echo "$btype configuration options: $opts"
    ./configure --clean
    ./configure $opts

    make clean
    make -j
    (cd tests ; make -j build)

    echo "$btype build done"
}

OPTS=""

case "$1" in
    clean)
        build Clean
        exit $?
        ;;
    asan)
        FSAN='-fsanitize=address'
        ;;
    tsan)
        FSAN='-fsanitize=thread'
        # C11 threads in glibc don't play nice with TSAN,
        # so use the builtin tinycthreads instead.
        OPTS="$OPTS --disable-c11threads"
        ;;
    ubsan)
        FSAN='-fsanitize=undefined -fsanitize-undefined-trap-on-error -fno-omit-frame-pointer'
        ;;
    "")
        ;;
    *)
        echo "Usage: $0 [clean|asan|tsan]"
        exit 1
        ;;
esac


# enable pedantic
#export CFLAGS='-std=c99 -pedantic -Wshadow'
#export CXXFLAGS='-std=c++98 -pedantic'

if [[ ! -z $FSAN ]]; then
    export CPPFLAGS="$CPPFLAGS $FSAN"
    export LDFLAGS="$LDFLAGS $FSAN"
fi

# enable devel asserts
OPTS="$OPTS --enable-devel"

# disable optimizations
OPTS="$OPTS --disable-optimization"

# gprof
#OPTS="$OPTS --enable-profiling --disable-optimization"

# disable lz4
#OPTS="$OPTS --disable-lz4"

# disable cyrus-sasl
#OPTS="$OPTS --disable-sasl"

# enable sharedptr debugging
#OPTS="$OPTS --enable-sharedptr-debug"

#enable refcnt debugging
#OPTS="$OPTS --enable-refcnt-debug"

build Development $OPTS

