#!/bin/bash
#
# Configure librdkafka for development

set -e
./configure --clean

# enable pedantic
#export CFLAGS='-std=c99 -pedantic -Wshadow'
#export CXXFLAGS='-std=c++98 -pedantic'

# enable FSAN
#FSAN="-fsanitize=address"
#export CPPFLAGS="$CPPFLAGS $FSAN"
#export LDFLAGS="$LDFLAGS $FSAN"

OPTS=""

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

echo "Devel configuration options: $OPTS"
./configure $OPTS

make clean
make -j
(cd tests ; make -j build)
