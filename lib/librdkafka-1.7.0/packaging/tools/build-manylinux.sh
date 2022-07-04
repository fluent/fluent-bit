#!/bin/bash
#
# Build on a manylinux (https://github.com/pypa/manylinux) docker container.
#
# This will provide a self-contained librdkafka shared library that works
# on most glibc-based Linuxes.
#
# Statically linked
# WITH openssl 1.1.1, zlib, lz4(bundled)
# WITHOUT libsasl2
#
#
# Run:
#  docker run -t -v "$PWD:/v quay.io/pypa/manylinux2010_x86_64 /v/packaging/tools/build-manylinux.sh /v /v/artifacts/librdkafka-manylinux2010_x86_64.tgz $config_args"

set -ex

LRK_DIR=$1
shift
OUT_TGZ=$1
shift
CONFIG_ARGS=$*

if [[ ! -f $LRK_DIR/configure.self || -z $OUT_TGZ ]]; then
    echo "Usage: $0 <librdkafka-root-direcotry> <output-tgz> [<configure-args..>]"
    exit 1
fi

set -u

yum install -y libstdc++-devel gcc gcc-c++ python34

# Copy the librdkafka git archive to a new location to avoid messing
# up the librdkafka working directory.

BUILD_DIR=$(mktemp -d)

pushd $BUILD_DIR

DEST_DIR=$PWD/dest
mkdir -p $DEST_DIR

(cd $LRK_DIR ; git archive --format tar HEAD) | tar xf -

./configure --install-deps --source-deps-only --disable-gssapi --disable-lz4-ext --enable-static --prefix=$DEST_DIR $CONFIG_ARGS

make -j

examples/rdkafka_example -X builtin.features

CI=true make -C tests run_local_quick

make install

# Tar up the output directory
pushd $DEST_DIR
ldd lib/*.so.1
tar cvzf $OUT_TGZ .
popd # $DEST_DIR

popd # $BUILD_DIR

rm -rf "$BUILD_DIR"
