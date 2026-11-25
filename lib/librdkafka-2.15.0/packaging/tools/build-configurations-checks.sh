#!/bin/sh
set -e
build_tool="$1"
docker_image_tag="$2"

if [ -n "$docker_image_tag" ]; then
    echo "Running in docker image tag: $docker_image_tag"
    # Running on the host, spin up the docker builder.
    ./packaging/tools/run-in-docker.sh $docker_image_tag ./packaging/tools/build-configurations-checks.sh $build_tool
    # Only reached on exec error
    exit $?
fi

if [ -z "$build_tool" ]; then
    # Default to using make if no build tool is specified.
    build_tool="make"
fi

# Clone the repo so other builds are unaffected of what we're doing
# and we get a pristine build tree.
git clone /librdkafka /home/user/librdkafka

cd /home/user/librdkafka

# Disable all flags to make sure it
# compiles correctly in all cases
if [ "$build_tool" = "make" ]; then
./configure --disable-ssl --disable-gssapi \
--disable-curl --disable-zlib \
--disable-zstd --disable-lz4-ext --disable-regex-ext \
--disable-c11threads --disable-syslog \
--enable-werror --enable-devel
cat ./config.h
else
cmake -DWITH_SSL=OFF -DWITH_SASL_CYRUS=OFF \
 -DWITH_CURL=OFF -DWITH_ZLIB=OFF \
 -DWITH_ZSTD=OFF -DHAVE_REGEX=OFF -DWITH_C11THREADS=OFF \
 -DWITH_LIBDL=OFF
cat ./generated/config.h
fi
make -j

export CI=true
if [ "0$build_tool" = "0make" ]; then
make -j -C tests run_local_quick
else
ctest -VV -R RdKafkaTestBrokerLessQuick --output-on-failure
fi
