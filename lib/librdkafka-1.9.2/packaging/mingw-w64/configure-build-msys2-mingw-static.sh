#!/bin/bash

set -e

cmake \
    -G "MinGW Makefiles" \
    -D CMAKE_INSTALL_PREFIX="$PWD/dest/" \
    -D RDKAFKA_BUILD_STATIC=ON \
    .

$mingw64 mingw32-make
$mingw64 mingw32-make install

# Bundle all the static dependencies with the static lib we just built
mkdir mergescratch
pushd mergescratch
cp /C/tools/msys64/mingw64/lib/libzstd.a ./
cp /C/tools/msys64/mingw64/lib/libcrypto.a ./
cp /C/tools/msys64/mingw64/lib/liblz4.a ./
cp /C/tools/msys64/mingw64/lib/libssl.a ./
cp /C/tools/msys64/mingw64/lib/libz.a ./
cp ../src/librdkafka.a ./

# Have to rename because ar won't work with + in the name
cp ../src-cpp/librdkafka++.a ./librdkafkacpp.a
ar -M << EOF
create librdkafka-static.a
addlib librdkafka.a
addlib libzstd.a
addlib libcrypto.a
addlib liblz4.a
addlib libssl.a
addlib libz.a
save
end
EOF

ar -M << EOF
create librdkafkacpp-static.a
addlib librdkafka-static.a
addlib librdkafkacpp.a
save
end
EOF

strip -g ./librdkafka-static.a
strip -g ./librdkafkacpp-static.a
cp ./librdkafka-static.a ../dest/lib/
cp ./librdkafkacpp-static.a ../dest/lib/librdkafka++-static.a
popd
rm -rf ./mergescratch

