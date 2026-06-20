#!/bin/sh

# backup old repo
mv msgpack-c msgpack-c.old
mkdir msgpack-c

rm -rf /tmp/flb-msgpack-c
git clone --branch=c_master https://github.com/msgpack/msgpack-c /tmp/flb-msgpack-c

cp -r /tmp/flb-msgpack-c/include msgpack-c/
cp -r /tmp/flb-msgpack-c/src msgpack-c/
cp -r /tmp/flb-msgpack-c/cmake msgpack-c/

# Register CMakeLists.txt
rm msgpack-c/CMakeLists.txt
cat << EOF > msgpack-c/CMakeLists.txt
cmake_minimum_required(VERSION 2.8)
project(msgpack-c)

set(src
    src/objectc.c
    src/unpack.c
    src/version.c
    src/vrefbuffer.c
    src/zone.c
)

INCLUDE(TestBigEndian)
TEST_BIG_ENDIAN(BIGENDIAN)
IF (BIGENDIAN)
    SET(MSGPACK_ENDIAN_BIG_BYTE 1)
    SET(MSGPACK_ENDIAN_LITTLE_BYTE 0)
ELSE ()
    SET(MSGPACK_ENDIAN_BIG_BYTE 0)
	SET(MSGPACK_ENDIAN_LITTLE_BYTE 1)
ENDIF ()

configure_file(
    "cmake/sysdep.h.in"
    "\${PROJECT_SOURCE_DIR}/include/msgpack/sysdep.h"
)

configure_file(
    "cmake/pack_template.h.in"
    "\${PROJECT_SOURCE_DIR}/include/msgpack/pack_template.h"
)

include_directories(include)
add_library(msgpack-c-static STATIC \${src})
EOF
