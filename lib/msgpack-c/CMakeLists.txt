cmake_minimum_required(VERSION 3.20)
project(msgpack-c C)

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
    "${PROJECT_SOURCE_DIR}/include/msgpack/sysdep.h"
)

configure_file(
    "cmake/pack_template.h.in"
    "${PROJECT_SOURCE_DIR}/include/msgpack/pack_template.h"
)

include_directories(include)
add_library(msgpack-c-static STATIC ${src})
