FIND_PACKAGE (GTest REQUIRED)
FIND_PACKAGE (ZLIB REQUIRED)
FIND_PACKAGE (Threads REQUIRED)

INCLUDE_DIRECTORIES (
    ${GTEST_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
)

LIST (APPEND check_PROGRAMS
    zone.cpp
    pack_unpack.cpp
    pack_unpack_c.cpp
    streaming.cpp
    streaming_c.cpp
    object.cpp
    object_with_zone.cpp
    version.cpp
    convert.cpp
    buffer.cpp
    cases.cpp
    fixint.cpp
    fixint_c.cpp
    msgpack_tuple.cpp
    msgpack_basic.cpp
    msgpack_container.cpp
    msgpack_stream.cpp
    msgpack_vref.cpp
    msgpack_c.cpp
    reference.cpp
    limit.cpp
)

IF (MSGPACK_CXX11)
    LIST (APPEND check_PROGRAMS
        msgpack_cpp11.cpp
        reference_cpp11.cpp
        iterator_cpp11.cpp
    )
ENDIF ()

FOREACH (source_file ${check_PROGRAMS})
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES (${source_file_we}
        msgpack
        ${GTEST_BOTH_LIBRARIES}
        ${ZLIB_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    ADD_TEST (${source_file_we} ${source_file_we})
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3")
    ENDIF ()
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
            STRING(REGEX REPLACE "/W[0-4]" "/W3" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        ELSE ()
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
        ENDIF ()
    ENDIF ()
ENDFOREACH ()
