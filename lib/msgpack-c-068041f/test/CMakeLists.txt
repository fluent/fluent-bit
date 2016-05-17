FIND_PACKAGE (GTest REQUIRED)
FIND_PACKAGE (ZLIB REQUIRED)
FIND_PACKAGE (Threads REQUIRED)

INCLUDE_DIRECTORIES (
    ${GTEST_INCLUDE_DIRS}
    ${ZLIB_INCLUDE_DIRS}
)

LIST (APPEND check_PROGRAMS
    array_ref.cpp
    buffer.cpp
    cases.cpp
    convert.cpp
    fixint.cpp
    fixint_c.cpp
    json.cpp
    limit.cpp
    msgpack_basic.cpp
    msgpack_c.cpp
    msgpack_container.cpp
    msgpack_stream.cpp
    msgpack_tuple.cpp
    msgpack_vref.cpp
    object.cpp
    object_with_zone.cpp
    pack_unpack.cpp
    pack_unpack_c.cpp
    raw.cpp
    reference.cpp
    streaming.cpp
    streaming_c.cpp
    user_class.cpp
    version.cpp
    zone.cpp
)

IF (MSGPACK_BOOST)
    LIST (APPEND check_PROGRAMS
        boost_fusion.cpp
        boost_variant.cpp
        boost_optional.cpp
        boost_string_ref.cpp
    )
ENDIF ()

IF (MSGPACK_CXX11)
    LIST (APPEND check_PROGRAMS
        iterator_cpp11.cpp
        msgpack_cpp11.cpp
        reference_cpp11.cpp
        reference_wrapper_cpp11.cpp
        shared_ptr_cpp11.cpp
        unique_ptr_cpp11.cpp
    )
ENDIF ()

IF (MSGPACK_ENABLE_SHARED)
    SET (MSGPACK_TEST_LIB msgpackc)
ELSE ()
    SET (MSGPACK_TEST_LIB msgpackc-static)
ENDIF ()

FOREACH (source_file ${check_PROGRAMS})
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES (${source_file_we}
        ${MSGPACK_TEST_LIB}
        ${GTEST_BOTH_LIBRARIES}
        ${ZLIB_LIBRARIES}
        ${CMAKE_THREAD_LIBS_INIT}
    )
    ADD_TEST (${source_file_we} ${source_file_we})
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -g -O3 ")
    ENDIF ()
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
    ENDIF ()

    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        IF ((CMAKE_CXX_COMPILER_VERSION VERSION_GREATER ${GNUCXX_NO_MISMATCHED_TAGS_SUPPORT_VERSION}) OR
            (CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL   ${GNUCXX_NO_MISMATCHED_TAGS_SUPPORT_VERSION}))
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
        ENDIF ()
    ENDIF ()

    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4] /WX")
            STRING(REGEX REPLACE "/W[0-4]" "/W3 /WX" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        ELSE ()
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
        ENDIF ()
    ENDIF ()
ENDFOREACH ()

ADD_EXECUTABLE (
    multi_file
    multi_file1.cpp multi_file2.cpp
)
ADD_TEST (multi_file multi_file)
