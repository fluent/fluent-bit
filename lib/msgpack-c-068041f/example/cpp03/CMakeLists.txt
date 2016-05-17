LIST (APPEND exec_PROGRAMS
    class_intrusive.cpp
    class_intrusive_map.cpp
    class_non_intrusive.cpp
    custom.cpp
    enum.cpp
    map_based_versionup.cpp
    protocol_new.cpp
    reuse_zone.cpp
    simple.cpp
)

IF (MSGPACK_DEFAULT_API_VERSION EQUAL 1)
    LIST (APPEND exec_PROGRAMS
        protocol.cpp
    )
ENDIF ()

IF (NOT MSVC)
    LIST (APPEND with_pthread_PROGRAMS
        stream.cpp
    )
ENDIF ()

IF (MSGPACK_BOOST)
    IF (NOT MSVC)
        LIST (APPEND with_boost_lib_PROGRAMS
            speed_test.cpp
            speed_test_nested_array.cpp
        )
    ENDIF ()
ENDIF ()

FOREACH (source_file ${exec_PROGRAMS})
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -g -O3")
    ENDIF ()
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
            STRING(REGEX REPLACE "/W[0-4]" "/W3 /WX" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        ELSE ()
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX")
        ENDIF ()
    ENDIF ()
ENDFOREACH ()

FOREACH (source_file ${with_pthread_PROGRAMS})
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    TARGET_LINK_LIBRARIES (${source_file_we}
        pthread
    )
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -g -O3 -pthread")
    ENDIF ()
    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
        IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
            STRING(REGEX REPLACE "/W[0-4]" "/W3 /WX" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        ELSE ()
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX")
        ENDIF ()
    ENDIF ()
ENDFOREACH ()

FOREACH (source_file ${with_boost_lib_PROGRAMS})
    INCLUDE_DIRECTORIES (
        ../include
        ${Boost_INCLUDE_DIRS}
    )
    GET_FILENAME_COMPONENT (source_file_we ${source_file} NAME_WE)
    ADD_EXECUTABLE (
        ${source_file_we}
        ${source_file}
    )
    LINK_DIRECTORIES(${Boost_LIBRARY_DIRS})
    TARGET_LINK_LIBRARIES (${source_file_we}
        ${Boost_TIMER_LIBRARY}
        ${Boost_CHRONO_LIBRARY}
        ${Boost_SYSTEM_LIBRARY}
    )
    IF (NOT MSVC AND NOT APPLE)
        TARGET_LINK_LIBRARIES (${source_file_we}
            rt
        )
    ENDIF ()

    IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
        SET_PROPERTY (TARGET ${source_file_we} APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -O3")
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
        IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
            STRING(REGEX REPLACE "/W[0-4]" "/W3 /WX" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
        ELSE ()
            SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX")
        ENDIF ()
    ENDIF ()
ENDFOREACH ()
