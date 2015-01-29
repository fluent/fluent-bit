FIND_PACKAGE (GTest REQUIRED)
FIND_PACKAGE (ZLIB REQUIRED)
FIND_PACKAGE (Threads REQUIRED)

INCLUDE_DIRECTORIES (
	${GTEST_INCLUDE_DIRS}
	${ZLIB_INCLUDE_DIRS}
)

SET (check_PROGRAMS
	pack_unpack.cc
	version.cc
	streaming_c.cc
	pack_unpack_c.cc
	zone.cc
	msgpack_test.cpp
	buffer.cc
	msgpackc_test.cpp
	streaming.cc
	convert.cc
	fixint_c.cc
)

IF (MSGPACK_ENABLE_CXX)
	LIST (APPEND check_PROGRAMS
		cases.cc
		fixint.cc
		object.cc
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
			STRING(REGEX REPLACE "/W[0-4]" "/W4" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		ELSE ()
			SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W4")
		ENDIF ()
	ENDIF ()
ENDFOREACH ()
