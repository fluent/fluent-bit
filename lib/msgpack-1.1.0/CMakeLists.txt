CMAKE_MINIMUM_REQUIRED (VERSION 2.8.6)
PROJECT (msgpack)

FILE (READ ${CMAKE_CURRENT_SOURCE_DIR}/include/msgpack/version_master.h contents)
STRING (REGEX MATCH "#define MSGPACK_VERSION_MAJOR *([0-9a-zA-Z_]*)" NULL_OUT ${contents})
SET (VERSION_MAJOR ${CMAKE_MATCH_1})
STRING (REGEX MATCH "#define MSGPACK_VERSION_MINOR *([0-9a-zA-Z_]*)" NULL_OUT ${contents})
SET (VERSION_MINOR ${CMAKE_MATCH_1})
STRING (REGEX MATCH "#define MSGPACK_VERSION_REVISION *([0-9a-zA-Z_]*)" NULL_OUT ${contents})
SET (VERSION_REVISION ${CMAKE_MATCH_1})
SET (VERSION ${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_REVISION})

SET (prefix ${CMAKE_INSTALL_PREFIX})
SET (exec_prefix "\${prefix}")
SET (libdir "\${exec_prefix}/lib")
SET (includedir "\${prefix}/include")

OPTION (MSGPACK_CXX11 "Using c++11 compiler" OFF)
OPTION (MSGPACK_32BIT "32bit compile" OFF)

IF (MSGPACK_CXX11)
   IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      SET (CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      SET (CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
      MESSAGE ( FATAL_ERROR "MSVC doesn't support C++11 yet.")
   ENDIF ()
ENDIF ()

IF (MSGPACK_32BIT)
   IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      SET (CMAKE_CXX_FLAGS "-m32 ${CMAKE_CXX_FLAGS}")
      SET (CMAKE_C_FLAGS "-m32 ${CMAKE_C_FLAGS}")
      SET (CMAKE_EXE_LINKER_FLAGS "-m32 ${CMAKE_EXE_LINKER_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      SET (CMAKE_CXX_FLAGS "-m32 ${CMAKE_CXX_FLAGS}")
      SET (CMAKE_C_FLAGS "-m32 ${CMAKE_C_FLAGS}")
      SET (CMAKE_EXE_LINKER_FLAGS "-m32 ${CMAKE_EXE_LINKER_FLAGS}")
   ENDIF ()
ENDIF ()

FIND_PACKAGE (GTest)
FIND_PACKAGE (ZLIB)
FIND_PACKAGE (Threads)
IF (GTEST_FOUND AND ZLIB_FOUND AND THREADS_FOUND)
    OPTION (MSGPACK_BUILD_TESTS "Build msgpack tests." ON)
ENDIF ()

OPTION (MSGPACK_ENABLE_CXX "Enable C++ interface." ON)

INCLUDE (CheckCXXSourceCompiles)
CHECK_CXX_SOURCE_COMPILES ("
#include <bits/atomicity.h>
int atomic_sub(int i) { return __gnu_cxx::__exchange_and_add(&i, -1) - 1; }
int atomic_add(int i) { return __gnu_cxx::__exchange_and_add(&i, 1) + 1; }
int main(int argc, char * argv[])
{
    atomic_sub(1);
    atomic_add(1);
}
" MSGPACK_ENABLE_GCC_CXX_ATOMIC)

IF (MSGPACK_ENABLE_GCC_CXX_ATOMIC)
    LIST (APPEND msgpack_SOURCES
        src/gcc_atomic.cpp
    )
ENDIF ()


LIST (APPEND msgpack_SOURCES
    src/unpack.c
    src/objectc.c
    src/version.c
    src/vrefbuffer.c
    src/zone.c
)

LIST (APPEND msgpack_HEADERS
    include/msgpack/pack_define.h
    include/msgpack/pack_template.h
    include/msgpack/unpack_define.h
    include/msgpack/unpack_template.h
    include/msgpack/util.h
    include/msgpack/sysdep.h
    include/msgpack/gcc_atomic.h
    include/msgpack/sbuffer.h
    include/msgpack/version.h
    include/msgpack/vrefbuffer.h
    include/msgpack/zbuffer.h
    include/msgpack/fbuffer.h
    include/msgpack/pack.h
    include/msgpack/unpack.h
    include/msgpack/object.h
    include/msgpack/zone.h
)

IF (MSGPACK_ENABLE_CXX)
    LIST (APPEND msgpack_HEADERS
        include/msgpack.hpp
        include/msgpack/adaptor/adaptor_base.hpp
        include/msgpack/adaptor/bool.hpp
        include/msgpack/adaptor/char_ptr.hpp
        include/msgpack/adaptor/check_container_size.hpp
        include/msgpack/adaptor/cpp11/array.hpp
        include/msgpack/adaptor/cpp11/array_char.hpp
        include/msgpack/adaptor/cpp11/forward_list.hpp
        include/msgpack/adaptor/cpp11/tuple.hpp
        include/msgpack/adaptor/cpp11/unordered_map.hpp
        include/msgpack/adaptor/cpp11/unordered_set.hpp
        include/msgpack/adaptor/define.hpp
        include/msgpack/adaptor/deque.hpp
        include/msgpack/adaptor/detail/cpp03_define.hpp
        include/msgpack/adaptor/detail/cpp03_msgpack_tuple.hpp
        include/msgpack/adaptor/detail/cpp11_define.hpp
        include/msgpack/adaptor/detail/cpp11_msgpack_tuple.hpp
        include/msgpack/adaptor/fixint.hpp
        include/msgpack/adaptor/float.hpp
        include/msgpack/adaptor/int.hpp
        include/msgpack/adaptor/list.hpp
        include/msgpack/adaptor/map.hpp
        include/msgpack/adaptor/msgpack_tuple.hpp
        include/msgpack/adaptor/nil.hpp
        include/msgpack/adaptor/pair.hpp
        include/msgpack/adaptor/raw.hpp
        include/msgpack/adaptor/set.hpp
        include/msgpack/adaptor/string.hpp
        include/msgpack/adaptor/tr1/unordered_map.hpp
        include/msgpack/adaptor/tr1/unordered_set.hpp
        include/msgpack/adaptor/vector.hpp
        include/msgpack/adaptor/vector_bool.hpp
        include/msgpack/adaptor/vector_char.hpp
        include/msgpack/cpp_config.hpp
        include/msgpack/detail/cpp03_zone.hpp
        include/msgpack/detail/cpp11_zone.hpp
        include/msgpack/fbuffer.hpp
        include/msgpack/object.hpp
        include/msgpack/object_fwd.hpp
        include/msgpack/pack.hpp
        include/msgpack/sbuffer.hpp
        include/msgpack/type.hpp
        include/msgpack/unpack.hpp
        include/msgpack/version.hpp
        include/msgpack/versioning.hpp
        include/msgpack/vrefbuffer.hpp
        include/msgpack/zbuffer.hpp
        include/msgpack/zone.hpp
    )
ENDIF ()

EXECUTE_PROCESS (
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/src/msgpack
)

CONFIGURE_FILE (
    msgpack.pc.in
    msgpack.pc
    @ONLY
)

INCLUDE_DIRECTORIES (
    ./
    include/
    ${CMAKE_CURRENT_BINARY_DIR}/include/
)

ADD_LIBRARY (msgpack SHARED
    ${msgpack_SOURCES}
    ${msgpack_HEADERS}
)

ADD_LIBRARY (msgpack-static STATIC
    ${msgpack_SOURCES}
    ${msgpack_HEADERS}
)

SET_TARGET_PROPERTIES (msgpack-static PROPERTIES OUTPUT_NAME "msgpack")
SET_TARGET_PROPERTIES (msgpack PROPERTIES IMPORT_SUFFIX "_import.lib")
SET_TARGET_PROPERTIES (msgpack PROPERTIES SOVERSION 3 VERSION 4.0.0)

IF (MSGPACK_BUILD_TESTS)
    ENABLE_TESTING ()
    SET(CTEST_MEMORYCHECK_COMMAND "/usr/bin/valgrind")
    INCLUDE(Dart)
    SET(MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --error-exitcode=1")
    ADD_SUBDIRECTORY (test)
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    SET_PROPERTY (TARGET msgpack APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3 -DPIC")
    SET_PROPERTY (TARGET msgpack-static APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -g -O3" )
ENDIF ()
IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        STRING(REGEX REPLACE "/W[0-4]" "/W3" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    ELSE ()
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3")
    ENDIF ()
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC90" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC10")
    SET_SOURCE_FILES_PROPERTIES(${msgpack_SOURCES} PROPERTIES LANGUAGE CXX)
ENDIF()

IF (NOT DEFINED CMAKE_INSTALL_LIBDIR)
    SET(CMAKE_INSTALL_LIBDIR lib)
ENDIF ()

INSTALL (TARGETS msgpack msgpack-static DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL (DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX})
INSTALL (FILES ${CMAKE_CURRENT_BINARY_DIR}/msgpack.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)

# Doxygen
FIND_PACKAGE (Doxygen)
IF (DOXYGEN_FOUND)
    ADD_CUSTOM_TARGET (
        doxygen_c
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "FILE_PATTERNS      = *.h" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "OUTPUT_DIRECTORY   = doc_c" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "INPUT              = ${CMAKE_CURRENT_SOURCE_DIR}/include" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "EXTRACT_ALL        = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "PROJECT_NAME       = \"MessagePack for C\"" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        VERBATIM
    )
    ADD_CUSTOM_TARGET (
        doxygen_cpp
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "FILE_PATTERNS      = *.hpp" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "OUTPUT_DIRECTORY   = doc_cpp" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "INPUT              = ${CMAKE_CURRENT_SOURCE_DIR}/include" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "EXTRACT_ALL        = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "PROJECT_NAME       = \"MessagePack for C++\"" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        VERBATIM
    )
    ADD_CUSTOM_TARGET (
        doxygen
        DEPENDS doxygen_c doxygen_cpp
    )
ENDIF ()
