CMAKE_MINIMUM_REQUIRED (VERSION 2.8.6)
PROJECT (msgpack)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fPIC")

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
SET (GNUCXX_STD_SUPPORT_VERSION "4.3")
SET (GNUCXX_NO_MISMATCHED_TAGS_SUPPORT_VERSION "4.4")

OPTION (MSGPACK_CXX11 "Using c++11 compiler" OFF)
OPTION (MSGPACK_32BIT "32bit compile" OFF)
OPTION (MSGPACK_BOOST "Using boost libraries" OFF)

IF (APPLE)
    SET(CMAKE_MACOSX_RPATH ON)
    SET(CMAKE_SKIP_BUILD_RPATH FALSE)
    SET(CMAKE_BUILD_WITH_INSTALL_RPATH FALSE)
    SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    SET(CMAKE_INSTALL_RPATH_USE_LINK_PATH TRUE)
    LIST(FIND CMAKE_PLATFORM_IMPLICIT_LINK_DIRECTORIES "${CMAKE_INSTALL_PREFIX}/lib" isSystemDir)
    IF ("${isSystemDir}" STREQUAL "-1")
        SET(CMAKE_INSTALL_RPATH "${CMAKE_INSTALL_PREFIX}/lib")
    ENDIF ()
ENDIF ()

IF (MSGPACK_CXX11)
   IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      SET (CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      SET (CMAKE_CXX_FLAGS "-std=c++11 ${CMAKE_CXX_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
      IF (CMAKE_CXX_COMPILER_VERSION VERSION_LESS 19)
          MESSAGE ( FATAL_ERROR "MSVC doesn't support C++11.")
      ENDIF ()
   ENDIF ()
ELSE ()
   IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
      IF ((CMAKE_CXX_COMPILER_VERSION VERSION_GREATER ${GNUCXX_STD_SUPPORT_VERSION}) OR
          (CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL   ${GNUCXX_STD_SUPPORT_VERSION}))
          SET (CMAKE_CXX_FLAGS "-std=c++03 ${CMAKE_CXX_FLAGS}")
      ENDIF ()
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
      SET (CMAKE_CXX_FLAGS "-std=c++03 ${CMAKE_CXX_FLAGS}")
   ELSEIF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
      IF (CMAKE_CXX_COMPILER_VERSION VERSION_GREATER 18)
          SET (CMAKE_CXX_FLAGS "-DMSGPACK_USE_CPP03 ${CMAKE_CXX_FLAGS}")
      ENDIF ()
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

IF (MSGPACK_BOOST)
   SET (CMAKE_CXX_FLAGS "-DMSGPACK_USE_BOOST ${CMAKE_CXX_FLAGS}")
   SET (Boost_USE_STATIC_LIBS        ON) # only find static libs
   SET (Boost_USE_MULTITHREADED      ON)
   SET (Boost_USE_STATIC_RUNTIME    OFF)
   FIND_PACKAGE (Boost COMPONENTS chrono timer system)
   INCLUDE_DIRECTORIES (
       ${MSGPACK_BOOST_DIR}
   )
ENDIF ()

IF (MSGPACK_CHAR_SIGN)
   SET (CMAKE_C_FLAGS "-f${MSGPACK_CHAR_SIGN}-char ${CMAKE_C_FLAGS}")
   SET (CMAKE_CXX_FLAGS "-f${MSGPACK_CHAR_SIGN}-char ${CMAKE_CXX_FLAGS}")
ENDIF ()

IF (MSGPACK_DEFAULT_API_VERSION)
   SET (CMAKE_CXX_FLAGS "-DMSGPACK_DEFAULT_API_VERSION=${MSGPACK_DEFAULT_API_VERSION} ${CMAKE_CXX_FLAGS}")
ELSE ()
   SET (CMAKE_CXX_FLAGS "-DMSGPACK_DEFAULT_API_VERSION=2 ${CMAKE_CXX_FLAGS}")
ENDIF ()

FILE (GLOB_RECURSE PREDEF_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/predef/include/boost ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/predef/include/boost/*.h)
FOREACH (F ${PREDEF_FILES})
   SET(M "Converting ${F}")
   MESSAGE(STATUS ${M})
   FILE (READ ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/predef/include/boost/${F} CONTENT)
   STRING(REPLACE "BOOST_" "MSGPACK_" CONTENT ${CONTENT})
   STRING(REPLACE "boost/" "msgpack/" CONTENT ${CONTENT})
   FILE (WRITE ${CMAKE_CURRENT_SOURCE_DIR}/include/msgpack/${F} ${CONTENT})
ENDFOREACH ()

FILE (GLOB_RECURSE PREPROCESSOR_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/preprocessor/include/boost ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/preprocessor/include/boost/*.hpp)
FOREACH (F ${PREPROCESSOR_FILES})
   SET(M "Converting ${F}")
   MESSAGE(STATUS ${M})
   FILE (READ ${CMAKE_CURRENT_SOURCE_DIR}/external/boost/preprocessor/include/boost/${F} CONTENT)
   STRING(REPLACE "BOOST_" "MSGPACK_" CONTENT ${CONTENT})
   STRING(REPLACE "boost/" "msgpack/" CONTENT ${CONTENT})
   FILE (WRITE ${CMAKE_CURRENT_SOURCE_DIR}/include/msgpack/${F} ${CONTENT})
ENDFOREACH ()

FIND_PACKAGE (GTest)
FIND_PACKAGE (ZLIB)
FIND_PACKAGE (Threads)
IF (GTEST_FOUND AND ZLIB_FOUND AND THREADS_FOUND)
    OPTION (MSGPACK_BUILD_TESTS "Build msgpack tests." ON)
ENDIF ()
OPTION (MSGPACK_BUILD_EXAMPLES "Build msgpack examples." ON)

OPTION (MSGPACK_ENABLE_CXX "Enable C++ interface." ON)
OPTION (MSGPACK_ENABLE_SHARED "Build shared libaries in addition to static libraries." ON)

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


LIST (APPEND msgpackc_SOURCES
    src/unpack.c
    src/objectc.c
    src/version.c
    src/vrefbuffer.c
    src/zone.c
)

LIST (APPEND msgpackc_HEADERS
    include/msgpack/pack_define.h
    include/msgpack/pack_template.h
    include/msgpack/unpack_define.h
    include/msgpack/unpack_template.h
    include/msgpack/util.h
    include/msgpack/sysdep.h
    include/msgpack/gcc_atomic.h
    include/msgpack.h
    include/msgpack/sbuffer.h
    include/msgpack/version.h
    include/msgpack/version_master.h
    include/msgpack/vrefbuffer.h
    include/msgpack/zbuffer.h
    include/msgpack/fbuffer.h
    include/msgpack/pack.h
    include/msgpack/unpack.h
    include/msgpack/object.h
    include/msgpack/zone.h
)

FILE (GLOB_RECURSE PREDEF_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include/msgpack/predef/*.h)

LIST (APPEND msgpackc_HEADERS ${PREDEF_FILES})
LIST (APPEND msgpackc_HEADERS include/msgpack/predef.h)

IF (MSGPACK_ENABLE_CXX)
    LIST (APPEND msgpack_HEADERS
        include/msgpack.hpp
        include/msgpack/adaptor/adaptor_base.hpp
        include/msgpack/adaptor/adaptor_base_decl.hpp
        include/msgpack/adaptor/array_ref.hpp
        include/msgpack/adaptor/array_ref_decl.hpp
        include/msgpack/adaptor/bool.hpp
        include/msgpack/adaptor/boost/fusion.hpp
        include/msgpack/adaptor/boost/msgpack_variant.hpp
        include/msgpack/adaptor/boost/msgpack_variant_decl.hpp
        include/msgpack/adaptor/boost/optional.hpp
        include/msgpack/adaptor/boost/string_ref.hpp
        include/msgpack/adaptor/char_ptr.hpp
        include/msgpack/adaptor/check_container_size.hpp
        include/msgpack/adaptor/check_container_size_decl.hpp
        include/msgpack/adaptor/cpp11/array.hpp
        include/msgpack/adaptor/cpp11/array_char.hpp
        include/msgpack/adaptor/cpp11/array_unsigned_char.hpp
        include/msgpack/adaptor/cpp11/forward_list.hpp
        include/msgpack/adaptor/cpp11/reference_wrapper.hpp
        include/msgpack/adaptor/cpp11/shared_ptr.hpp
        include/msgpack/adaptor/cpp11/tuple.hpp
        include/msgpack/adaptor/cpp11/unique_ptr.hpp
        include/msgpack/adaptor/cpp11/unordered_map.hpp
        include/msgpack/adaptor/cpp11/unordered_set.hpp
        include/msgpack/adaptor/define.hpp
        include/msgpack/adaptor/define_decl.hpp
        include/msgpack/adaptor/deque.hpp
        include/msgpack/adaptor/ext.hpp
        include/msgpack/adaptor/ext_decl.hpp
        include/msgpack/adaptor/fixint.hpp
        include/msgpack/adaptor/fixint_decl.hpp
        include/msgpack/adaptor/float.hpp
        include/msgpack/adaptor/int.hpp
        include/msgpack/adaptor/int_decl.hpp
        include/msgpack/adaptor/list.hpp
        include/msgpack/adaptor/map.hpp
        include/msgpack/adaptor/map_decl.hpp
        include/msgpack/adaptor/msgpack_tuple.hpp
        include/msgpack/adaptor/msgpack_tuple_decl.hpp
        include/msgpack/adaptor/nil.hpp
        include/msgpack/adaptor/nil_decl.hpp
        include/msgpack/adaptor/pair.hpp
        include/msgpack/adaptor/raw.hpp
        include/msgpack/adaptor/raw_decl.hpp
        include/msgpack/adaptor/set.hpp
        include/msgpack/adaptor/string.hpp
        include/msgpack/adaptor/tr1/unordered_map.hpp
        include/msgpack/adaptor/tr1/unordered_set.hpp
        include/msgpack/adaptor/v4raw.hpp
        include/msgpack/adaptor/v4raw_decl.hpp
        include/msgpack/adaptor/vector.hpp
        include/msgpack/adaptor/vector_bool.hpp
        include/msgpack/adaptor/vector_char.hpp
        include/msgpack/adaptor/vector_unsigned_char.hpp
        include/msgpack/cpp_config.hpp
        include/msgpack/cpp_config_decl.hpp
        include/msgpack/fbuffer.hpp
        include/msgpack/fbuffer_decl.hpp
        include/msgpack/iterator.hpp
        include/msgpack/iterator_decl.hpp
        include/msgpack/meta.hpp
        include/msgpack/meta_decl.hpp
        include/msgpack/object.hpp
        include/msgpack/object_decl.hpp
        include/msgpack/object_fwd.hpp
        include/msgpack/object_fwd_decl.hpp
        include/msgpack/pack.hpp
        include/msgpack/pack_decl.hpp
        include/msgpack/sbuffer.hpp
        include/msgpack/sbuffer_decl.hpp
        include/msgpack/type.hpp
        include/msgpack/unpack.hpp
        include/msgpack/unpack_decl.hpp
        include/msgpack/v1/adaptor/adaptor_base.hpp
        include/msgpack/v1/adaptor/adaptor_base_decl.hpp
        include/msgpack/v1/adaptor/array_ref.hpp
        include/msgpack/v1/adaptor/array_ref_decl.hpp
        include/msgpack/v1/adaptor/bool.hpp
        include/msgpack/v1/adaptor/boost/fusion.hpp
        include/msgpack/v1/adaptor/boost/msgpack_variant.hpp
        include/msgpack/v1/adaptor/boost/msgpack_variant_decl.hpp
        include/msgpack/v1/adaptor/boost/optional.hpp
        include/msgpack/v1/adaptor/boost/string_ref.hpp
        include/msgpack/v1/adaptor/char_ptr.hpp
        include/msgpack/v1/adaptor/check_container_size.hpp
        include/msgpack/v1/adaptor/check_container_size_decl.hpp
        include/msgpack/v1/adaptor/cpp11/array.hpp
        include/msgpack/v1/adaptor/cpp11/array_char.hpp
        include/msgpack/v1/adaptor/cpp11/array_unsigned_char.hpp
        include/msgpack/v1/adaptor/cpp11/forward_list.hpp
        include/msgpack/v1/adaptor/cpp11/reference_wrapper.hpp
        include/msgpack/v1/adaptor/cpp11/shared_ptr.hpp
        include/msgpack/v1/adaptor/cpp11/tuple.hpp
        include/msgpack/v1/adaptor/cpp11/unique_ptr.hpp
        include/msgpack/v1/adaptor/cpp11/unordered_map.hpp
        include/msgpack/v1/adaptor/cpp11/unordered_set.hpp
        include/msgpack/v1/adaptor/define.hpp
        include/msgpack/v1/adaptor/define_decl.hpp
        include/msgpack/v1/adaptor/deque.hpp
        include/msgpack/v1/adaptor/detail/cpp03_define_array.hpp
        include/msgpack/v1/adaptor/detail/cpp03_define_array_decl.hpp
        include/msgpack/v1/adaptor/detail/cpp03_define_map.hpp
        include/msgpack/v1/adaptor/detail/cpp03_define_map_decl.hpp
        include/msgpack/v1/adaptor/detail/cpp03_msgpack_tuple.hpp
        include/msgpack/v1/adaptor/detail/cpp03_msgpack_tuple_decl.hpp
        include/msgpack/v1/adaptor/detail/cpp11_define_array.hpp
        include/msgpack/v1/adaptor/detail/cpp11_define_array_decl.hpp
        include/msgpack/v1/adaptor/detail/cpp11_define_map.hpp
        include/msgpack/v1/adaptor/detail/cpp11_define_map_decl.hpp
        include/msgpack/v1/adaptor/detail/cpp11_msgpack_tuple.hpp
        include/msgpack/v1/adaptor/detail/cpp11_msgpack_tuple_decl.hpp
        include/msgpack/v1/adaptor/ext.hpp
        include/msgpack/v1/adaptor/ext_decl.hpp
        include/msgpack/v1/adaptor/fixint.hpp
        include/msgpack/v1/adaptor/fixint_decl.hpp
        include/msgpack/v1/adaptor/float.hpp
        include/msgpack/v1/adaptor/int.hpp
        include/msgpack/v1/adaptor/int_decl.hpp
        include/msgpack/v1/adaptor/list.hpp
        include/msgpack/v1/adaptor/map.hpp
        include/msgpack/v1/adaptor/map_decl.hpp
        include/msgpack/v1/adaptor/msgpack_tuple.hpp
        include/msgpack/v1/adaptor/msgpack_tuple_decl.hpp
        include/msgpack/v1/adaptor/nil.hpp
        include/msgpack/v1/adaptor/nil_decl.hpp
        include/msgpack/v1/adaptor/pair.hpp
        include/msgpack/v1/adaptor/raw.hpp
        include/msgpack/v1/adaptor/raw_decl.hpp
        include/msgpack/v1/adaptor/set.hpp
        include/msgpack/v1/adaptor/string.hpp
        include/msgpack/v1/adaptor/tr1/unordered_map.hpp
        include/msgpack/v1/adaptor/tr1/unordered_set.hpp
        include/msgpack/v1/adaptor/v4raw.hpp
        include/msgpack/v1/adaptor/v4raw_decl.hpp
        include/msgpack/v1/adaptor/vector.hpp
        include/msgpack/v1/adaptor/vector_bool.hpp
        include/msgpack/v1/adaptor/vector_char.hpp
        include/msgpack/v1/adaptor/vector_unsigned_char.hpp
        include/msgpack/v1/cpp_config.hpp
        include/msgpack/v1/cpp_config_decl.hpp
        include/msgpack/v1/detail/cpp03_zone.hpp
        include/msgpack/v1/detail/cpp03_zone_decl.hpp
        include/msgpack/v1/detail/cpp11_zone.hpp
        include/msgpack/v1/detail/cpp11_zone_decl.hpp
        include/msgpack/v1/fbuffer.hpp
        include/msgpack/v1/fbuffer_decl.hpp
        include/msgpack/v1/iterator.hpp
        include/msgpack/v1/iterator_decl.hpp
        include/msgpack/v1/meta.hpp
        include/msgpack/v1/meta_decl.hpp
        include/msgpack/v1/object.hpp
        include/msgpack/v1/object_decl.hpp
        include/msgpack/v1/object_fwd.hpp
        include/msgpack/v1/object_fwd_decl.hpp
        include/msgpack/v1/pack.hpp
        include/msgpack/v1/pack_decl.hpp
        include/msgpack/v1/preprocessor.hpp
        include/msgpack/v1/sbuffer.hpp
        include/msgpack/v1/sbuffer_decl.hpp
        include/msgpack/v1/type.hpp
        include/msgpack/v1/unpack.hpp
        include/msgpack/v1/unpack_decl.hpp
        include/msgpack/v1/version.hpp
        include/msgpack/v1/versioning.hpp
        include/msgpack/v1/vrefbuffer.hpp
        include/msgpack/v1/vrefbuffer_decl.hpp
        include/msgpack/v1/zbuffer.hpp
        include/msgpack/v1/zbuffer_decl.hpp
        include/msgpack/v1/zone.hpp
        include/msgpack/v1/zone_decl.hpp
        include/msgpack/v2/adaptor/adaptor_base.hpp
        include/msgpack/v2/adaptor/adaptor_base_decl.hpp
        include/msgpack/v2/adaptor/array_ref_decl.hpp
        include/msgpack/v2/adaptor/boost/msgpack_variant_decl.hpp
        include/msgpack/v2/adaptor/check_container_size_decl.hpp
        include/msgpack/v2/adaptor/define_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp03_define_array_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp03_define_map_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp03_msgpack_tuple_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp11_define_array_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp11_define_map_decl.hpp
        include/msgpack/v2/adaptor/detail/cpp11_msgpack_tuple_decl.hpp
        include/msgpack/v2/adaptor/ext_decl.hpp
        include/msgpack/v2/adaptor/fixint_decl.hpp
        include/msgpack/v2/adaptor/int_decl.hpp
        include/msgpack/v2/adaptor/map_decl.hpp
        include/msgpack/v2/adaptor/msgpack_tuple_decl.hpp
        include/msgpack/v2/adaptor/nil_decl.hpp
        include/msgpack/v2/adaptor/raw_decl.hpp
        include/msgpack/v2/adaptor/v4raw_decl.hpp
        include/msgpack/v2/cpp_config_decl.hpp
        include/msgpack/v2/detail/cpp03_zone_decl.hpp
        include/msgpack/v2/detail/cpp11_zone_decl.hpp
        include/msgpack/v2/fbuffer_decl.hpp
        include/msgpack/v2/iterator_decl.hpp
        include/msgpack/v2/meta_decl.hpp
        include/msgpack/v2/object.hpp
        include/msgpack/v2/object_decl.hpp
        include/msgpack/v2/object_fwd.hpp
        include/msgpack/v2/object_fwd_decl.hpp
        include/msgpack/v2/pack_decl.hpp
        include/msgpack/v2/sbuffer_decl.hpp
        include/msgpack/v2/unpack.hpp
        include/msgpack/v2/unpack_decl.hpp
        include/msgpack/v2/vrefbuffer_decl.hpp
        include/msgpack/v2/zbuffer_decl.hpp
        include/msgpack/v2/zone_decl.hpp
        include/msgpack/version.hpp
        include/msgpack/versioning.hpp
        include/msgpack/vrefbuffer.hpp
        include/msgpack/vrefbuffer_decl.hpp
        include/msgpack/zbuffer.hpp
        include/msgpack/zbuffer_decl.hpp
        include/msgpack/zone.hpp
        include/msgpack/zone_decl.hpp
    )
    FILE (GLOB_RECURSE PREPROCESSOR_FILES RELATIVE ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/include/msgpack/preprocessor/*.hpp)

    LIST (APPEND msgpackc_HEADERS ${PREPROCESSOR_FILES})
    LIST (APPEND msgpackc_HEADERS include/msgpack/preprocessor.hpp)
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

IF (MSGPACK_ENABLE_SHARED)
    ADD_LIBRARY (msgpackc SHARED
        ${msgpackc_SOURCES}
        ${msgpackc_HEADERS}
    )
ENDIF ()

ADD_LIBRARY (msgpackc-static STATIC
    ${msgpackc_SOURCES}
    ${msgpackc_HEADERS}
)

SET_TARGET_PROPERTIES (msgpackc-static PROPERTIES OUTPUT_NAME "msgpackc")
IF (MSGPACK_ENABLE_SHARED)
    SET_TARGET_PROPERTIES (msgpackc PROPERTIES IMPORT_SUFFIX "_import.lib")
    SET_TARGET_PROPERTIES (msgpackc PROPERTIES SOVERSION 2 VERSION 2.0.0)
ENDIF ()

IF (MSGPACK_BUILD_TESTS)
    ENABLE_TESTING ()
    # MEMORYCHECK_COMMAND_OPTIONS needs to place prior to CTEST_MEMORYCHECK_COMMAND
    SET (MEMORYCHECK_COMMAND_OPTIONS "--leak-check=full --show-leak-kinds=definite,possible --error-exitcode=1")
    FIND_PROGRAM(CTEST_MEMORYCHECK_COMMAND NAMES valgrind)
    INCLUDE(Dart)
    ADD_SUBDIRECTORY (test)
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    IF (MSGPACK_ENABLE_SHARED)
        SET_PROPERTY (TARGET msgpackc APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -g -O3 -DPIC")
    ENDIF ()
    SET_PROPERTY (TARGET msgpackc-static APPEND_STRING PROPERTY COMPILE_FLAGS "-Wall -Wextra -Werror -g -O3" )
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "Clang")
    IF (MSGPACK_ENABLE_SHARED)
        SET_PROPERTY (TARGET msgpackc APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
    ENDIF ()
    SET_PROPERTY (TARGET msgpackc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "GNU")
    IF ((CMAKE_CXX_COMPILER_VERSION VERSION_GREATER ${GNUCXX_NO_MISMATCHED_TAGS_SUPPORT_VERSION}) OR
        (CMAKE_CXX_COMPILER_VERSION VERSION_EQUAL   ${GNUCXX_NO_MISMATCHED_TAGS_SUPPORT_VERSION}))
        IF (MSGPACK_ENABLE_SHARED)
            SET_PROPERTY (TARGET msgpackc APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
        ENDIF ()
        SET_PROPERTY (TARGET msgpackc-static APPEND_STRING PROPERTY COMPILE_FLAGS " -Wno-mismatched-tags")
    ENDIF ()
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC")
    IF (CMAKE_CXX_FLAGS MATCHES "/W[0-4]")
        STRING(REGEX REPLACE "/W[0-4]" "/W3 /WX" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
    ELSE ()
        SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /W3 /WX")
    ENDIF ()
ENDIF ()

IF ("${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC90" OR "${CMAKE_CXX_COMPILER_ID}" STREQUAL "MSVC10")
    SET_SOURCE_FILES_PROPERTIES(${msgpackc_SOURCES} PROPERTIES LANGUAGE CXX)
ENDIF()

IF (NOT DEFINED CMAKE_INSTALL_LIBDIR)
    SET(CMAKE_INSTALL_LIBDIR lib)
ENDIF ()

IF (MSGPACK_BUILD_EXAMPLES)
    ADD_SUBDIRECTORY (example)
ENDIF ()

IF (MSGPACK_ENABLE_SHARED)
    SET (MSGPACK_INSTALLTARGETS msgpackc msgpackc-static)
ELSE()
    SET (MSGPACK_INSTALLTARGETS msgpackc-static)
ENDIF ()

INSTALL (TARGETS ${MSGPACK_INSTALLTARGETS} DESTINATION ${CMAKE_INSTALL_LIBDIR})
INSTALL (DIRECTORY include DESTINATION ${CMAKE_INSTALL_PREFIX})
IF (NOT MSVC)
    INSTALL (FILES ${CMAKE_CURRENT_BINARY_DIR}/msgpack.pc DESTINATION ${CMAKE_INSTALL_LIBDIR}/pkgconfig)
ENDIF ()

# Doxygen
FIND_PACKAGE (Doxygen)
IF (DOXYGEN_FOUND)
    LIST (APPEND Doxyfile_c_CONTENT
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "FILE_PATTERNS      = *.h" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "OUTPUT_DIRECTORY   = doc_c" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "INPUT              = ${CMAKE_CURRENT_SOURCE_DIR}/include" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "EXTRACT_ALL        = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        COMMAND ${CMAKE_COMMAND} -E echo "PROJECT_NAME       = \"MessagePack for C\"" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
    )
    IF (DOXYGEN_DOT_FOUND)
        LIST (APPEND Doxyfile_c_CONTENT
            COMMAND ${CMAKE_COMMAND} -E echo "HAVE_DOT       = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        )
    ENDIF ()
    ADD_CUSTOM_TARGET (
        doxygen_c
        ${Doxyfile_c_CONTENT}
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_c
        VERBATIM
    )
    LIST (APPEND Doxyfile_cpp_CONTENT
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "FILE_PATTERNS      = *.hpp" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "OUTPUT_DIRECTORY   = doc_cpp" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "INPUT              = ${CMAKE_CURRENT_SOURCE_DIR}/include" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${CMAKE_COMMAND} -E echo "EXTRACT_ALL        = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
    )
    IF (DOXYGEN_DOT_FOUND)
        LIST (APPEND Doxyfile_cpp_CONTENT
            COMMAND ${CMAKE_COMMAND} -E echo "HAVE_DOT       = YES" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        )
    ENDIF ()
    ADD_CUSTOM_TARGET (
        doxygen_cpp
        ${Doxyfile_cpp_CONTENT}
        COMMAND ${CMAKE_COMMAND} -E echo "PROJECT_NAME       = \"MessagePack for C++\"" >> ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile_cpp
        VERBATIM
    )
    ADD_CUSTOM_TARGET (
        doxygen
        DEPENDS doxygen_c doxygen_cpp
    )
ENDIF ()
