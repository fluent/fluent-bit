# Copyright (C) The c-ares project and its contributors
# SPDX-License-Identifier: MIT

# Get rid of: warning C4530: C++ exception handler used, but unwind semantics are not enabled. Specify /EHsc
IF (MSVC)
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /EHsc")
ENDIF ()

find_package(Threads)
find_package(GTest REQUIRED)

IF (CMAKE_VERSION VERSION_LESS "3.23.0")
  Message("GoogleTest found, cmake version too old to verify GMock, look for errors...")
ELSE ()
  IF (NOT TARGET GTest::gmock)
    Message(FATAL_ERROR "GoogleTest found but the GMock component was not found")
  ENDIF()
ENDIF()

# create target to access and use internal cares library
add_library(caresinternal INTERFACE)
target_compile_definitions(caresinternal INTERFACE HAVE_CONFIG_H=1)

target_include_directories(caresinternal
   INTERFACE "${PROJECT_BINARY_DIR}"
             "${PROJECT_BINARY_DIR}/src/lib"
             "${PROJECT_SOURCE_DIR}"
             "${PROJECT_SOURCE_DIR}/src/lib"
             "${PROJECT_SOURCE_DIR}/include"
)

IF (CARES_STATIC)
  target_link_libraries(caresinternal INTERFACE ${PROJECT_NAME}::cares_static)
ELSE ()
  target_link_libraries(caresinternal INTERFACE ${PROJECT_NAME}::cares)
ENDIF ()

transform_makefile_inc("Makefile.inc" "${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake")
include(${CMAKE_CURRENT_BINARY_DIR}/Makefile.inc.cmake)

add_executable(arestest ${TESTSOURCES} ${TESTHEADERS})
target_include_directories(arestest PRIVATE ${CMAKE_CURRENT_BINARY_DIR})
IF (CMAKE_VERSION VERSION_LESS "3.23.0")
  FIND_LIBRARY(LIBGMOCK NAMES gmock PATHS ${GTEST_ROOT} PATH_SUFFIXES lib)
  IF (LIBGMOCK-NOTFOUND)
    MESSAGE(FATAL_ERROR "Could not find Gmock")
  ENDIF ()
  target_link_libraries(arestest PRIVATE caresinternal GTest::GTest ${LIBGMOCK})
ELSE ()
  target_link_libraries(arestest PRIVATE caresinternal GTest::gmock)
ENDIF()
target_compile_definitions(arestest PRIVATE CARES_NO_DEPRECATED)

IF (CARES_BUILD_CONTAINER_TESTS)
  target_compile_definitions(arestest PRIVATE HAVE_USER_NAMESPACE HAVE_UTS_NAMESPACE)
ENDIF ()

add_executable(aresfuzz ${FUZZSOURCES})
target_compile_definitions(aresfuzz PRIVATE CARES_NO_DEPRECATED)
target_link_libraries(aresfuzz PRIVATE caresinternal)

add_executable(aresfuzzname ${FUZZNAMESOURCES})
target_compile_definitions(aresfuzzname PRIVATE CARES_NO_DEPRECATED)
target_link_libraries(aresfuzzname PRIVATE caresinternal)

add_executable(dnsdump ${DUMPSOURCES})
target_compile_definitions(dnsdump PRIVATE CARES_NO_DEPRECATED)
target_link_libraries(dnsdump PRIVATE caresinternal)

add_executable(ares_queryloop ${LOOPSOURCES})
target_compile_definitions(ares_queryloop PRIVATE CARES_NO_DEPRECATED)
target_link_libraries(ares_queryloop PRIVATE caresinternal)

# register tests

add_test(NAME arestest COMMAND $<TARGET_FILE:arestest>)

file(GLOB_RECURSE FUZZINPUT_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput" "fuzzinput/*")
add_test(
  NAME aresfuzz
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzzinput"
  COMMAND $<TARGET_FILE:aresfuzz> ${FUZZINPUT_FILES}
)

file(GLOB_RECURSE FUZZNAMES_FILES RELATIVE "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames" "fuzznames/*")
add_test(
  NAME aresfuzzname
  WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/fuzznames"
  COMMAND $<TARGET_FILE:aresfuzzname> ${FUZZNAMES_FILES}
)
