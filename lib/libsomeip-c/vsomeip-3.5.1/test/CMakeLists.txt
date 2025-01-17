# Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

##############################################################################
# Test section
##############################################################################

##############################################################################
# google benchmark
find_package(benchmark)

##############################################################################
# google test

# remove export symbols from the cxx flags
string(REPLACE "${EXPORTSYMBOLS}" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")

# check for set environment variable
if(${GTEST_ROOT} STREQUAL "n/a")
    message(STATUS "GTEST_ROOT is not defined. For building the tests the variable
             GTEST_ROOT has to be defined. Tests can not be built.")
    # early exit
    return()  # test can not be build -> make commands build_tests and check are not available
else()
    message(STATUS "GTEST_ROOT is set. gtest root path set to ${GTEST_ROOT}")
endif()

# build google test as static library (always) -> therefore deactivate BUILD_SHARED_LIBS in case it is active
set(BUILD_SHARED_LIBS_AUTOMATIC_OFF 0)
if ("${BUILD_SHARED_LIBS}" STREQUAL "ON")
    set(BUILD_SHARED_LIBS OFF)
    set(BUILD_SHARED_LIBS_AUTOMATIC_OFF 1)
endif()
add_subdirectory(${GTEST_ROOT} ${CMAKE_CURRENT_BINARY_DIR}/gtest EXCLUDE_FROM_ALL)
if ("${BUILD_SHARED_LIBS_AUTOMATIC_OFF}" STREQUAL "1")
    set(BUILD_SHARED_LIBS ON)
    set(BUILD_SHARED_LIBS_AUTOMATIC_OFF 0)
endif()

##############################################################################
# build tests

SET(TESTS_BAT "OFF" CACHE BOOL
"Controls whether only BAT tests should be build or not")
SET(TEST_SYMLINK_CONFIG_FILES "OFF" CACHE BOOL
"Controls if the json and scripts needed needed to run the tests are copied or symlinked into the build directroy (ignored on Windows)")
SET(TEST_SYMLINK_CONFIG_FILES_RELATIVE "OFF" CACHE BOOL
    "Controls if the json and scripts needed needed to run the tests are symlinked relatively into the build directroy (ignored on Windows)")

SET(TEST_IP_DEFAULT_VALUE "XXX.XXX.XXX.XXX")
SET(TEST_IP_MASTER "${TEST_IP_DEFAULT_VALUE}" CACHE STRING
    "The IP address of the interface which will act as test master")
    SET(TEST_IP_SLAVE "${TEST_IP_DEFAULT_VALUE}" CACHE STRING
    "The IP address of the interface which will act as test slave")

if((${TEST_IP_MASTER} STREQUAL ${TEST_IP_DEFAULT_VALUE}) OR
   (${TEST_IP_SLAVE}  STREQUAL ${TEST_IP_DEFAULT_VALUE}))
    message(WARNING "TEST_IP_MASTER and/or TEST_IP_SLAVE isn't set. "
                    "Remote tests cannot be run. "
                    "To enable, please specify for example "
                    "-DTEST_IP_MASTER=10.0.3.1 -DTEST_IP_SLAVE=10.0.3.2")
endif()

SET(TEST_IP_SLAVE_SECOND "${TEST_IP_DEFAULT_VALUE}" CACHE STRING
"The second IP address of the interface which will act as test slave")
set(TEST_SECOND_ADDRESS "OFF" CACHE BOOL
    "Controls whether second address tests should run or not")

if(${TEST_IP_SLAVE_SECOND} STREQUAL ${TEST_IP_DEFAULT_VALUE})
    message(WARNING "TEST_IP_SLAVE_SECOND isn't set. "
                    "Test with more than one IP address on same interface is not enabled."
                    "Please specify them via for example "
                    "-TEST_IP_SLAVE_SECOND=10.0.3.126")
else()
    set(TEST_SECOND_ADDRESS "ON")
endif()

set(TEST_E2E_PROFILE_04 "ON")
set(TEST_E2E_PROFILE_07 "ON")

SET(TEST_UID_DEFAULT_VALUE "123456789")
SET(TEST_UID "${TEST_UID_DEFAULT_VALUE}" CACHE STRING
    "The User ID of the user running the test: Needed for security")
SET(TEST_GID_DEFAULT_VALUE "123456789")
SET(TEST_GID "${TEST_GID_DEFAULT_VALUE}" CACHE STRING
"The Group ID of the user running the test: Needed for security")

SET(TEST_SECURITY "ON" CACHE BOOL
"Controls whether security tests should run or not")

if((${TEST_UID} STREQUAL ${TEST_UID_DEFAULT_VALUE}) OR
   (${TEST_GID}  STREQUAL ${TEST_GID_DEFAULT_VALUE}) OR
   DISABLE_SECURITY)
    message(WARNING "TEST_UID and/or TEST_GID isn't set. "
                    "Security Tests are not runnable "
                    "Please specify them for example "
                    "-DTEST_UID=1000 -DTEST_GID=1000")
    SET(TEST_SECURITY "OFF")
endif()

add_custom_target(build_tests)

set(CMAKE_CTEST_COMMAND ctest -V)
add_custom_target(check COMMAND ${CMAKE_CTEST_COMMAND})
add_dependencies(check build_tests)

add_custom_target(build_network_tests)
add_dependencies(build_network_tests ${VSOMEIP_NAME})
add_dependencies(build_network_tests ${VSOMEIP_NAME}-e2e)
add_dependencies(build_network_tests ${VSOMEIP_NAME}-sd)
add_dependencies(build_tests build_network_tests)

add_custom_target(build_unit_tests)
add_dependencies(build_unit_tests ${VSOMEIP_NAME})
add_dependencies(build_unit_tests ${VSOMEIP_NAME}-sd)
add_dependencies(build_tests build_unit_tests)

add_custom_target(build_benchmark_tests)
add_dependencies(build_benchmark_tests ${VSOMEIP_NAME})
add_dependencies(build_benchmark_tests ${VSOMEIP_NAME}-sd)
add_dependencies(build_tests build_benchmark_tests)

##############################################################################
# add network, unit and benchmark tests directories
##############################################################################

add_subdirectory(common EXCLUDE_FROM_ALL)
add_subdirectory(network_tests EXCLUDE_FROM_ALL)

if (NOT DISABLE_SECURITY)
    add_subdirectory(unit_tests EXCLUDE_FROM_ALL)

    if(benchmark_FOUND)
        add_subdirectory(benchmark_tests EXCLUDE_FROM_ALL)
    endif()
endif()

##############################################################################
# Add internal_routing_disabled_acceptance_test
##############################################################################

if(NOT ${TESTS_BAT})
    add_subdirectory(internal_routing_disabled_acceptance_test)
endif()

configure_file(tsan-suppressions.txt tsan-suppressions.txt COPYONLY)
