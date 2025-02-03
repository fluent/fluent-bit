# Copyright (C) 2015-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project("unit_tests_policy_manager_impl_tests" LANGUAGES CXX)

file(GLOB SRCS ../main.cpp *.cpp)

set(THREADS_PREFER_PTHREAD_FLAG ON)

# ----------------------------------------------------------------------------
# Executable and libraries to link
# ----------------------------------------------------------------------------
add_executable(${PROJECT_NAME} ${SRCS})
target_link_libraries(
    ${PROJECT_NAME}
    vsomeip3
    vsomeip3-cfg
    ${Boost_LIBRARIES}
    ${DL_LIBRARY}
    gtest
    vsomeip_utilities
)

# configure macro.hpp for correct path
set(UNIT_TEST_BIN_DIR ${CMAKE_SOURCE_DIR}/build/test/unit_tests)

configure_file(
   "${CMAKE_SOURCE_DIR}/test/unit_tests/security_policy_manager_impl_tests/policy_manager_impl_unit_test_macro.hpp.in"
   "${CMAKE_SOURCE_DIR}/test/unit_tests/security_policy_manager_impl_tests/policy_manager_impl_unit_test_macro.hpp"
)

file(MAKE_DIRECTORY ${UNIT_TEST_BIN_DIR}/security_policy_manager_impl_tests/0_0)

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

add_dependencies(build_unit_tests ${PROJECT_NAME})
