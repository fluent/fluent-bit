# Copyright (C) 2015-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project("unit_tests_message_payload_impl_tests" LANGUAGES CXX)

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

add_test(NAME ${PROJECT_NAME} COMMAND ${PROJECT_NAME})

add_dependencies(build_unit_tests ${PROJECT_NAME})
