# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

project("unit_tests_protocol_tests" LANGUAGES CXX)

file(GLOB TEST_SRCS main.cpp *.cpp)

# We need to set the source files directly because vsomeip doesn't export the
# commands for linking.
set(
    VSIP_SRCS
    ../../../implementation/protocol/src/config_command.cpp
    ../../../implementation/protocol/src/command.cpp
)

add_executable(
    ${PROJECT_NAME}
    ${TEST_SRCS}
    ${VSIP_SRCS}
)

target_link_libraries(
    ${PROJECT_NAME}
    gtest
)

add_dependencies(build_unit_tests ${PROJECT_NAME})

add_test(
    NAME ${PROJECT_NAME}
    COMMAND ${PROJECT_NAME}
)
