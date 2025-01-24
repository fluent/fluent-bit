# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(configuration_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    configuration_test_deprecated.json
    configuration_test.json
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(configuration_test
    configuration_test.cpp
)

# Link vsomeip configuration libraries.
target_link_libraries(configuration_test
    ${VSOMEIP_NAME}-cfg
)

# Add build dependencies and link libraries to executable.
targets_link_default_libraries(configuration_test)
targets_add_default_dependencies(configuration_test)

# Add custom test command.
add_custom_test(
    NAME configuration_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/configuration_test
)
