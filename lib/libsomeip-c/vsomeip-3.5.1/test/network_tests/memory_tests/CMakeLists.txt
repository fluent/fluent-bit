# Copyright (C) 2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(memory_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    memory_test_client.json
    memory_test_master_starter.sh
    memory_test_service.json
    memory_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(memory_test_client
    memory_test_client.cpp
)

# Add test executable.
add_executable(memory_test_service
    memory_test_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    memory_test_service
    memory_test_client
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Add custom test command.
add_custom_test(
    NAME memory_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/memory_test_master_starter.sh
    TIMEOUT 600
)
