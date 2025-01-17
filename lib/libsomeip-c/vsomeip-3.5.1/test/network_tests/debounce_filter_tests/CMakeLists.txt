# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(debounce_filter_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    debounce_filter_test_client.json
    debounce_filter_test_master_starter.sh
    debounce_filter_test_service.json
    debounce_filter_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(debounce_filter_test_client
    debounce_filter_test_client.cpp
)

# Add test executable.
add_executable(debounce_filter_test_service
    debounce_filter_test_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    debounce_filter_test_client
    debounce_filter_test_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Add custom test command.
add_custom_test(
    NAME debounce_filter_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/debounce_filter_test_master_starter.sh
)
