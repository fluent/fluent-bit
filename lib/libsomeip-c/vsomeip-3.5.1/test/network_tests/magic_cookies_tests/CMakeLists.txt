# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(magic_cookies_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    magic_cookies_test_client.json
    magic_cookies_test_client_start.sh
    magic_cookies_test_service.json
    magic_cookies_test_service_start.sh
    magic_cookies_test_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(magic_cookies_test_client
    magic_cookies_test_client.cpp
)

# Add test executable.
add_executable(magic_cookies_test_service
    magic_cookies_test_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    magic_cookies_test_client
    magic_cookies_test_service
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Link thread libraries to executables.
foreach(target ${executables})
    target_link_libraries(${target} ${CMAKE_THREAD_LIBS_INIT})
endforeach()

# Add custom test command.
add_custom_test(
    NAME magic_cookies_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/magic_cookies_test_starter.sh
    TIMEOUT 250
)
