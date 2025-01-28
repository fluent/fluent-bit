# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(payload_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    external_local_payload_test_client_external.json
    external_local_payload_test_client_external_start.sh
    external_local_payload_test_client_external_starter.sh
    external_local_payload_test_client_local.json
    external_local_payload_test_client_local_and_external_starter.sh
    external_local_payload_test_client_local_start.sh
    external_local_payload_test_client_local_starter.sh
    external_local_payload_test_service.json
    external_local_payload_test_service_client_external_start.sh
    external_local_payload_test_service_start.sh
    local_payload_test_client.json
    local_payload_test_client_start.sh
    local_payload_test_huge_payload_starter.sh
    local_payload_test_service.json
    local_payload_test_service_start.sh
    local_payload_test_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(payload_test_service
    payload_test_service.cpp
)

# Add test executable.
add_executable(payload_test_client
    payload_test_client.cpp
    stopwatch.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    payload_test_service
    payload_test_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME local_payload_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/local_payload_test_starter.sh
)

# Add custom test command.
add_custom_test(
    NAME local_payload_test_huge_payload
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/local_payload_test_huge_payload_starter.sh
    TIMEOUT 1800
)

# Add custom test command.
add_custom_test(
    NAME external_local_payload_test_client_local
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/external_local_payload_test_client_local_starter.sh
)

# Add custom test command.
add_custom_test(
    NAME external_local_payload_test_client_external
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/external_local_payload_test_client_external_starter.sh
    TIMEOUT 480
)

# Add custom test command.
add_custom_test(
    NAME external_local_payload_test_client_local_and_external
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/external_local_payload_test_client_local_and_external_starter.sh
    TIMEOUT 480
)
