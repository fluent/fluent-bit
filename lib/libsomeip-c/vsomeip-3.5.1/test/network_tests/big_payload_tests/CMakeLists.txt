# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(big_payload_tests LANGUAGES CXX)

# Configure the necessary files into the build folder.
set(configuration_files
    big_payload_test_client_local_start.sh
    big_payload_test_external_client_start.sh
    big_payload_test_external_service_start.sh
    big_payload_test_external_starter.sh
    big_payload_test_local.json
    big_payload_test_local_limited.json
    big_payload_test_local_queue_limited.json
    big_payload_test_local_random.json
    big_payload_test_local_starter.sh
    big_payload_test_local_tcp_client.json
    big_payload_test_local_tcp_client_limited.json
    big_payload_test_local_tcp_client_queue_limited.json
    big_payload_test_local_tcp_client_random.json
    big_payload_test_local_tcp_client_start.sh
    big_payload_test_local_tcp_service.json
    big_payload_test_local_tcp_service_limited.json
    big_payload_test_local_tcp_service_queue_limited.json
    big_payload_test_local_tcp_service_random.json
    big_payload_test_local_tcp_service_start.sh
    big_payload_test_local_tcp_starter.sh
    big_payload_test_service_local_start.sh
    big_payload_test_tcp_client.json
    big_payload_test_tcp_client_limited_general.json
    big_payload_test_tcp_client_queue_limited_general.json
    big_payload_test_tcp_client_queue_limited_specific.json
    big_payload_test_tcp_client_random.json
    big_payload_test_tcp_service.json
    big_payload_test_tcp_service_limited_general.json
    big_payload_test_tcp_service_queue_limited_general.json
    big_payload_test_tcp_service_queue_limited_specific.json
    big_payload_test_tcp_service_random.json
    big_payload_test_udp_client.json
    big_payload_test_udp_service.json
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(big_payload_test_service
    big_payload_test_service.cpp
)

# Add test executable.
add_executable(big_payload_test_client
    big_payload_test_client.cpp
)

# Add build dependencies and link libraries to executables.
set(test_executables
    big_payload_test_service
    big_payload_test_client
)
targets_link_default_libraries("${test_executables}")
targets_add_default_dependencies("${test_executables}")

# Add custom test commands.

add_custom_test(
    NAME big_payload_test_local
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_starter.sh
)

add_custom_test(
    NAME big_payload_test_local_random
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_starter.sh RANDOM
)

add_custom_test(
    NAME big_payload_test_local_limited
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_starter.sh LIMITED
)

add_custom_test(
    NAME big_payload_test_local_queue_limited
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_starter.sh QUEUELIMITEDGENERAL
)

add_custom_test(
    NAME big_payload_test_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_tcp_starter.sh
)

add_custom_test(
    NAME big_payload_test_local_tcp_random
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_tcp_starter.sh RANDOM
)

add_custom_test(
    NAME big_payload_test_local_tcp_limited
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_tcp_starter.sh LIMITED
)

add_custom_test(
    NAME big_payload_test_local_tcp_queue_limited
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_local_tcp_starter.sh QUEUELIMITEDGENERAL
)

add_custom_test(
    NAME big_payload_test_external
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh
)

add_custom_test(
    NAME big_payload_test_external_random
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh RANDOM
)

add_custom_test(
    NAME big_payload_test_external_limited
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh LIMITED
)

add_custom_test(
    NAME big_payload_test_external_limited_general
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh LIMITEDGENERAL
)

add_custom_test(
    NAME big_payload_test_external_queue_limited_general
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh QUEUELIMITEDGENERAL
)

add_custom_test(
    NAME big_payload_test_external_queue_limited_specific
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh QUEUELIMITEDSPECIFIC
)

add_custom_test(
    NAME big_payload_test_external_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/big_payload_test_external_starter.sh UDP
)
