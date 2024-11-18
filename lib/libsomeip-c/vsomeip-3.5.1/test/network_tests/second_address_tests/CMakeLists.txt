# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(second_address_tests LANGUAGES CXX)

# Configure necessary files into build folder.
set(configuration_files
    second_address_test_master_client.json
    second_address_test_master_service_udp.json
    second_address_test_master_starter.sh
    second_address_test_slave_client.json
    second_address_test_slave_service_udp.json
    second_address_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(second_address_test_service
    second_address_test_service.cpp
)

# Add test executable.
add_executable(second_address_test_client
    second_address_test_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    second_address_test_service
    second_address_test_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME second_address_test_second_ip_address_service_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/second_address_test_master_starter.sh SERVICE UDP
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME second_address_test_second_ip_address_client_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/second_address_test_master_starter.sh CLIENT UDP
    TIMEOUT 180
)
