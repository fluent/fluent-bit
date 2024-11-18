# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(client_id_tests LANGUAGES CXX)

# Configure the necessary files into the build folder.
set(configuration_files
    client_id_test_diff_client_ids_diff_ports_master.json
    client_id_test_diff_client_ids_diff_ports_slave.json
    client_id_test_diff_client_ids_partial_same_ports_master.json
    client_id_test_diff_client_ids_partial_same_ports_slave.json
    client_id_test_diff_client_ids_same_ports_master.json
    client_id_test_diff_client_ids_same_ports_slave.json
    client_id_test_master_starter.sh
    client_id_test_same_client_ids_diff_ports_master.json
    client_id_test_same_client_ids_diff_ports_slave.json
    client_id_test_same_client_ids_same_ports_master.json
    client_id_test_same_client_ids_same_ports_slave.json
    client_id_test_slave_starter.sh
    client_id_test_utility.json
    client_id_test_utility_discontinuous_masked_511.json
    client_id_test_utility_masked_127.json
    client_id_test_utility_masked_511.json
    client_id_test_utility_masked_4095.json
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(client_id_test_service
    client_id_test_service.cpp
)

# Add test executable.
add_executable(client_id_test_utility
    client_id_test_utility.cpp
)

# Link vsomeip configuration libraries.
target_link_libraries(client_id_test_utility
    ${VSOMEIP_NAME}-cfg
)

# Add build dependencies and link libraries to executables.
set(test_executables
    client_id_test_service
    client_id_test_utility
)
targets_link_default_libraries("${test_executables}")
targets_add_default_dependencies("${test_executables}")

# Add custom test commands.

add_custom_test(
    NAME client_id_test_diff_client_ids_diff_ports
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_master_starter.sh client_id_test_diff_client_ids_diff_ports_master.json
)

add_custom_test(
    NAME client_id_test_diff_client_ids_same_ports
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_master_starter.sh client_id_test_diff_client_ids_same_ports_master.json
)

add_custom_test(
    NAME client_id_test_diff_client_ids_partial_same_ports
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_master_starter.sh client_id_test_diff_client_ids_partial_same_ports_master.json
)

add_custom_test(
    NAME client_id_test_utility
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility
    ENVIRONMENT "VSOMEIP_CONFIGURATION=${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility.json"
)

add_custom_test(
    NAME client_id_test_utility_masked_511
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility
    ENVIRONMENT "VSOMEIP_CONFIGURATION=${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility_masked_511.json"
)

add_custom_test(
    NAME client_id_test_utility_masked_4095
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility
    ENVIRONMENT "VSOMEIP_CONFIGURATION=${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility_masked_4095.json"
    TIMEOUT 600
)

add_custom_test(
    NAME client_id_test_utility_masked_127
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility
    ENVIRONMENT "VSOMEIP_CONFIGURATION=${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility_masked_127.json"
)

add_custom_test(
    NAME client_id_test_utility_discontinuous_masked_511
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility
    ENVIRONMENT "VSOMEIP_CONFIGURATION=${CMAKE_CURRENT_BINARY_DIR}/client_id_test_utility_discontinuous_masked_511.json"
)
