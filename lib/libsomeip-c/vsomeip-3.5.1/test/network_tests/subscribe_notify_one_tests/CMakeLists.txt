# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(subscribe_notify_one_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    subscribe_notify_one_test_diff_client_ids_diff_ports_master.json
    subscribe_notify_one_test_diff_client_ids_diff_ports_master_tcp.json
    subscribe_notify_one_test_diff_client_ids_diff_ports_master_udp.json
    subscribe_notify_one_test_diff_client_ids_diff_ports_slave.json
    subscribe_notify_one_test_diff_client_ids_diff_ports_slave_tcp.json
    subscribe_notify_one_test_diff_client_ids_diff_ports_slave_udp.json
    subscribe_notify_one_test_master_starter.sh
    subscribe_notify_one_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(subscribe_notify_one_test_service
    subscribe_notify_one_test_service.cpp
)

# Add build dependencies and link libraries to executables.
targets_add_default_dependencies(subscribe_notify_one_test_service)
targets_link_default_libraries(subscribe_notify_one_test_service)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_one_test_diff_client_ids_diff_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_one_test_master_starter.sh
        UDP subscribe_notify_one_test_diff_client_ids_diff_ports_master_udp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_one_test_diff_client_ids_diff_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_one_test_master_starter.sh
        TCP subscribe_notify_one_test_diff_client_ids_diff_ports_master_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_one_test_diff_client_ids_diff_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_one_test_master_starter.sh
        TCP_AND_UDP subscribe_notify_one_test_diff_client_ids_diff_ports_master.json
)
