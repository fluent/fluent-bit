# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(subscribe_notify_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_master.json
    subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_master_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_slave.json
    subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_slave_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_master.json
    subscribe_notify_test_diff_client_ids_diff_ports_master_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_master_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_master_tcp_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_master_udp.json
    subscribe_notify_test_diff_client_ids_diff_ports_master_udp_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_master_udp.json
    subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_master_udp_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_slave_udp.json
    subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_slave_udp_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave_tcp_local_tcp.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave_udp.json
    subscribe_notify_test_diff_client_ids_diff_ports_slave_udp_local_tcp.json
    subscribe_notify_test_diff_client_ids_partial_same_ports_master.json
    subscribe_notify_test_diff_client_ids_partial_same_ports_master_local_tcp.json
    subscribe_notify_test_diff_client_ids_partial_same_ports_slave.json
    subscribe_notify_test_diff_client_ids_partial_same_ports_slave_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_master.json
    subscribe_notify_test_diff_client_ids_same_ports_master_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_master_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_master_tcp_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_master_udp.json
    subscribe_notify_test_diff_client_ids_same_ports_master_udp_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_slave.json
    subscribe_notify_test_diff_client_ids_same_ports_slave_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_slave_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_slave_tcp_local_tcp.json
    subscribe_notify_test_diff_client_ids_same_ports_slave_udp.json
    subscribe_notify_test_diff_client_ids_same_ports_slave_udp_local_tcp.json
    subscribe_notify_test_master_starter.sh
    subscribe_notify_test_one_event_two_eventgroups_master.json
    subscribe_notify_test_one_event_two_eventgroups_master_local_tcp.json
    subscribe_notify_test_one_event_two_eventgroups_master_starter.sh
    subscribe_notify_test_one_event_two_eventgroups_slave_starter.sh
    subscribe_notify_test_one_event_two_eventgroups_tcp_slave.json
    subscribe_notify_test_one_event_two_eventgroups_tcp_slave_local_tcp.json
    subscribe_notify_test_one_event_two_eventgroups_udp_slave.json
    subscribe_notify_test_one_event_two_eventgroups_udp_slave_local_tcp.json
    subscribe_notify_test_same_client_ids_diff_ports_master.json
    subscribe_notify_test_same_client_ids_diff_ports_master_local_tcp.json
    subscribe_notify_test_same_client_ids_diff_ports_slave.json
    subscribe_notify_test_same_client_ids_diff_ports_slave_local_tcp.json
    subscribe_notify_test_same_client_ids_same_ports_master.json
    subscribe_notify_test_same_client_ids_same_ports_master_local_tcp.json
    subscribe_notify_test_same_client_ids_same_ports_slave.json
    subscribe_notify_test_same_client_ids_same_ports_slave_local_tcp.json
    subscribe_notify_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(subscribe_notify_test_service
    subscribe_notify_test_service.cpp
)

# Add test executable.
add_executable(subscribe_notify_test_one_event_two_eventgroups_service
    subscribe_notify_test_one_event_two_eventgroups_service.cpp
)

# Add test executable.
add_executable(subscribe_notify_test_one_event_two_eventgroups_client
    subscribe_notify_test_one_event_two_eventgroups_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    subscribe_notify_test_service
    subscribe_notify_test_one_event_two_eventgroups_service
    subscribe_notify_test_one_event_two_eventgroups_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Subscribe Notify Tests - Local Communication over UDS

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_master_udp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP
        subscribe_notify_test_diff_client_ids_diff_ports_master_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_diff_ports_master.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_same_ports_master_udp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP
        subscribe_notify_test_diff_client_ids_same_ports_master_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_same_ports_master.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_partial_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_partial_same_ports_master.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_master_udp.json
        SAME_SERVICE_ID
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_master.json
)

# Subscribe Notify Tests - Local Communication over TCP

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_master_udp_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_tcp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP
        subscribe_notify_test_diff_client_ids_diff_ports_master_tcp_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_both_tcp_and_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_diff_ports_master_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_same_ports_master_udp_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_tcp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP
        subscribe_notify_test_diff_client_ids_same_ports_master_tcp_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_same_ports_both_tcp_and_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_same_ports_master_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_partial_same_ports_both_tcp_and_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        TCP_AND_UDP
        subscribe_notify_test_diff_client_ids_partial_same_ports_master_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_same_service_id_master_udp_local_tcp.json
        SAME_SERVICE_ID
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_master_starter.sh
        UDP
        subscribe_notify_test_diff_client_ids_diff_ports_autoconfig_master_local_tcp.json
)

# Subscribe Notify Tests - One Event Two Eventgroups

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_one_event_two_eventgroups_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_one_event_two_eventgroups_master_starter.sh
        UDP
        subscribe_notify_test_one_event_two_eventgroups_master.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_one_event_two_eventgroups_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_one_event_two_eventgroups_master_starter.sh
        TCP
        subscribe_notify_test_one_event_two_eventgroups_master.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_one_event_two_eventgroups_udp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_one_event_two_eventgroups_master_starter.sh
        UDP
        subscribe_notify_test_one_event_two_eventgroups_master_local_tcp.json
)

# Add custom test command.
add_custom_test(
    NAME subscribe_notify_test_one_event_two_eventgroups_tcp_local_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/subscribe_notify_test_one_event_two_eventgroups_master_starter.sh
        TCP
        subscribe_notify_test_one_event_two_eventgroups_master_local_tcp.json
)
