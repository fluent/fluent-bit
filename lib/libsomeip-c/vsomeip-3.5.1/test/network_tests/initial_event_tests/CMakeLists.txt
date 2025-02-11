# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(initial_event_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    initial_event_test_diff_client_ids_diff_ports_master.json
    initial_event_test_diff_client_ids_diff_ports_master_tcp.json
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    initial_event_test_diff_client_ids_diff_ports_same_service_id_master.json
    initial_event_test_diff_client_ids_diff_ports_same_service_id_slave.json
    initial_event_test_diff_client_ids_diff_ports_slave.json
    initial_event_test_diff_client_ids_diff_ports_slave_tcp.json
    initial_event_test_diff_client_ids_diff_ports_slave_udp.json
    initial_event_test_diff_client_ids_partial_same_ports_master.json
    initial_event_test_diff_client_ids_partial_same_ports_slave.json
    initial_event_test_diff_client_ids_same_ports_master.json
    initial_event_test_diff_client_ids_same_ports_master_tcp.json
    initial_event_test_diff_client_ids_same_ports_master_udp.json
    initial_event_test_diff_client_ids_same_ports_slave.json
    initial_event_test_diff_client_ids_same_ports_slave_tcp.json
    initial_event_test_diff_client_ids_same_ports_slave_udp.json
    initial_event_test_master_starter.sh
    initial_event_test_master_starter_qnx.sh
    initial_event_test_same_client_ids_diff_ports_master.json
    initial_event_test_same_client_ids_diff_ports_slave.json
    initial_event_test_same_client_ids_same_ports_master.json
    initial_event_test_same_client_ids_same_ports_slave.json
    initial_event_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(initial_event_test_client
    initial_event_test_client.cpp
)

# Add test executable.
add_executable(initial_event_test_service
    initial_event_test_service.cpp
)

# Add test executable.
add_executable(initial_event_test_availability_checker
    initial_event_test_availability_checker.cpp
)

# Add test executable.
add_executable(initial_event_test_stop_service
    initial_event_test_stop_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    initial_event_test_client
    initial_event_test_service
    initial_event_test_availability_checker
    initial_event_test_stop_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Initial Events Tests - Single Event

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_diff_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    UDP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_diff_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_tcp.json
    TCP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_diff_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master.json
    TCP_AND_UDP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_same_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_udp.json
    UDP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_same_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_tcp.json
    TCP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master.json
    TCP_AND_UDP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_partial_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_partial_same_ports_master.json
    TCP_AND_UDP
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_diff_ports_same_service_id_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_same_service_id_master.json
    TCP_AND_UDP SAME_SERVICE_ID
)

# Initial Events Tests - Multiple Events

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    UDP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_tcp.json
    TCP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_udp_and_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_same_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_udp.json
    UDP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_same_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_tcp.json
    TCP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_partial_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_partial_same_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_same_service_id_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_same_service_id_master.json
    TCP_AND_UDP SAME_SERVICE_ID MULTIPLE_EVENTS
)

# Initial Events Tests - Multiple Events, Subscribe On Availability

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_diff_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    UDP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_diff_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_tcp.json
    TCP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_diff_ports_udp_and_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_same_ports_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_udp.json
    UDP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_same_ports_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master_tcp.json
    TCP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_same_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_partial_same_ports_both_tcp_and_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_partial_same_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_subscribe_on_availability_diff_client_ids_diff_ports_same_service_id_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_same_service_id_master.json
    TCP_AND_UDP SAME_SERVICE_ID MULTIPLE_EVENTS SUBSCRIBE_ON_AVAILABILITY
)

# Initial Events Tests - Multiple Events, Subscribe Only One

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_partial_subscription_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    UDP MULTIPLE_EVENTS SUBSCRIBE_ONLY_ONE
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_partial_subscription_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_tcp.json
    TCP MULTIPLE_EVENTS SUBSCRIBE_ONLY_ONE
)

# Add custom test command.
add_custom_test(
    NAME initial_event_test_multiple_events_diff_client_ids_diff_ports_partial_subscription_udp_and_tcp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master.json
    TCP_AND_UDP MULTIPLE_EVENTS SUBSCRIBE_ONLY_ONE
)

# Initial Events Tests - Subscribe Twice

# Add custom test command.
add_custom_test(
    NAME initial_event_test_diff_client_ids_diff_ports_client_subscribes_twice
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/initial_event_test_master_starter.sh
    initial_event_test_diff_client_ids_diff_ports_master_udp.json
    UDP CLIENT_SUBSCRIBES_TWICE
)
