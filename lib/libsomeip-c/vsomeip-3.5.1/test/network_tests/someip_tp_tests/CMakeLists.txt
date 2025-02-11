# Copyright (C) 2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(someip_tp_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    someip_tp_test_master.json
    someip_tp_test_master_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(someip_tp_test_service
    someip_tp_test_service.cpp
)

# Add test executable.
set(service_discovery_sources
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/configuration_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/entry_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/eventgroupentry_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/ip_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/ipv4_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/ipv6_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/load_balancing_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/message_element_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/message_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/protection_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/selective_option_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/serviceentry_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/service_discovery/src/unknown_option_impl.cpp
)
set(message_sources
    ${CMAKE_SOURCE_DIR}/implementation/message/src/deserializer.cpp
    ${CMAKE_SOURCE_DIR}/implementation/message/src/message_impl.cpp
    ${CMAKE_SOURCE_DIR}/implementation/message/src/payload_impl.cpp
)
set(endpoint_sources
    ${CMAKE_SOURCE_DIR}/implementation/endpoints/src/tp.cpp
    ${CMAKE_SOURCE_DIR}/implementation/endpoints/src/tp_reassembler.cpp
    ${CMAKE_SOURCE_DIR}/implementation/endpoints/src/tp_message.cpp
)
add_executable(someip_tp_test_msg_sender
    someip_tp_test_msg_sender.cpp
    ${service_discovery_sources}
    ${message_sources}
    ${endpoint_sources}
)

# Link vsomeip-sd to test executable.
target_link_libraries(someip_tp_test_msg_sender
    ${VSOMEIP_NAME}-sd
)

# Add build dependencies and link libraries to executables.
set(executables
    someip_tp_test_service
    someip_tp_test_msg_sender
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_in_sequence
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh IN_SEQUENCE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_mixed
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh MIXED
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_incomplete
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh INCOMPLETE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_duplicate
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh DUPLICATE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_overlap
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh OVERLAP
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME someip_tp_test_overlap_front_back
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/someip_tp_test_master_starter.sh OVERLAP_FRONT_BACK
    TIMEOUT 180
)
