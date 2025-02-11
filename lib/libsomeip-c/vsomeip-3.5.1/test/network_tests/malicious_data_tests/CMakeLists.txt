# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(malicious_data_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    malicious_data_test_master.json
    malicious_data_test_master_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(malicious_data_test_service
    malicious_data_test_service.cpp
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
add_executable(malicious_data_test_msg_sender
    malicious_data_test_msg_sender.cpp
    ${service_discovery_sources}
    ${message_sources}
)

# Link the vsomeip-sd library to the executable.
target_link_libraries(malicious_data_test_msg_sender
    ${VSOMEIP_NAME}-sd
)

# Add build dependencies and link libraries to executables.
set(executables
    malicious_data_test_service
    malicious_data_test_msg_sender
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME malicious_data_test_events
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/malicious_data_test_master_starter.sh MALICIOUS_EVENTS
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME malicious_data_test_protocol_version
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/malicious_data_test_master_starter.sh PROTOCOL_VERSION
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME malicious_data_test_message_type
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/malicious_data_test_master_starter.sh MESSAGE_TYPE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME malicious_data_test_return_code
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/malicious_data_test_master_starter.sh RETURN_CODE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME malicious_data_test_wrong_header_fields_udp
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/malicious_data_test_master_starter.sh WRONG_HEADER_FIELDS_UDP
    TIMEOUT 180
)
