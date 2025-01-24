# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(pending_subscription_test LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    pending_subscription_test_master.json
    pending_subscription_test_master_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(pending_subscription_test_service
    pending_subscription_test_service.cpp
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
add_executable(pending_subscription_test_sd_msg_sender
    pending_subscription_test_sd_msg_sender.cpp
    ${service_discovery_sources}
    ${message_sources}
)

# Link vsomeip-sd to executable.
target_link_libraries(pending_subscription_test_sd_msg_sender ${VSOMEIP_NAME}-sd)

# Add build dependencies and link libraries to executables.
set(executables
    pending_subscription_test_service
    pending_subscription_test_sd_msg_sender
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_subscribe
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_alternating_subscribe_unsubscribe
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE_UNSUBSCRIBE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_unsubscribe
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh UNSUBSCRIBE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_alternating_subscribe_unsubscribe_nack
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE_UNSUBSCRIBE_NACK
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_alternating_subscribe_unsubscribe_same_port
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE_UNSUBSCRIBE_SAME_PORT
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_subscribe_resubscribe_mixed
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE_RESUBSCRIBE_MIXED
    TIMEOUT 300
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_subscribe_stopsubscribe_subscribe
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh SUBSCRIBE_STOPSUBSCRIBE_SUBSCRIBE
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME pending_subscription_test_send_request_to_sd_port
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/pending_subscription_test_master_starter.sh REQUEST_TO_SD
    TIMEOUT 180
)
