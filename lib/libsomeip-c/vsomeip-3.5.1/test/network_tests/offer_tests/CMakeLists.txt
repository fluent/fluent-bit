# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(offer_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    offer_test_big_sd_msg_master.json
    offer_test_big_sd_msg_master_starter.sh
    offer_test_big_sd_msg_slave.json
    offer_test_big_sd_msg_slave_starter.sh
    offer_test_external_master.json
    offer_test_external_master_starter.sh
    offer_test_external_slave.json
    offer_test_external_slave_starter.sh
    offer_test_local.json
    offer_test_local_starter.sh
    offer_test_multiple_offerings.json
    offer_test_multiple_offerings_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(offer_test_service
    offer_test_service.cpp
)

# Add test executable.
add_executable(offer_test_multiple_offerings
    offer_test_multiple_offerings.cpp
)

# Add test executable.
add_executable(offer_test_client
    offer_test_client.cpp
)

# Add test executable.
add_executable(offer_test_service_external
    offer_test_service_external.cpp
)

# Add test executable.
add_executable(offer_test_external_sd_msg_sender
    offer_test_external_sd_msg_sender.cpp
)

# Add test executable.
add_executable(offer_test_big_sd_msg_service
    offer_test_big_sd_msg_service.cpp
)

# Add test executable.
add_executable(offer_test_big_sd_msg_client
    offer_test_big_sd_msg_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    offer_test_service
    offer_test_multiple_offerings
    offer_test_client
    offer_test_service_external
    offer_test_external_sd_msg_sender
    offer_test_big_sd_msg_service
    offer_test_big_sd_msg_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME offer_test_local
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offer_test_local_starter.sh
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME offer_test_external
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offer_test_external_master_starter.sh
    TIMEOUT 360
)

# Add custom test command.
add_custom_test(
    NAME offer_test_big_sd_msg
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offer_test_big_sd_msg_master_starter.sh
    TIMEOUT 360
)

# Add custom test command.
add_custom_test(
    NAME offer_test_multiple_offerings
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offer_test_multiple_offerings_starter.sh
    TIMEOUT 1800
)
