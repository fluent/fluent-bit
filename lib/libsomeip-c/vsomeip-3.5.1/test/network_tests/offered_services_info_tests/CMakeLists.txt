# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(offered_services_info_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    offered_services_info_test_local.json
    offered_services_info_test_local_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(offered_services_info_test_service
    offered_services_info_test_service.cpp
)

# Add test executable.
add_executable(offered_services_info_test_client
    offered_services_info_test_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    offered_services_info_test_service
    offered_services_info_test_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME offered_services_info_test_local
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/offered_services_info_test_local_starter.sh
    TIMEOUT 180
)
