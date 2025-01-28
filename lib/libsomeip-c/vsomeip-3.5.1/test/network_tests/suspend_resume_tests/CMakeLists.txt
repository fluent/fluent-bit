# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(suspend_resume_tests LANGUAGES CXX)

# Configure necessary files into the build folder.
set(configuration_files
    suspend_resume_test_client.json
    suspend_resume_test_master_starter.sh
    suspend_resume_test_service.json
    suspend_resume_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(suspend_resume_test_service
    suspend_resume_test_service.cpp
)

# Add test executable.
add_executable(suspend_resume_test_client
    suspend_resume_test_client.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    suspend_resume_test_service
    suspend_resume_test_client
)
targets_add_default_dependencies("${executables}")
targets_link_default_libraries("${executables}")

# Add custom test command.
add_custom_test(
    NAME suspend_resume_test_initial
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/suspend_resume_test_master_starter.sh SERVICE
)
