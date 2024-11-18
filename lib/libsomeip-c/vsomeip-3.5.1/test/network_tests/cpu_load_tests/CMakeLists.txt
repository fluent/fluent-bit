# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

# Configure necessary files into the build folder.
set(configuration_files
    cpu_load_test_client_master.json
    cpu_load_test_client_slave.json
    cpu_load_test_master_starter.sh
    cpu_load_test_service_master.json
    cpu_load_test_service_slave.json
    cpu_load_test_slave_starter.sh
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(cpu_load_test_service
    cpu_load_test_service.cpp
    cpu_load_measurer.cpp
)

# Add test executable.
add_executable(cpu_load_test_client
    cpu_load_test_client.cpp
    cpu_load_measurer.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    cpu_load_test_client
    cpu_load_test_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Add custom test command.
add_custom_test(
    NAME cpu_load_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/cpu_load_test_master_starter.sh
    TIMEOUT 3000
)
