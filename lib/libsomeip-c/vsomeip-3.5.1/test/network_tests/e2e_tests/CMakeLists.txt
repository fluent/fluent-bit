# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(e2e_tests LANGUAGES CXX)

# Configure necessary files into the build directory.
set(configuration_files
    e2e_test_client_external.json
    e2e_test_external_master_start.sh
    e2e_test_external_slave_start.sh
    e2e_test_service_external.json
)
configure_files("${configuration_files}")

# Add test executable.
add_executable(e2e_test_client
    e2e_test_client.cpp
)

# Add test executable.
add_executable(e2e_test_service
    e2e_test_service.cpp
)

# Add build dependencies and link libraries to executables.
set(executables
    e2e_test_client
    e2e_test_service
)
targets_link_default_libraries("${executables}")
targets_add_default_dependencies("${executables}")

# Add custom test command.
add_custom_test(
    NAME e2e_test_external
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/e2e_test_external_master_start.sh e2e_test_client_external.json
    TIMEOUT 180
)

if(TEST_E2E_PROFILE_04)

    # Configure necessary files into the build directory.
    set(configuration_files
        e2e_profile_04_test_client_external.json
        e2e_profile_04_test_external_master_start.sh
        e2e_profile_04_test_external_slave_start.sh
        e2e_profile_04_test_service_external.json
    )
    configure_files("${configuration_files}")

    # Add test executable.
    add_executable(e2e_profile_04_test_client
        e2e_profile_04_test_client.cpp
    )

    # Add test executable.
    add_executable(e2e_profile_04_test_service
        e2e_profile_04_test_service.cpp
    )

    # Add build dependencies and link libraries to executables.
    set(executables
        e2e_profile_04_test_client
        e2e_profile_04_test_service
    )
    targets_link_default_libraries("${executables}")
    targets_add_default_dependencies("${executables}")

    # Add custom test command.
    add_custom_test(
        NAME e2e_profile_04_test_external
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/e2e_profile_04_test_external_master_start.sh e2e_profile_04_test_client_external.json
        TIMEOUT 180
    )

endif()

if(TEST_E2E_PROFILE_07)

    # Configure necessary files into the build directory.
    set(configuration_files
        e2e_profile_07_test_client_external.json
        e2e_profile_07_test_external_master_start.sh
        e2e_profile_07_test_external_slave_start.sh
        e2e_profile_07_test_service_external.json
    )
    configure_files("${configuration_files}")

    # Add test executable.
    add_executable(e2e_profile_07_test_client
        e2e_profile_07_test_client.cpp
    )

    # Add test executable.
    add_executable(e2e_profile_07_test_service
        e2e_profile_07_test_service.cpp
    )

    # Add build dependencies and link libraries to executables.
    set(executables
        e2e_profile_07_test_client
        e2e_profile_07_test_service
    )
    targets_link_default_libraries("${executables}")
    targets_add_default_dependencies("${executables}")

    # Add custom test command.
    add_custom_test(
        NAME e2e_profile_07_test_external
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/e2e_profile_07_test_external_master_start.sh e2e_profile_07_test_client_external.json
        TIMEOUT 180
    )

endif()
