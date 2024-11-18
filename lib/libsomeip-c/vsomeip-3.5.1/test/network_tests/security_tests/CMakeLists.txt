# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(security_tests LANGUAGES CXX)

if(TEST_SECURITY)

    # Configure necessary files into the build folder.
    set(configuration_files
        security_test_config_client_external_allow.json
        security_test_config_client_external_deny.json
        security_test_config_service_external_allow.json
        security_test_config_service_external_deny.json
        security_test_external_master_start.sh
        security_test_external_slave_start.sh
        security_test_local_config.json
        security_test_local_start.sh
    )
    configure_files("${configuration_files}")

    # Add test executable.
    add_executable(security_test_service
        security_test_service.cpp
    )

    # Add test executable.
    add_executable(security_test_client
        security_test_client.cpp
    )

    # Add build dependencies and link libraries to executables.
    set(executables
        security_test_service
        security_test_client
    )
    targets_add_default_dependencies("${executables}")
    targets_link_default_libraries("${executables}")

    # Add custom test command.
    add_custom_test(
        NAME security_test
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/security_test_local_start.sh
    )

    # Add custom test command.
    add_custom_test(
        NAME security_test_external_allow
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/security_test_external_master_start.sh security_test_config_client_external_allow.json --allow
    )

    # Add custom test command.
    add_custom_test(
        NAME security_test_external_deny
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/security_test_external_master_start.sh security_test_config_client_external_deny.json --deny
    )

endif()
