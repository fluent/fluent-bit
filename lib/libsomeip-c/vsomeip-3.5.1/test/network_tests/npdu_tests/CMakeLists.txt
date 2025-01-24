# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(npdu_tests LANGUAGES CXX)

if(NOT TESTS_BAT AND NOT ${CMAKE_SYSTEM_NAME} MATCHES "QNX")

    # Configure necessary files into the build folder.
    set(configuration_files
        npdu_test_client_no_npdu.json
        npdu_test_client_no_npdu_start.sh
        npdu_test_client_npdu.json
        npdu_test_client_npdu_start.sh
        npdu_test_service_no_npdu.json
        npdu_test_service_no_npdu_start.sh
        npdu_test_service_npdu.json
        npdu_test_service_npdu_start.sh
        npdu_test_starter.sh
    )
    configure_files("${configuration_files}")

    # Routing managers.

    # Add test executable.
    add_executable(npdu_test_rmd_client_side
        npdu_test_rmd.cpp
    )
    set_target_properties(npdu_test_rmd_client_side
        PROPERTIES COMPILE_FLAGS -DRMD_CLIENT_SIDE
    )

    # Add test executable.
    add_executable(npdu_test_rmd_service_side
        npdu_test_rmd.cpp
    )
    set_target_properties(npdu_test_rmd_service_side
        PROPERTIES COMPILE_FLAGS -DRMD_SERVICE_SIDE
    )

    # Add build dependencies and link libraries to executables.
    set(routing_managers
        npdu_test_rmd_client_side
        npdu_test_rmd_service_side
    )
    targets_add_default_dependencies("${routing_managers}")
    targets_link_default_libraries("${routing_managers}")

    # Clients and Services.

    # Add test executable.
    add_executable(npdu_test_service_1
        npdu_test_service.cpp
    )
    set_target_properties(npdu_test_service_1
        PROPERTIES COMPILE_FLAGS -DSERVICE_NUMBER=0
    )

    # Add test executable.
    add_executable(npdu_test_service_2
        npdu_test_service.cpp
    )
    set_target_properties(npdu_test_service_2
        PROPERTIES COMPILE_FLAGS -DSERVICE_NUMBER=1
    )

    # Add test executable.
    add_executable(npdu_test_service_3
        npdu_test_service.cpp
    )
    set_target_properties(npdu_test_service_3
        PROPERTIES COMPILE_FLAGS -DSERVICE_NUMBER=2
    )

    # Add test executable.
    add_executable(npdu_test_service_4
        npdu_test_service.cpp
    )
    set_target_properties(npdu_test_service_4
        PROPERTIES COMPILE_FLAGS -DSERVICE_NUMBER=3
    )

    # Add test executable.
    add_executable(npdu_test_client_1
        npdu_test_client.cpp
    )

    # Add test executable.
    add_executable(npdu_test_client_2
        npdu_test_client.cpp
    )

    # Add test executable.
    add_executable(npdu_test_client_3
        npdu_test_client.cpp
    )

    # Add test executable.
    add_executable(npdu_test_client_4
        npdu_test_client.cpp
    )

    # Add build dependencies and link libraries to executables.
    set(executables
        npdu_test_service_1
        npdu_test_service_2
        npdu_test_service_3
        npdu_test_service_4
        npdu_test_client_1
        npdu_test_client_2
        npdu_test_client_3
        npdu_test_client_4
    )
    targets_add_default_dependencies("${executables}")
    targets_link_default_libraries("${executables}")

    # Link executables to vsomeip-cfg.
    foreach(target ${executables})
        target_link_libraries(${target} ${VSOMEIP_NAME}-cfg)
    endforeach()

    # Add custom test command.
    add_custom_test(
        NAME npdu_test_udp
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/npdu_test_starter.sh UDP sync
        TIMEOUT 840
    )

    # Add custom test command.
    add_custom_test(
        NAME npdu_test_tcp
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/npdu_test_starter.sh TCP sync
        TIMEOUT 840
    )

endif()
