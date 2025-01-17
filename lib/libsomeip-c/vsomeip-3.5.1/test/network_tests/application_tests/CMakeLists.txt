# Copyright (C) 2023-2024 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required(VERSION 3.4...3.22)

project(application_tests LANGUAGES CXX)

# Configure necessary files and copy them to the build folder.
set(configuration_files
    application_test.json
    application_test_daemon.json
    application_test_no_dispatch_threads.json
    application_test_no_dispatch_threads_daemon.json
    application_test_dispatch_threads.json
    application_test_starter.sh
    application_test_dispatch_threads_starter.sh
    application_test_dispatch_threads_executor_starter.sh
)
configure_files("${configuration_files}")

# Add the test executable.
add_executable(application_test
    application_test.cpp
)

# Add the test executable for application_test_multiple_init
add_executable(application_test_multiple_init
    application_test_multiple_init.cpp
)

# Add the test executable for application_test_dispatch_threads_executor
add_executable(application_test_dispatch_threads_executor
    application_test_dispatch_threads_executor.cpp
)

# Add the test executable for application_test_dispatch_threads
add_executable(application_test_dispatch_threads
    application_test_dispatch_threads.cpp
)

# Add build dependencies and link libraries to executables.
set(executable_targets
    application_test
    application_test_multiple_init
    application_test_dispatch_threads
    application_test_dispatch_threads_executor
)
targets_add_default_dependencies("${executable_targets}")
targets_link_default_libraries("${executable_targets}")

# Add custom test command.
add_custom_test(
    NAME application_test
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/application_test_starter.sh
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME application_test_multiple_init
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/application_test_multiple_init
    TIMEOUT 180
)

# Add custom test command.
add_custom_test(
    NAME application_test_dispatch_threads_executor
    COMMAND ${CMAKE_CURRENT_BINARY_DIR}/application_test_dispatch_threads_executor_starter.sh
    TIMEOUT 180
)

if (NOT ${TESTS_BAT})

    # Configure necessary files and copy them to the build folder.
    set(configuration_files
        application_test_single_process.json
        application_test_single_process_starter.sh
        application_test_availability_starter.sh
    )
    configure_files("${configuration_files}")

    # Add the test executable.
    add_executable(application_test_single_process
        application_test_single_process.cpp
    )

    if(QNX)
        target_compile_definitions(application_test_single_process
            PRIVATE _QNX_SOURCE
        )
    endif()

    # Add the test executable.
    add_executable(application_test_availability
        application_test_availability.cpp
    )

    # Add build dependencies and link libraries to executables.
    set(executable_targets
        application_test_single_process
        application_test_availability
    )
    targets_add_default_dependencies("${executable_targets}")
    targets_link_default_libraries("${executable_targets}")

    # Add custom test command.
    add_custom_test(
        NAME application_test_single_process
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/application_test_single_process_starter.sh
        TIMEOUT 80
    )

    # Add custom test command.
    add_custom_test(
        NAME application_test_availability
        COMMAND ${CMAKE_CURRENT_BINARY_DIR}/application_test_availability_starter.sh
        TIMEOUT 80
    )

endif()
