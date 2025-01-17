# Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

set (VSOMEIP_NAME vsomeip3)

# Add the gtest header files to the include files
include_directories(
    .
    ${gtest_SOURCE_DIR}/include
)

set(TEST_LINK_LIBRARIES gtest)
if (${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    set(TEST_LINK_LIBRARIES ${TEST_LINK_LIBRARIES} socket)
endif()
set(NETWORK_TEST_BIN_DIR ${PROJECT_BINARY_DIR}/test/network_tests)
set(NETWORK_TEST_SRC_DIR ${PROJECT_SOURCE_DIR}/test/network_tests)
set(HOSTNAME "$ENV{HOSTNAME}")

# Configures the given files into the build folder.
#
# This function looks for files in the `conf` folder with the same name as the
# given files, and ending in `.in`. It will then copy these files into the build
# folder, and replace variables marked with @VARIABLE@ with their actual value.
#
# # Example
#
# set(configuration_files
#     my_test_config.json
#     my_test_starter.sh
# )
# configure_files("${configuration_files}")
function(configure_files files)
    foreach(item ${files})
        configure_file(
            ${CMAKE_CURRENT_SOURCE_DIR}/conf/${item}.in
            ${CMAKE_CURRENT_BINARY_DIR}/${item}
            @ONLY
        )
    endforeach()
endfunction()

# Links the given targets to the default libraries.
#
# These include libraries that are used by nearly every test, such as vsomeip,
# boost, gtest, etc.
#
# # Example
#
# set(executables
#     my_test_service
#     my_test_client
# )
# targets_link_default_libraries("${executables}")
function(targets_link_default_libraries targets)
    foreach(target ${targets})
        target_link_libraries(${target}
            ${VSOMEIP_NAME}
            ${Boost_LIBRARIES}
            ${DL_LIBRARY}
            ${TEST_LINK_LIBRARIES}
            ${DLT_LIBRARIES}
            vsomeip_utilities
        )
    endforeach()
endfunction()

# Adds build dependencies to the given targets.
#
# These ensure that the targets will be built alongside `gtest` and
# `build_network_tests` targets.
#
# # Example
#
# set(executables
#     my_test_service
#     my_test_client
# )
# targets_add_default_dependencies("${executables}")
function(targets_add_default_dependencies targets)
    foreach(target ${targets})
        add_dependencies(${target} gtest)
        add_dependencies(build_network_tests ${target})
    endforeach()
endfunction()

# Adds a custom command to be called by ctest.
#
# Options include timeouts and environment variables.
#
# Handles the necessary steps to allow calling the test with valgrind, etc.
#
# # Example
#
# add_custom_test(
#     NAME my_test_name
#     COMMAND ${CMAKE_CURRENT_BINARY_DIR}/my_test_starter.sh ARG1 ARG2...
#     TIMEOUT 60 # Optional. Defaults to 120s.
#     ENVIRONMENT VSOMEIP_CONFIGURATION=my_test_config.json # Optional.
# )
function(add_custom_test)
    set(options "")
    set(oneValueArgs NAME TIMEOUT)
    set(multiValueArgs COMMAND ENVIRONMENT)
    cmake_parse_arguments(MY_TEST
        "${options}" "${oneValueArgs}" "${multiValueArgs}" ${ARGN}
    )

    # Replace "test_name" in TEST_ENTRYPOINT with the actual test name.
    string(REPLACE
        "test_name" "${MY_TEST_NAME}" custom_test_entrypoint "${TEST_ENTRYPOINT}"
    )

    # Add a custom test command.
    add_test(
        NAME ${MY_TEST_NAME}
        COMMAND ${custom_test_entrypoint} ${MY_TEST_COMMAND}
    )

    if(NOT MY_TEST_TIMEOUT)
        # Set the default timeout to 120 seconds.
        set(MY_TEST_TIMEOUT 120)
    endif()

    # Set a timeout for the test.
    set_tests_properties(${MY_TEST_NAME}
        PROPERTIES TIMEOUT ${MY_TEST_TIMEOUT}
    )

    if(MY_TEST_ENVIRONMENT)
        # Set environment variables for the test.
        set_property(
            TEST ${MY_TEST_NAME}
            APPEND PROPERTY ENVIRONMENT
            "${MY_TEST_ENVIRONMENT}"
        )
    endif()
endfunction()

### ADD TESTS SUBDIRECTORIES ###
if(NOT ${TESTS_BAT})
    add_subdirectory(client_id_tests)
    add_subdirectory(initial_event_tests)
    add_subdirectory(subscribe_notify_one_tests)
    add_subdirectory(subscribe_notify_tests)
    add_subdirectory(restart_routing_tests)
    add_subdirectory(configuration_tests)
    add_subdirectory(cpu_load_tests)
    add_subdirectory(debounce_callback_tests)
    add_subdirectory(debounce_filter_tests)
    add_subdirectory(debounce_frequency_tests)
    add_subdirectory(debounce_tests)
    add_subdirectory(e2e_tests)
    add_subdirectory(event_tests)
    add_subdirectory(lazy_load_tests)
    add_subdirectory(magic_cookies_tests)
    add_subdirectory(malicious_data_tests)
    add_subdirectory(memory_tests)
    add_subdirectory(offer_stop_offer_test)
    add_subdirectory(offered_services_info_tests)
    add_subdirectory(pending_subscription_tests)
    add_subdirectory(regression_tests)
    add_subdirectory(second_address_tests)
    add_subdirectory(security_tests)
    add_subdirectory(someip_tp_tests)
    add_subdirectory(offer_tests)
    add_subdirectory(suspend_resume_tests)
endif()

add_subdirectory(application_tests)
add_subdirectory(routing_tests)
add_subdirectory(big_payload_tests)
add_subdirectory(header_factory_tests)
add_subdirectory(npdu_tests)
add_subdirectory(payload_tests)
add_subdirectory(cyclic_event_tests)

# some tests require the routingmanagerd
if (NOT MSVC)
add_dependencies(build_network_tests routingmanagerd)
endif ()
