# Define the location of your zig executable.
find_program(ZIG_EXECUTABLE zig REQUIRED)

get_property(include_dirs DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES)

#message(STATUS "1 Hack hack hack ${CMAKE_SOURCE_DIR}")
#message(STATUS "2 Hack hac/k hack ${PROJECT_SOURCE_DIR}")
#message(FATAL_ERROR "Hack hack hack : ${CMAKE_CURRENT_BINARY_DIR}")

add_custom_command(
    OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-out_zig_test_1.o
    COMMAND ${CMAKE_COMMAND} -E env "FLB_ZIG_BUILD_INCLUDE_DIRECTORIES=${include_dirs}" ${ZIG_EXECUTABLE} build --prefix "${CMAKE_CURRENT_BINARY_DIR}"
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/build.zig
    VERBATIM
)

# Add a custom target to trigger the custom command.
add_custom_target(zig-build-done
    DEPENDS ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-out_zig_test_1.o
)

# Add a dummy target for testing
#add_executable(dummy_target)
#add_dependencies(dummy_target zig-build-done)

#add_library(flb-plugin-out_zig_test_1 STATIC ${src})
#add_sanitizers(flb-plugin-${name})
#target_link_libraries(flb-plugin-${name} fluent-bit-static msgpack-c-static ${deps})

set(src
    dummy.c
    ${CMAKE_CURRENT_BINARY_DIR}/flb-plugin-out_zig_test_1.o)

FLB_PLUGIN(out_zig_test_1 "${src}" "")

add_dependencies(flb-plugin-out_zig_test_1 zig-build-done)

#execute_process(
#  COMMAND ${CMAKE_COMMAND} -E env
#          "FLB_ZIG_BUILD_INCLUDE_DIRECTORIES=${include_dirs}"
#          "FLB_ZIG_BUILD_BINARY_DIRECTORY=${PROJECT_BINARY_DIR}"
#          zig build --build-file "${PROJECT_SOURCE_DIR}/build.zig" --prefix "${PROJECT_BINARY_DIR}"
#)

# Add a custom command to run 'zig build'.
#add_custom_command(
#    OUTPUT ${CMAKE_BINARY_DIR}/zig-build-done # A dummy output file to track the command.
#    COMMAND ${ZIG_EXECUTABLE} build
#    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} # Assumes your build.zig is in the source dir.
#    DEPENDS ${CMAKE_SOURCE_DIR}/build.zig # Trigger rebuild when build.zig changes.
#    VERBATIM
#)

