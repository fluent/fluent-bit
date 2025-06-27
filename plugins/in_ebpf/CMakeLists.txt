# Define source files for the main plugin
file(GLOB_RECURSE src
    "in_ebpf.c"
    "traces/**/handler.c"
)

# Determine architecture and set flags accordingly
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64")
  set(ARCH_FLAG "-D__TARGET_ARCH_x86_64")
  set(VMLINUX_PATH "${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes/external/gadget/amd64")
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64" OR CMAKE_SYSTEM_PROCESSOR MATCHES "arm64")
  set(ARCH_FLAG "-D__TARGET_ARCH_arm64")
  set(VMLINUX_PATH "${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes/external/gadget/arm64")
else()
  message(FATAL_ERROR "Unsupported architecture: ${CMAKE_SYSTEM_PROCESSOR}")
endif()

# Include directories for external headers, common headers, and generated skeletons
include_directories(
  ${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes/external
  ${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes
)

# Create an interface library for gadget includes
add_library(gadget INTERFACE)
target_include_directories(gadget INTERFACE ${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes/external/gadget)

set(LIBC_PATH "/lib64/libc.so.6")

find_program(LSB_RELEASE_EXEC lsb_release)
if (LSB_RELEASE_EXEC)
  execute_process(COMMAND ${LSB_RELEASE_EXEC} -i
      OUTPUT_VARIABLE LSB_RELEASE_ID_SHORT
      OUTPUT_STRIP_TRAILING_WHITESPACE
  )

  message(STATUS "##### lsb_release -i -- ${LSB_RELEASE_ID_SHORT}")

  if (LSB_RELEASE_ID_SHORT MATCHES "Ubuntu" OR
      LSB_RELEASE_ID_SHORT MATCHES "Debian" OR
      LSB_RELEASE_ID_SHORT MATCHES "LinuxMint")
    # Just added for the future enhancement
    if (CMAKE_SYSTEM_PROCESSOR MATCHES "^(arm64|aarch64)")
      set(LIBC_PATH "/usr/lib/aarch64-linux-gnu/libc.so.6")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
      set(LIBC_PATH "/usr/lib/x86_64-linux-gnu/libc.so.6")
    elseif (CMAKE_SIZEOF_VOID_P EQUAL 4)
      set(LIBC_PATH "/usr/lib/i386-linux-gnu/libc.so.6")
    endif()
  endif()
endif()

# Generate the malloc trace from the template
configure_file(
  "${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/malloc/bpf.c.in"
  "${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/malloc/bpf.c"
  )

# Find all bpf.c files in the traces directory
file(GLOB_RECURSE TRACE_C_FILES ${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/*/bpf.c)

# Create a list to hold all the object files and skeleton headers that will be generated
set(TRACE_OBJ_FILES "")
set(TRACE_SKEL_HEADERS "")

add_custom_target(ebpf-generated-directory ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_BINARY_DIR}/plugins/in_ebpf/traces/includes/generated/)

# Iterate over each trace bpf.c file to generate corresponding .o and .skel.h files
foreach(TRACE_C_FILE ${TRACE_C_FILES})
  # Get the filename and parent directory name (for uniqueness)
  get_filename_component(TRACE_FILE_NAME ${TRACE_C_FILE} NAME_WE)
  get_filename_component(TRACE_PARENT_DIR ${TRACE_C_FILE} DIRECTORY)
  get_filename_component(TRACE_PARENT_DIR_NAME ${TRACE_PARENT_DIR} NAME)

  # Ensure the output filenames maintain the original "trace_" prefix
  set(TRACE_BASE_NAME "trace_${TRACE_PARENT_DIR_NAME}")

  # Set unique names by including the parent directory name in the output paths
  set(TRACE_OBJ_FILE ${CMAKE_BINARY_DIR}/plugins/in_ebpf/traces/includes/generated/${TRACE_BASE_NAME}.o)
  set(TRACE_SKEL_HEADER ${CMAKE_BINARY_DIR}/plugins/in_ebpf/traces/includes/generated/${TRACE_BASE_NAME}.skel.h)

  # Compile each bpf.c file to its corresponding .o file
  add_custom_command(
    OUTPUT ${TRACE_OBJ_FILE}
    COMMAND clang
            -target bpf
            ${ARCH_FLAG}              # Use architecture-specific flag
            -O2                       # Optional: Optimization level
            -g                        # Optional: Debug info
            -I${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes/external
            -I${CMAKE_SOURCE_DIR}/plugins/in_ebpf/traces/includes
            -I${VMLINUX_PATH}         # Include the correct vmlinux.h based on architecture
            -c ${TRACE_C_FILE}
            -o ${TRACE_OBJ_FILE}
    DEPENDS ${TRACE_C_FILE} ebpf-generated-directory
  )

  # Generate skeleton header for each compiled BPF object file
  add_custom_command(
    OUTPUT ${TRACE_SKEL_HEADER}
    COMMAND bpftool gen skeleton ${TRACE_OBJ_FILE} > ${TRACE_SKEL_HEADER}
    DEPENDS ${TRACE_OBJ_FILE}
    COMMENT "Generating skeleton ${TRACE_SKEL_HEADER} from ${TRACE_OBJ_FILE}"
  )

  # Add generated object and skeleton files to their respective lists
  list(APPEND TRACE_OBJ_FILES ${TRACE_OBJ_FILE})
  list(APPEND TRACE_SKEL_HEADERS ${TRACE_SKEL_HEADER})
endforeach()

# Create a custom target specifically for generating eBPF skeletons
add_custom_target(flb-ebpf-generate_skeletons DEPENDS ${TRACE_SKEL_HEADERS})

# Create a custom target to compile all eBPF programs (all trace bpf.c files)
add_custom_target(compile_ebpf ALL DEPENDS ${TRACE_OBJ_FILES} ${TRACE_SKEL_HEADERS})

# Ensure that the custom target depends on the gadget interface library (for include paths)
add_dependencies(compile_ebpf gadget)

# Include generated skeleton headers in the main plugin
include_directories(${CMAKE_BINARY_DIR}/plugins/in_ebpf/traces/includes/)

# Declare the Fluent Bit plugin (using the default compiler for the main plugin)
FLB_PLUGIN(in_ebpf "${src}" "")

# Link necessary libraries
target_link_libraries(flb-plugin-in_ebpf gadget -lbpf -lelf -lz)
