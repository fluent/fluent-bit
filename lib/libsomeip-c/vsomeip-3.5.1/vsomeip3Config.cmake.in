# Config file for the vSomeIP package, defines the following variables:
# Exports the following targets:
#   vsomeip3 - CMake target for vSomeIP
# Additionally, the following variables are defined:
#   VSOMEIP_LIBRARIES - list of libraries to link against, contains only
#                       "vsomeip3"

# Compute paths
get_filename_component (VSOMEIP_CMAKE_DIR "${CMAKE_CURRENT_LIST_FILE}" PATH)
# Legacy variable, no longer used but kept for compatibility
get_filename_component(VSOMEIP_INCLUDE_DIRS "" PATH)

# Our library dependencies (contains definitions for IMPORTED targets)
if (NOT TARGET vsomeip AND NOT vsomeip_BINARY_DIR)
    include ("${VSOMEIP_CMAKE_DIR}/vsomeip3Targets.cmake")
endif ()

# These are IMPORTED targets created by vsomeipTargets.cmake
set (VSOMEIP_LIBRARIES vsomeip3)
