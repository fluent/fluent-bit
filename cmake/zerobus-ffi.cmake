# Locate the pre-installed ZeroBus FFI static library.
#
# The out_zerobus plugin requires the ZeroBus FFI library to be installed
# on the build system before configuring.  Fluent Bit does not download
# third-party dependencies at configure/build time.
#
# If the library is not found the plugin is silently disabled.
#
# Use -DZEROBUS_LIB_DIR=/path/to/dir to point to a custom location.
#
# After this module runs successfully:
#   ZEROBUS_LIB_FILE — full path to the static library

set(_ZEROBUS_LIB_NAME "zerobus_ffi")

if(ZEROBUS_LIB_DIR)
  # User provided an explicit directory — search only there.
  find_library(ZEROBUS_LIB_FILE
    NAMES ${_ZEROBUS_LIB_NAME}
    PATHS "${ZEROBUS_LIB_DIR}"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
else()
  # Search standard system paths.
  find_library(ZEROBUS_LIB_FILE NAMES ${_ZEROBUS_LIB_NAME})
endif()

if(ZEROBUS_LIB_FILE)
  message(STATUS "ZeroBus FFI library: ${ZEROBUS_LIB_FILE}")
else()
  message(STATUS
    "ZeroBus FFI: library not found, disabling out_zerobus. "
    "To enable, install libzerobus_ffi or set -DZEROBUS_LIB_DIR=/path/to/lib.")
  FLB_OPTION(FLB_OUT_ZEROBUS OFF)
endif()
