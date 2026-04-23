# Set up the ZeroBus FFI prebuilt static library.
#
# If ZEROBUS_LIB_DIR is already set by the user, that path is used as-is.
# Otherwise the official release tarball is downloaded and the correct
# platform subdirectory is selected automatically.
#
# On unsupported platforms or when the download fails, the plugin is
# disabled automatically (FLB_OUT_ZEROBUS is set to OFF).
#
# After this module runs:
#   ZEROBUS_LIB_DIR  — directory containing the static library
#   ZEROBUS_LIB_FILE — full path to the static library

set(_ZEROBUS_LIB_FILENAME
  "${CMAKE_STATIC_LIBRARY_PREFIX}zerobus_ffi${CMAKE_STATIC_LIBRARY_SUFFIX}")

if(ZEROBUS_LIB_DIR)
  set(ZEROBUS_LIB_FILE
    "${ZEROBUS_LIB_DIR}/${_ZEROBUS_LIB_FILENAME}"
    CACHE FILEPATH "Full path to ZeroBus FFI static library" FORCE)
  if(NOT EXISTS "${ZEROBUS_LIB_FILE}")
    message(STATUS
      "ZeroBus FFI: library not found at ${ZEROBUS_LIB_FILE}, "
      "disabling out_zerobus.")
    unset(ZEROBUS_LIB_FILE CACHE)
    FLB_OPTION(FLB_OUT_ZEROBUS OFF)
  endif()
  return()
endif()

set(_ZEROBUS_URL
  "https://github.com/databricks/zerobus-sdk/releases/download/ffi-v1.0.0/zerobus-ffi-1.0.0.tar.gz")
set(_ZEROBUS_SHA256
  "c38609f5bddc160b43b35f9047919b35f66375308be69a0d0d6cd20bc01cee5a")

# Determine the platform subdirectory inside the tarball
if(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "^(aarch64|arm64|ARM64|AARCH64)$")
    set(_ZEROBUS_PLATFORM "linux-aarch64")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "^(x86_64|AMD64)$")
    set(_ZEROBUS_PLATFORM "linux-x86-64")
  else()
    message(STATUS
      "ZeroBus FFI: unsupported Linux architecture '${CMAKE_SYSTEM_PROCESSOR}', "
      "disabling out_zerobus. "
      "To build manually, set -DZEROBUS_LIB_DIR=/path/to/lib.")
    FLB_OPTION(FLB_OUT_ZEROBUS OFF)
    return()
  endif()
elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(_ZEROBUS_PLATFORM "windows-x86-64")
  else()
    message(STATUS
      "ZeroBus FFI: no prebuilt library for 32-bit Windows, "
      "disabling out_zerobus. "
      "To build manually, set -DZEROBUS_LIB_DIR=/path/to/lib.")
    FLB_OPTION(FLB_OUT_ZEROBUS OFF)
    return()
  endif()
else()
  message(STATUS
    "ZeroBus FFI: no prebuilt library available for ${CMAKE_SYSTEM_NAME}, "
    "disabling out_zerobus. "
    "To build manually, set -DZEROBUS_LIB_DIR=/path/to/lib.")
  FLB_OPTION(FLB_OUT_ZEROBUS OFF)
  return()
endif()

# Download the tarball if not already cached
set(_ZEROBUS_TARBALL "${CMAKE_BINARY_DIR}/zerobus-ffi-1.0.0.tar.gz")
if(NOT EXISTS "${_ZEROBUS_TARBALL}")
  message(STATUS "ZeroBus FFI: downloading ${_ZEROBUS_URL}")
  file(DOWNLOAD
    "${_ZEROBUS_URL}"
    "${_ZEROBUS_TARBALL}"
    EXPECTED_HASH "SHA256=${_ZEROBUS_SHA256}"
    SHOW_PROGRESS
    STATUS _DOWNLOAD_STATUS
  )
  list(GET _DOWNLOAD_STATUS 0 _DOWNLOAD_ERROR)
  if(_DOWNLOAD_ERROR)
    message(STATUS
      "ZeroBus FFI: download failed (${_DOWNLOAD_STATUS}), "
      "disabling out_zerobus. "
      "To build manually, set -DZEROBUS_LIB_DIR=/path/to/lib.")
    file(REMOVE "${_ZEROBUS_TARBALL}")
    FLB_OPTION(FLB_OUT_ZEROBUS OFF)
    return()
  endif()
endif()

# Extract the tarball
set(_ZEROBUS_EXTRACT_DIR "${CMAKE_BINARY_DIR}")
if(NOT EXISTS "${_ZEROBUS_EXTRACT_DIR}/native/${_ZEROBUS_PLATFORM}/${_ZEROBUS_LIB_FILENAME}")
  execute_process(
    COMMAND ${CMAKE_COMMAND} -E tar xzf "${_ZEROBUS_TARBALL}"
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    RESULT_VARIABLE _EXTRACT_RESULT
  )
  if(_EXTRACT_RESULT)
    message(STATUS
      "ZeroBus FFI: extraction failed, disabling out_zerobus.")
    FLB_OPTION(FLB_OUT_ZEROBUS OFF)
    return()
  endif()
endif()

set(ZEROBUS_LIB_DIR "${_ZEROBUS_EXTRACT_DIR}/native/${_ZEROBUS_PLATFORM}"
    CACHE PATH "Path to ZeroBus FFI library directory" FORCE)
set(ZEROBUS_LIB_FILE "${ZEROBUS_LIB_DIR}/${_ZEROBUS_LIB_FILENAME}"
    CACHE FILEPATH "Full path to ZeroBus FFI static library" FORCE)

if(NOT EXISTS "${ZEROBUS_LIB_FILE}")
  message(STATUS
    "ZeroBus FFI: ${_ZEROBUS_LIB_FILENAME} not found at ${ZEROBUS_LIB_DIR}, "
    "disabling out_zerobus.")
  FLB_OPTION(FLB_OUT_ZEROBUS OFF)
  return()
endif()

message(STATUS "ZeroBus FFI library: ${ZEROBUS_LIB_FILE}")
