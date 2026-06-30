# Build or locate the Zerobus FFI static library.
#
# The out_zerobus plugin builds the bundled Zerobus FFI Rust source by default.
# Use -DZEROBUS_LIB_DIR=/path/to/dir to point to a custom prebuilt location, or
# -DFLB_PREFER_SYSTEM_LIB_ZEROBUS_FFI=On to prefer a system library.
#
# After this module runs successfully:
#   ZEROBUS_LIB_FILE         - full path to the static library
#   ZEROBUS_LIB_BUILD_TARGET - optional target that builds the bundled library
#   ZEROBUS_FFI_INCLUDE_DIR  - directory containing zerobus.h

set(_ZEROBUS_LIB_NAME "zerobus_ffi")
set(ZEROBUS_LIB_BUILD_TARGET "")
set(ZEROBUS_RUST_SOURCE_DIR
  "${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ZEROBUS_FFI}/rust")

if(NOT ZEROBUS_INCLUDE_DIR)
  set(ZEROBUS_INCLUDE_DIR "${ZEROBUS_RUST_SOURCE_DIR}/ffi")
endif()
set(ZEROBUS_FFI_INCLUDE_DIR "${ZEROBUS_INCLUDE_DIR}")

if(ZEROBUS_LIB_DIR)
  find_library(ZEROBUS_LIB_FILE
    NAMES ${_ZEROBUS_LIB_NAME}
    PATHS "${ZEROBUS_LIB_DIR}"
    NO_DEFAULT_PATH
    NO_CMAKE_FIND_ROOT_PATH
  )
elseif(FLB_PREFER_SYSTEM_LIB_ZEROBUS_FFI)
  find_library(ZEROBUS_LIB_FILE NAMES ${_ZEROBUS_LIB_NAME})
endif()

if(ZEROBUS_LIB_FILE)
  message(STATUS "Zerobus FFI library: ${ZEROBUS_LIB_FILE}")
  return()
endif()

if(NOT EXISTS "${ZEROBUS_RUST_SOURCE_DIR}/Cargo.toml")
  message(FATAL_ERROR
    "Bundled Zerobus FFI source not found at ${ZEROBUS_RUST_SOURCE_DIR}. "
    "Install libzerobus_ffi and set -DFLB_PREFER_SYSTEM_LIB_ZEROBUS_FFI=On, "
    "set -DZEROBUS_LIB_DIR=/path/to/lib, or disable the plugin with "
    "-DFLB_OUT_ZEROBUS=OFF.")
endif()

find_program(CARGO_EXECUTABLE cargo)
if(NOT CARGO_EXECUTABLE)
  message(FATAL_ERROR
    "cargo is required to build the bundled Zerobus FFI source. Install Rust, "
    "set -DZEROBUS_LIB_DIR=/path/to/lib, or disable the plugin with "
    "-DFLB_OUT_ZEROBUS=OFF.")
endif()

set(ZEROBUS_CARGO_TARGET_DIR
  "${CMAKE_BINARY_DIR}/zerobus-cargo-target"
  CACHE PATH "Cargo target directory for bundled Zerobus FFI builds")

set(_ZEROBUS_CARGO_RELEASE_DIR "${ZEROBUS_CARGO_TARGET_DIR}/release")
set(_ZEROBUS_CARGO_TARGET_ARGS "")
if(ZEROBUS_RUST_TARGET)
  list(APPEND _ZEROBUS_CARGO_TARGET_ARGS --target "${ZEROBUS_RUST_TARGET}")
  set(_ZEROBUS_CARGO_RELEASE_DIR
    "${ZEROBUS_CARGO_TARGET_DIR}/${ZEROBUS_RUST_TARGET}/release")
endif()

set(ZEROBUS_LIB_FILE
  "${_ZEROBUS_CARGO_RELEASE_DIR}/${CMAKE_STATIC_LIBRARY_PREFIX}zerobus_ffi${CMAKE_STATIC_LIBRARY_SUFFIX}")

file(GLOB_RECURSE _ZEROBUS_RUST_SOURCES CONFIGURE_DEPENDS
  "${ZEROBUS_RUST_SOURCE_DIR}/Cargo.toml"
  "${ZEROBUS_RUST_SOURCE_DIR}/Cargo.lock"
  "${ZEROBUS_RUST_SOURCE_DIR}/ffi/*"
  "${ZEROBUS_RUST_SOURCE_DIR}/sdk/*"
)

add_custom_command(
  OUTPUT "${ZEROBUS_LIB_FILE}"
  COMMAND ${CMAKE_COMMAND} -E env
    "CARGO_TARGET_DIR=${ZEROBUS_CARGO_TARGET_DIR}"
    "${CARGO_EXECUTABLE}" build
      --manifest-path "${ZEROBUS_RUST_SOURCE_DIR}/Cargo.toml"
      --locked
      --release
      -p zerobus-ffi
      ${_ZEROBUS_CARGO_TARGET_ARGS}
  DEPENDS ${_ZEROBUS_RUST_SOURCES}
  WORKING_DIRECTORY "${ZEROBUS_RUST_SOURCE_DIR}"
  COMMENT "Building bundled Zerobus FFI"
  VERBATIM
)

add_custom_target(zerobus-ffi-bundled DEPENDS "${ZEROBUS_LIB_FILE}")
set(ZEROBUS_LIB_BUILD_TARGET zerobus-ffi-bundled)

message(STATUS "Zerobus FFI source: ${ZEROBUS_RUST_SOURCE_DIR}")
message(STATUS "Zerobus FFI library: ${ZEROBUS_LIB_FILE}")
