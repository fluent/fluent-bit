cmake_minimum_required(VERSION 3.2)

include("packaging/cmake/parseversion.cmake")
parseversion("src/rdkafka.h")

project(RdKafka VERSION ${RDKAFKA_VERSION})

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/packaging/cmake/Modules/")

# Options. No 'RDKAFKA_' prefix to match old C++ code. {

# This option doesn't affect build in fact, only C code
# (see 'rd_kafka_version_str'). In CMake the build type feature usually used
# (like Debug, Release, etc.).
option(WITHOUT_OPTIMIZATION "Disable optimization" OFF)

option(ENABLE_DEVEL "Enable development asserts, checks, etc" OFF)
option(ENABLE_REFCNT_DEBUG "Enable refcnt debugging" OFF)
option(ENABLE_SHAREDPTR_DEBUG "Enable sharedptr debugging" OFF)
set(TRYCOMPILE_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/packaging/cmake/try_compile")
set(BUILT_WITH "CMAKE")

# Toolchain {
list(APPEND BUILT_WITH "${CMAKE_C_COMPILER_ID}")
list(APPEND BUILT_WITH "${CMAKE_CXX_COMPILER_ID}")
# }

# PkgConfig {
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
  set(WITH_PKGCONFIG ON)
  list(APPEND BUILT_WITH "PKGCONFIG")
endif()
# }

# LIBM {
include(CheckLibraryExists)
check_library_exists(m pow "" WITH_HDRHISTOGRAM)
if(WITH_HDRHISTOGRAM)
    list(APPEND BUILT_WITH "HDRHISTOGRAM")
endif()
# }

# ZLIB {
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  set(with_zlib_default ON)
else()
  set(with_zlib_default OFF)
endif()
option(WITH_ZLIB "With ZLIB" ${with_zlib_default})
if(WITH_ZLIB)
  list(APPEND BUILT_WITH "ZLIB")
endif()
# }

# ZSTD {
find_package(Zstd QUIET)
if(ZSTD_FOUND)
  set(with_zstd_default ON)
else()
  set(with_zstd_default OFF)
endif()
option(WITH_ZSTD "With ZSTD" ${with_zstd_default})
if(WITH_ZSTD)
  list(APPEND BUILT_WITH "ZSTD")
endif()
# }

# LibDL {
try_compile(
    WITH_LIBDL
    "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
    "${TRYCOMPILE_SRC_DIR}/dlopen_test.c"
    LINK_LIBRARIES "${CMAKE_DL_LIBS}"
)
if(WITH_LIBDL)
  list(APPEND BUILT_WITH "LIBDL")
endif()
# }

# WITH_PLUGINS {
if(WITH_LIBDL)
  set(with_plugins_default ON)
else()
  set(with_plugins_default OFF)
endif()
option(WITH_PLUGINS "With plugin support" ${with_plugins_default})
if(WITH_PLUGINS)
  list(APPEND BUILT_WITH "PLUGINS")
endif()
# }

# OpenSSL {
if(WITH_BUNDLED_SSL) # option from 'h2o' parent project
  set(with_ssl_default ON)
else()
  find_package(OpenSSL QUIET)
  if(OpenSSL_FOUND)
    set(with_ssl_default ON)
  else()
    set(with_ssl_default OFF)
  endif()
endif()
option(WITH_SSL "With SSL" ${with_ssl_default})
if(WITH_SSL)
  list(APPEND BUILT_WITH "SSL")
endif()
# }

# SASL {
if(WIN32)
  set(with_sasl_default ON)
else()
  if(PkgConfig_FOUND)
    pkg_check_modules(SASL libsasl2)
    if(SASL_FOUND)
      set(with_sasl_default ON)
    else()
      try_compile(
          WITH_SASL_CYRUS_BOOL
          "${CMAKE_CURRENT_BINARY_DIR}/try_compile"
          "${TRYCOMPILE_SRC_DIR}/libsasl2_test.c"
          LINK_LIBRARIES "-lsasl2"
      )
      if(WITH_SASL_CYRUS_BOOL)
        set(with_sasl_default ON)
        set(SASL_LIBRARIES "-lsasl2")
      else()
        set(with_sasl_default OFF)
      endif()
    endif()
  endif()
endif()
option(WITH_SASL "With SASL" ${with_sasl_default})
if(WITH_SASL)
  if(WITH_SSL)
    set(WITH_SASL_SCRAM ON)
    set(WITH_SASL_OAUTHBEARER ON)
    list(APPEND BUILT_WITH "SASL_SCRAM SASL_OAUTHBEARER")
  endif()
  if(NOT WIN32)
    set(WITH_SASL_CYRUS ON)
    list(APPEND BUILT_WITH "SASL_CYRUS")
  endif()
endif()
# }

# LZ4 {
option(ENABLE_LZ4_EXT "Enable external LZ4 library support" ON)
set(WITH_LZ4_EXT OFF)
if(ENABLE_LZ4_EXT)
  find_package(LZ4)
  if(LZ4_FOUND)
    set(WITH_LZ4_EXT ON)
    list(APPEND BUILT_WITH "LZ4_EXT")
  else()
    message(STATUS "Using bundled LZ4 implementation.")
  endif()
endif()
# }

option(RDKAFKA_BUILD_STATIC "Build static rdkafka library" OFF)
option(RDKAFKA_BUILD_EXAMPLES "Build examples" ON)
option(RDKAFKA_BUILD_TESTS "Build tests" ON)
if(WIN32)
    option(WITHOUT_WIN32_CONFIG "Avoid including win32_config.h on cmake builds" ON)
endif(WIN32)

# In:
# * TRYCOMPILE_SRC_DIR
# Out:
# * HAVE_ATOMICS_32
# * HAVE_ATOMICS_32_SYNC
# * HAVE_ATOMICS_64
# * HAVE_ATOMICS_64_SYNC
# * HAVE_REGEX
# * HAVE_STRNDUP
# * HAVE_PTHREAD_SETNAME_GNU
# * HAVE_PTHREAD_SETNAME_DARWIN
# * WITH_C11THREADS
# * WITH_CRC32C_HW
# * LINK_ATOMIC
include("packaging/cmake/try_compile/rdkafka_setup.cmake")
if(WITH_C11THREADS)
  list(APPEND BUILT_WITH "C11THREADS")
endif()
if(WITH_CRC32C_HW)
  list(APPEND BUILT_WITH "CRC32C_HW")
endif()

set(GENERATED_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")

# In:
# * WITHOUT_OPTIMIZATION
# * ENABLE_DEVEL
# * ENABLE_REFCNT_DEBUG
# * ENABLE_SHAREDPTR_DEBUG
# * HAVE_ATOMICS_32
# * HAVE_ATOMICS_32_SYNC
# * HAVE_ATOMICS_64
# * HAVE_ATOMICS_64_SYNC
# * WITH_ZLIB
# * WITH_SSL
# * WITH_SASL
# * HAVE_REGEX
# * HAVE_STRNDUP
# * HAVE_PTHREAD_SETNAME_GNU
# * HAVE_PTHREAD_SETNAME_DARWIN
list(APPEND BUILT_WITH "SNAPPY")
list(APPEND BUILT_WITH "SOCKEM")
string(REPLACE ";" " " BUILT_WITH "${BUILT_WITH}")
configure_file("packaging/cmake/config.h.in" "${GENERATED_DIR}/config.h")

# Installation (https://github.com/forexample/package-example) {

include(GNUInstallDirs)

set(config_install_dir "lib/cmake/${PROJECT_NAME}")

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(project_version "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(targets_export_name "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

include(CMakePackageConfigHelpers)

# In:
#   * targets_export_name
#   * PROJECT_NAME
configure_package_config_file(
    "packaging/cmake/Config.cmake.in"
    "${project_config}"
    INSTALL_DESTINATION "${config_install_dir}"
)

write_basic_package_version_file(
    "${project_version}"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY AnyNewerVersion
)

install(
    FILES "${project_config}" "${project_version}" "packaging/cmake/Modules/FindLZ4.cmake"
    DESTINATION "${config_install_dir}"
)

install(
    EXPORT "${targets_export_name}"
    NAMESPACE "${namespace}"
    DESTINATION "${config_install_dir}"
)

install(
    FILES LICENSES.txt
    DESTINATION "share/licenses/librdkafka"
)

# }

add_subdirectory(src)
add_subdirectory(src-cpp)

if(RDKAFKA_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(RDKAFKA_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
