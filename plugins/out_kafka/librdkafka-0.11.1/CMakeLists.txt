cmake_minimum_required(VERSION 3.4)
project(RdKafka)

# Options. No 'RDKAFKA_' prefix to match old C++ code. {

# This option doesn't affect build in fact, only C code
# (see 'rd_kafka_version_str'). In CMake the build type feature usually used
# (like Debug, Release, etc.).
option(WITHOUT_OPTIMIZATION "Disable optimization" OFF)

option(ENABLE_DEVEL "Enable development asserts, checks, etc" OFF)
option(ENABLE_REFCNT_DEBUG "Enable refcnt debugging" OFF)
option(ENABLE_SHAREDPTR_DEBUG "Enable sharedptr debugging" OFF)

# ZLIB {
find_package(ZLIB QUIET)
if(ZLIB_FOUND)
  set(with_zlib_default ON)
else()
  set(with_zlib_default OFF)
endif()
option(WITH_ZLIB "With ZLIB" ${with_zlib_default})
# }

# LibDL {
find_package(LIBDL QUIET)
if(LIBDL_FOUND)
  set(with_libdl_default ON)
else()
  set(with_libdl_default OFF)
endif()
option(WITH_LIBDL "With LibDL" ${with_libdl_default})
# }

# WITH_PLUGINS {
if(WITH_LIBDL)
  set(with_plugins_default ON)
else()
  set(with_plugins_default OFF)
endif()
option(WITH_PLUGINS "With plugin support" ${with_plugins_default})
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
# }

# SASL {
if(WIN32)
  set(with_sasl_default ON)
else()
  include(FindPkgConfig)
  pkg_check_modules(SASL QUIET libsasl2)
  if(SASL_FOUND)
    set(with_sasl_default ON)
  else()
    set(with_sasl_default OFF)
  endif()
endif()
option(WITH_SASL "With SASL" ${with_sasl_default})
if(WITH_SASL)
  if(WIN32)
    set(WITH_SASL_SCRAM ON)
  else()
    set(WITH_SASL_CYRUS ON)
  endif()
endif()
# }

# }

option(RDKAFKA_BUILD_EXAMPLES "Build examples" ON)
option(RDKAFKA_BUILD_TESTS "Build tests" ON)

set(TRYCOMPILE_SRC_DIR "${CMAKE_CURRENT_LIST_DIR}/packaging/cmake/try_compile")

# In:
# * TRYCOMPILE_SRC_DIR
# Out:
# * HAVE_ATOMICS_32
# * HAVE_ATOMICS_32_SYNC
# * HAVE_ATOMICS_64
# * HAVE_ATOMICS_64_SYNC
# * HAVE_REGEX
# * HAVE_STRNDUP
# * LINK_ATOMIC
include("packaging/cmake/try_compile/rdkafka_setup.cmake")

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
configure_file(config.h.in "${GENERATED_DIR}/config.h" @ONLY)

# Installation (https://github.com/forexample/package-example) {

include(GNUInstallDirs)

set(config_install_dir "lib/cmake/${PROJECT_NAME}")

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
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

install(
    FILES "${project_config}"
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

if(RDKAFKA_BUILD_EXAMPLES)
  add_subdirectory(examples)
endif()

if(RDKAFKA_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
