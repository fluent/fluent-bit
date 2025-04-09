cmake_minimum_required(VERSION 3.20)
project(cprofiles C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMetrics Version
set(CPROF_VERSION_MAJOR  0)
set(CPROF_VERSION_MINOR  1)
set(CPROF_VERSION_PATCH  1)
set(CPROF_VERSION_STR "${CPROF_VERSION_MAJOR}.${CPROF_VERSION_MINOR}.${CPROF_VERSION_PATCH}")

# Include helpers
include(cmake/macros.cmake)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(CPROF_SYSTEM_WINDOWS On)
  add_definitions(-DCPROF_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CPROF_SYSTEM_MACOS On)
  add_definitions(-DCPROF_SYSTEM_MACOS)
endif()

if(NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

# Define __CPROF_FILENAME__ consistently across Operating Systems
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__CPROF_FILENAME__='\"$$(subst ${CMAKE_SOURCE_DIR}/,,$$(abspath $$<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__CPROF_FILENAME__=__FILE__")
endif()

# Configuration options
option(CPROF_DEV                       "Enable development mode"                    No)
option(CPROF_DEBUG                     "Enable debug mode"                          No)
option(CPROF_TESTS                     "Enable unit testing"                        No)
option(CPROF_INSTALL_TARGETS           "Enable subdirectory library installations" Yes)

if(CPROF_DEV)
  set(CPROF_TESTS   Yes)
  set(CPROF_DEBUG   Yes)
endif()

if(CPROF_DEBUG)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Bundled libraries
include(cmake/libraries.cmake)
include(cmake/headers.cmake)

# Include headers and dependency headers
include_directories(
  src
  include
  )

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" CPROF_HAVE_TIMESPEC_GET)
if(CPROF_HAVE_TIMESPEC_GET)
  CPROF_DEFINITION(CPROF_HAVE_TIMESPEC_GET)
endif()

# gmtime_r() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_r(&tms.tv_sec, &tm);
  }" CPROF_HAVE_GMTIME_R)
if(CPROF_HAVE_GMTIME_R)
  CPROF_DEFINITION(CPROF_HAVE_GMTIME_R)
endif()

# gmtime_s() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_s(&tm, &tms.tv_sec);
  }" CPROF_HAVE_GMTIME_S)
if(CPROF_HAVE_GMTIME_S)
  CPROF_DEFINITION(CPROF_HAVE_GMTIME_S)
endif()

# clock_get_time() support for macOS.
check_c_source_compiles("
  #include <mach/clock.h>
  #include <mach/mach.h>
  int main() {
      clock_serv_t cclock;
      mach_timespec_t mts;
      host_get_clock_service(mach_host_self(), CALENDAR_CLOCK, &cclock);
      clock_get_time(cclock, &mts);
      return mach_port_deallocate(mach_task_self(), cclock);
  }" CPROF_HAVE_CLOCK_GET_TIME)
if(CPROF_HAVE_CLOCK_GET_TIME)
  CPROF_DEFINITION(CPROF_HAVE_CLOCK_GET_TIME)
endif()

# Check if 'C Floppy' library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <cfl/cfl_found.h>
  int main() {
     return cfl_found();
  }" CPROF_HAVE_CFL)
if(CPROF_HAVE_CFL)
  CPROF_DEFINITION(CPROF_HAVE_CFL)
  message(STATUS "CFL found in the system. OK")
endif()

# Check if fluent-otel-proto library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <fluent-otel-proto/fluent-otel_found.h>
  int main() {
     return fluent_otel_found();
  }" CPROF_HAVE_FLUENT_OTEL_PROTO)
if(CPROF_HAVE_FLUENT_OTEL_PROTO)
  CPROF_DEFINITION(CPROF_HAVE_FLUENT_OTEL_PROTO)
endif()

# Configure header files
configure_file(
  "${PROJECT_SOURCE_DIR}/include/cprofiles/cprof_info.h.in"
  "${PROJECT_BINARY_DIR}/include/cprofiles/cprof_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/cprofiles/cprof_version.h.in"
  "${PROJECT_BINARY_DIR}/include/cprofiles/cprof_version.h"
  )

include_directories("${PROJECT_BINARY_DIR}/include/")

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CPROF_INSTALL_LIBDIR "lib")
  set(CPROF_INSTALL_INCLUDEDIR "include")
else()
  set(CPROF_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  set(CPROF_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# mpack
if(NOT TARGET mpack-static)
  include_directories(lib/mpack/src/)
  add_subdirectory(lib/mpack EXCLUDE_FROM_ALL)

  if (CPROF_INSTALL_TARGETS)
    install(TARGETS mpack-static
      RUNTIME DESTINATION ${CPROF_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CPROF_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CPROF_INSTALL_LIBDIR}
      COMPONENT library)

    install(FILES lib/mpack/src/mpack/mpack.h
      DESTINATION ${CPROF_INSTALL_INCLUDEDIR}/mpack
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
  endif()
endif()

# C Floppy
if (NOT CPROF_HAVE_CFL)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CPROF_PATH_LIB_CFL}/include)
  add_subdirectory(lib/cfl)
  CPROF_DEFINITION(CPROF_HAVE_CFL)
  CPROF_DEFINITION(CPROF_HAVE_CFL_INTERNAL)
  if (CPROF_INSTALL_TARGETS)
    file(GLOB bundledCFLHeaders "lib/cfl/include/cfl/*.h")
    install(FILES ${bundledCFLHeaders}
      DESTINATION ${CPROF_INSTALL_INCLUDEDIR}/cfl
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS cfl-static
      RUNTIME DESTINATION ${CPROF_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CPROF_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CPROF_INSTALL_LIBDIR}
      COMPONENT library)

    # xxHash
    install(FILES lib/cfl/lib/xxhash/xxh3.h
      DESTINATION ${CPROF_INSTALL_INCLUDEDIR}
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(FILES lib/cfl/lib/xxhash/xxhash.h
      DESTINATION ${CPROF_INSTALL_INCLUDEDIR}
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS xxhash
      RUNTIME DESTINATION ${CPROF_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CPROF_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CPROF_INSTALL_LIBDIR}
      COMPONENT library)
  endif()
endif()

# fluent-otel-proto
if (NOT CPROF_HAVE_FLUENT_OTEL_PROTO)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CPROF_PATH_LIB_FLUENT_OTEL_PROTO}/include)
  CPROF_OPTION(FLUENT_PROTO_PROFILES "on")
  CPROF_OPTION(FLUENT_PROTO_EXAMPLES "off")
  add_subdirectory(lib/fluent-otel-proto)
  CPROF_DEFINITION(CPROF_HAVE_FLUENT_OTEL_PROTO)
  CPROF_DEFINITION(CPROF_HAVE_FLUENT_OTEL_PROTO_INTERNAL)
  if (CPROF_INSTALL_TARGETS)
    file(GLOB bundledOTELProtoHeaders "lib/fluent-otel-proto/include/fluent-otel-proto/*.h")
    install(FILES ${bundledOTELProtoHeaders}
      DESTINATION ${CPROF_INSTALL_INCLUDEDIR}/fluent-otel-proto
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS fluent-otel-proto
      RUNTIME DESTINATION ${CPROF_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CPROF_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CPROF_INSTALL_LIBDIR}
      COMPONENT library)
  endif()
endif()

# Source code
add_subdirectory(include)
add_subdirectory(src)

# Tests
if(CPROF_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${CPROFILES_VERSION_STR})
set(CPACK_PACKAGE_NAME "cprofiles")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@calyptia.com>")
set(CPACK_PACKAGE_VENDOR "Calyptia")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(CPROF_SYSTEM_WINDOWS)
  set(CPACK_GENERATOR "ZIP")

  if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win64")
  else()
    set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-win32")
  endif()
endif()


# Enable components
set(CPACK_DEB_COMPONENT_INSTALL ON)
set(CPACK_RPM_COMPONENT_INSTALL ON)
set(CPACK_productbuild_COMPONENT_INSTALL ON)
set(CPACK_COMPONENTS_ALL ${CPACK_COMPONENTS_ALL} binary library headers)
set(CPACK_COMPONENTS_GROUPING "ONE_PER_GROUP")

set(CPACK_COMPONENT_BINARY_GROUP "RUNTIME")
set(CPACK_COMPONENT_LIBRARY_GROUP "RUNTIME")

# Debian package setup and name sanitizer
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

find_program(DPKG_PROGRAM dpkg DOC "dpkg program of Debian-based systems")
if(DPKG_PROGRAM)
  execute_process(
    COMMAND ${DPKG_PROGRAM} --print-architecture
    OUTPUT_VARIABLE CPACK_DEBIAN_PACKAGE_ARCHITECTURE
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )

  set(CPACK_DEBIAN_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}-headers.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
  set(CPACK_DEBIAN_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}_${CPACK_PACKAGE_VERSION}_${CPACK_DEBIAN_PACKAGE_ARCHITECTURE}.deb")
  set(CPACK_DEBIAN_RUNTIME_PACKAGE_CONTROL_EXTRA
    ${CMAKE_CURRENT_SOURCE_DIR}/debian/conffiles
    )
endif()

# RPM Generation information
set(CPACK_RPM_PACKAGE_GROUP "System Environment/Daemons")
set(CPACK_RPM_PACKAGE_LICENSE "Apache v2.0")
set(CPACK_RPM_PACKAGE_RELEASE ${CPACK_PACKAGE_RELEASE})
set(CPACK_PACKAGE_DESCRIPTION_FILE "${PROJECT_SOURCE_DIR}/cpack/description")
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "A standalone library to create and manipulate metrics in C")
set(CPACK_RPM_SPEC_MORE_DEFINE "%define ignore \#")
set(CPACK_RPM_USER_FILELIST
  "%ignore /lib"
  "%ignore /lib64"
  "%ignore /lib64/pkgconfig"
  "%ignore /usr/local"
  "%ignore /usr/local/bin")

set(CPACK_RPM_PACKAGE_AUTOREQ ON)
set(CPACK_RPM_RUNTIME_PACKAGE_NAME "${CPACK_PACKAGE_NAME}")
set(CPACK_RPM_HEADERS_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}-headers.rpm")
set(CPACK_RPM_RUNTIME_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}.rpm")

# CPack: DEB
set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)

# CPack: Windows System
if(CPACK_GENERATOR MATCHES "ZIP")
  set(CPACK_MONOLITHIC_INSTALL 1)
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "cprofiles")
endif()

# CPack: macOS w/ productbuild
if(CPROF_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CPROF_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CPROF_VERSION_STR}-intel)
  else()
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CPROF_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_CURRENT_SOURCE_DIR}/README.md" -output "${CMAKE_CURRENT_SOURCE_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${CMETRICS_PKG}")
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "com.calyptia.${CPACK_PACKAGE_NAME}")
  endif()
endif()

# Create tarball
add_custom_target(cprofiles_tarball COMMAND "bash" "${CMAKE_CURRENT_SOURCE_DIR}/create-submoduled-tarball.sh" "cprofiles-${CPROF_VERSION_STR}")

include(CPack)
