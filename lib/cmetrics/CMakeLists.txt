cmake_minimum_required(VERSION 3.20)
project(cmetrics C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# CMetrics Version
set(CMT_VERSION_MAJOR  2)
set(CMT_VERSION_MINOR  0)
set(CMT_VERSION_PATCH  2)
set(CMT_VERSION_STR "${CMT_VERSION_MAJOR}.${CMT_VERSION_MINOR}.${CMT_VERSION_PATCH}")

# Include helpers
include(cmake/macros.cmake)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

# On macOS, search Homebrew for keg-only versions of Bison and Flex. Xcode does
# not provide new enough versions for us to use.
if (CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
    execute_process(
        COMMAND brew --prefix bison
        RESULT_VARIABLE BREW_BISON
        OUTPUT_VARIABLE BREW_BISON_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (BREW_BISON EQUAL 0 AND EXISTS "${BREW_BISON_PREFIX}")
        message(STATUS "Found Bison keg installed by Homebrew at ${BREW_BISON_PREFIX}")
        set(BISON_EXECUTABLE "${BREW_BISON_PREFIX}/bin/bison")
    endif()

    execute_process(
        COMMAND brew --prefix flex
        RESULT_VARIABLE BREW_FLEX
        OUTPUT_VARIABLE BREW_FLEX_PREFIX
        OUTPUT_STRIP_TRAILING_WHITESPACE
    )
    if (BREW_FLEX EQUAL 0 AND EXISTS "${BREW_FLEX_PREFIX}")
        message(STATUS "Found Flex keg installed by Homebrew at ${BREW_FLEX_PREFIX}")
        set(FLEX_EXECUTABLE "${BREW_FLEX_PREFIX}/bin/flex")
    endif()
endif()

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(CMT_SYSTEM_WINDOWS On)
  add_definitions(-DCMT_SYSTEM_WINDOWS)

  # Disable unistd.h for flex/bison
  CMT_DEFINITION(YY_NO_UNISTD_H)
  message(STATUS "Specifying YY_NO_UNISTD_H")
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CMT_SYSTEM_MACOS On)
  add_definitions(-DCMT_SYSTEM_MACOS)
endif()

if(NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

# Define __CMT_FILENAME__ consistently across Operating Systems
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__CMT_FILENAME__='\"$$(subst ${CMAKE_SOURCE_DIR}/,,$$(abspath $$<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__CMT_FILENAME__=__FILE__")
endif()

# Configuration options
option(CMT_DEV                       "Enable development mode"                    No)
option(CMT_DEBUG                     "Enable debug mode"                          No)
option(CMT_TESTS                     "Enable unit testing"                        No)
option(CMT_INSTALL_TARGETS           "Enable subdirectory library installations" Yes)
option(CMT_PROMETHEUS_TEXT_DECODER   "Enable prometheus text format decoder (requires Flex/Bison)" Yes)

if(CMT_DEV)
  set(CMT_TESTS   Yes)
  set(CMT_DEBUG   Yes)
endif()

if(CMT_DEBUG)
  set(CMAKE_BUILD_TYPE Debug)
endif()

set(FLEX_BISON_GENERATED_DIR ${CMAKE_CURRENT_BINARY_DIR})

# Bundled libraries
include(cmake/libraries.cmake)
include(cmake/headers.cmake)

# Include headers and dependency headers
include_directories(
  src
  include
  ${FLEX_BISON_GENERATED_DIR}
  )

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" CMT_HAVE_TIMESPEC_GET)
if(CMT_HAVE_TIMESPEC_GET)
  CMT_DEFINITION(CMT_HAVE_TIMESPEC_GET)
endif()

# gmtime_r() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_r(&tms.tv_sec, &tm);
  }" CMT_HAVE_GMTIME_R)
if(CMT_HAVE_GMTIME_R)
  CMT_DEFINITION(CMT_HAVE_GMTIME_R)
endif()

# gmtime_s() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_s(&tm, &tms.tv_sec);
  }" CMT_HAVE_GMTIME_S)
if(CMT_HAVE_GMTIME_S)
  CMT_DEFINITION(CMT_HAVE_GMTIME_S)
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
  }" CMT_HAVE_CLOCK_GET_TIME)
if(CMT_HAVE_CLOCK_GET_TIME)
  CMT_DEFINITION(CMT_HAVE_CLOCK_GET_TIME)
endif()

# FIXME: MessagePack support
check_c_source_compiles("
  #include \"../../../lib/msgpack-c/include/msgpack.h\"
  int main() {
     msgpack_packer pck;
     msgpack_sbuffer sbuf;
     return 0;
  }" CMT_HAVE_MSGPACK)

if(CMT_PROMETHEUS_TEXT_DECODER)
    # Flex and Bison: check if the variables has not been defined before by
    # a parent project to avoid conflicts.
    if(NOT FLEX_FOUND)
      find_package(FLEX 2)
    endif()

    if(NOT BISON_FOUND)
      find_package(BISON 3)
    endif()

    if(FLEX_FOUND AND BISON_FOUND)
        set(CMT_BUILD_PROMETHEUS_TEXT_DECODER 1)
        CMT_DEFINITION(CMT_HAVE_PROMETHEUS_TEXT_DECODER)
    endif()
endif()

# Check if 'C Floppy' library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <cfl/cfl_found.h>
  int main() {
     return cfl_found();
  }" CMT_HAVE_CFL)
if(CMT_HAVE_CFL)
  CMT_DEFINITION(CMT_HAVE_CFL)
  message(STATUS "CFL found in the system. OK")
endif()

# Check if fluent-otel-proto library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <fluent-otel-proto/fluent-otel_found.h>
  int main() {
     return fluent_otel_found();
  }" CMT_HAVE_FLUENT_OTEL_PROTO)
if(CMT_HAVE_FLUENT_OTEL_PROTO)
  CMT_DEFINITION(CMT_HAVE_FLUENT_OTEL_PROTO)
endif()

# Configure header files
configure_file(
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/cmetrics/cmt_version.h"
  )

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMT_INSTALL_LIBDIR "lib")
  set(CMT_INSTALL_INCLUDEDIR "include")
else()
  set(CMT_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  set(CMT_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# mpack
if(NOT TARGET mpack-static)
  include_directories(lib/mpack/src/)
  add_subdirectory(lib/mpack EXCLUDE_FROM_ALL)

  if (CMT_INSTALL_TARGETS)
    install(TARGETS mpack-static
      RUNTIME DESTINATION ${CMT_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMT_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMT_INSTALL_LIBDIR}
      COMPONENT library)

    install(FILES lib/mpack/src/mpack/mpack.h
      DESTINATION ${CMT_INSTALL_INCLUDEDIR}/mpack
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
  endif()
endif()

# C Floppy
if (NOT CMT_HAVE_CFL)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CMT_PATH_LIB_CFL}/include)
  add_subdirectory(lib/cfl)
  CMT_DEFINITION(CMT_HAVE_CFL)
  CMT_DEFINITION(CMT_HAVE_CFL_INTERNAL)
  if (CMT_INSTALL_TARGETS)
    file(GLOB bundledCFLHeaders "lib/cfl/include/cfl/*.h")
    install(FILES ${bundledCFLHeaders}
      DESTINATION ${CMT_INSTALL_INCLUDEDIR}/cfl
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS cfl-static
      RUNTIME DESTINATION ${CMT_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMT_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMT_INSTALL_LIBDIR}
      COMPONENT library)

    # xxHash
    install(FILES lib/cfl/lib/xxhash/xxh3.h
      DESTINATION ${CMT_INSTALL_INCLUDEDIR}
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
    install(FILES lib/cfl/lib/xxhash/xxhash.h
      DESTINATION ${CMT_INSTALL_INCLUDEDIR}
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS xxhash
      RUNTIME DESTINATION ${CMT_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMT_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMT_INSTALL_LIBDIR}
      COMPONENT library)
  endif()
endif()

# fluent-otel-proto
if (NOT CMT_HAVE_FLUENT_OTEL_PROTO)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CMT_PATH_LIB_FLUENT_OTEL_PROTO}/include)
  CMT_OPTION(FLUENT_PROTO_METRICS   "on")
  CMT_OPTION(FLUENT_PROTO_EXAMPLES "off")
  add_subdirectory(lib/fluent-otel-proto)
  CMT_DEFINITION(CMT_HAVE_FLUENT_OTEL_PROTO)
  CMT_DEFINITION(CMT_HAVE_FLUENT_OTEL_PROTO_INTERNAL)
  if (CMT_INSTALL_TARGETS)
    file(GLOB bundledOTELProtoHeaders "lib/fluent-otel-proto/include/fluent-otel-proto/*.h")
    install(FILES ${bundledOTELProtoHeaders}
      DESTINATION ${CMT_INSTALL_INCLUDEDIR}/fluent-otel-proto
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)

    install(TARGETS fluent-otel-proto
      RUNTIME DESTINATION ${CMT_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CMT_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CMT_INSTALL_LIBDIR}
      COMPONENT library)
  endif()
endif()

# Source code
add_subdirectory(include)
add_subdirectory(src)

# Tests
if(CMT_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${CMT_VERSION_STR})
set(CPACK_PACKAGE_NAME "cmetrics")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@calyptia.com>")
set(CPACK_PACKAGE_VENDOR "Calyptia")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(CMT_SYSTEM_WINDOWS)
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
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "cmetrics")
endif()

# CPack: macOS w/ productbuild
if(CMT_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CMT_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CMT_VERSION_STR}-intel)
  else()
    set(CMETRICS_PKG ${CMAKE_CURRENT_BINARY_DIR}/${CPACK_PACKAGE_NAME}-${CMT_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(cpack/macos/welcome.txt.cmakein ${CMAKE_CURRENT_SOURCE_DIR}/welcome.txt)
    configure_file(LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_CURRENT_SOURCE_DIR}/README.md" -output "${CMAKE_CURRENT_SOURCE_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${CMETRICS_PKG}")
    set(CPACK_RESOURCE_FILE_WELCOME ${CMAKE_CURRENT_SOURCE_DIR}/welcome.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CMAKE_CURRENT_SOURCE_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "com.calyptia.${CPACK_PACKAGE_NAME}")
  endif()
endif()

# Create tarball
add_custom_target(tarball COMMAND "bash" "${CMAKE_CURRENT_SOURCE_DIR}/create-submoduled-tarball.sh" "cmetrics-${CMT_VERSION_STR}")

include(CPack)
