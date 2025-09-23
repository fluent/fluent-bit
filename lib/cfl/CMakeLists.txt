cmake_minimum_required(VERSION 3.20)
project(cfl C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# C Floppy Version
set(CFL_VERSION_MAJOR  0)
set(CFL_VERSION_MINOR  6)
set(CFL_VERSION_PATCH  1)
set(CFL_VERSION_STR    "${CFL_VERSION_MAJOR}.${CFL_VERSION_MINOR}.${CFL_VERSION_PATCH}")

# Configuration options
option(CFL_DEV                            "Enable development mode"                    No)
option(CFL_TESTS                          "Enable unit testing"                        No)
option(CFL_INSTALL_BUNDLED_XXHASH_HEADERS "Enable bundled xxHash headers installation" Yes)

if(CFL_DEV)
  set(CMAKE_BUILD_TYPE Debug)
  set(CFL_TESTS        On)
endif()

# Include helpers
include(cmake/macros.cmake)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(CFL_SYSTEM_WINDOWS On)
  add_definitions(-DCFL_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CFL_SYSTEM_MACOS On)
  add_definitions(-DCFL_SYSTEM_MACOS)
endif()

if(NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

# Define __FILENAME__
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")



# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" CFL_HAVE_TIMESPEC_GET)
if(CFL_HAVE_TIMESPEC_GET)
  CFL_DEFINITION(CFL_HAVE_TIMESPEC_GET)
endif()

# gmtime_r() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_r(&tms.tv_sec, &tm);
  }" CFL_HAVE_GMTIME_R)
if(CFL_HAVE_GMTIME_R)
  CFL_DEFINITION(CFL_HAVE_GMTIME_R)
endif()

# gmtime_s() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_s(&tm, &tms.tv_sec);
  }" CFL_HAVE_GMTIME_S)
if(CFL_HAVE_GMTIME_S)
  CFL_DEFINITION(CFL_HAVE_GMTIME_S)
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
  }" CFL_HAVE_CLOCK_GET_TIME)
if(CFL_HAVE_CLOCK_GET_TIME)
  CFL_DEFINITION(CFL_HAVE_CLOCK_GET_TIME)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/cfl/cfl_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/cfl/cfl_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/cfl/cfl_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/cfl/cfl_version.h"
  )

# Include headers and dependency headers
include_directories(
  lib/xxhash/
  include
  )

# xxHash
if(NOT TARGET xxhash)
  # Do something when target found
  set(XXHASH_BUILD_ENABLE_INLINE_API OFF)
  set(XXHASH_BUILD_XXHSUM OFF)
  set(BUILD_SHARED_LIBS OFF)
  add_subdirectory(lib/xxhash/cmake_unofficial EXCLUDE_FROM_ALL)
endif()

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CFL_INSTALL_BINDIR "bin")
  set(CFL_INSTALL_LIBDIR "lib")
  set(CFL_INSTALL_INCLUDEDIR "include")
else()
  set(CFL_INSTALL_BINDIR ${CMAKE_INSTALL_FULL_BINDIR})
  set(CFL_INSTALL_LIBDIR "${CMAKE_INSTALL_LIBDIR}")
  set(CFL_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# Output paths
set(CFL_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CFL_BUILD_DIR "${CFL_ROOT}/build")

# CFL sources
add_subdirectory(include)
add_subdirectory(src)

# Tests
if(CFL_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${CFL_VERSION_STR})
set(CPACK_PACKAGE_NAME "cfl")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@calyptia.com>")
set(CPACK_PACKAGE_VENDOR "Calyptia")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(CFL_SYSTEM_WINDOWS)
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
set(CPACK_PACKAGE_DESCRIPTION_SUMMARY "C Traces Library")
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
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "cfl")
endif()

# CPack: macOS w/ productbuild
if(CFL_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(CFL_PKG ${CFL_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CFL_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(CFL_PKG ${CFL_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CFL_VERSION_STR}-intel)
  else()
    set(CFL_PKG ${CFL_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CFL_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(cpack/macos/welcome.txt.cmakein ${CFL_BUILD_DIR}/welcome.txt)
    configure_file(LICENSE ${CFL_BUILD_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_SOURCE_DIR}/README.md" -output "${CFL_BUILD_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${CFL_PKG}")
    set(CPACK_RESOURCE_FILE_WELCOME ${CFL_BUILD_DIR}/welcome.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CFL_BUILD_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CFL_BUILD_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "com.calyptia.${CPACK_PACKAGE_NAME}")
  endif()
endif()

include(CPack)
