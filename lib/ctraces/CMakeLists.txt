cmake_minimum_required(VERSION 3.20)
project(ctraces C)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Include helpers
include(cmake/macros.cmake)
include(CheckCSourceCompiles)
include(GNUInstallDirs)

# Define macro to identify Windows system (without Cygwin)
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  set(CTR_SYSTEM_WINDOWS On)
  add_definitions(-DCTR_SYSTEM_WINDOWS)
endif()

# Define macro to identify macOS system
if(CMAKE_SYSTEM_NAME MATCHES "Darwin")
  set(CTR_SYSTEM_MACOS On)
  add_definitions(-DCTR_SYSTEM_MACOS)
endif()

if(NOT MSVC)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
endif()

# CTraces Version
set(CTR_VERSION_MAJOR  0)
set(CTR_VERSION_MINOR  7)
set(CTR_VERSION_PATCH  0)
set(CTR_VERSION_STR "${CTR_VERSION_MAJOR}.${CTR_VERSION_MINOR}.${CTR_VERSION_PATCH}")

# Define __FILENAME__ consistently across Operating Systems
if(NOT ${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__='\"$$(subst ${CMAKE_SOURCE_DIR}/,,$$(abspath $$<))\"'")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D__FILENAME__=__FILE__")
endif()

# Configuration options
option(CTR_DEV             "Enable development mode"                   No)
option(CTR_TESTS           "Enable unit testing"                       No)
option(CTR_EXAMPLES        "Build example binaries"                    No)
option(CTR_INSTALL_TARGETS "Enable subdirectory library installations" Yes)

if(CTR_DEV)
  set(CTR_TESTS        Yes)
  set(CTR_EXAMPLES     Yes)
  set(CMAKE_BUILD_TYPE Debug)
endif()

# Bundled libraries
include(cmake/libraries.cmake)
include(cmake/headers.cmake)

# Include headers and dependency headers
include_directories(
  src
  include
  lib/monkey/include
  )

# timespec_get() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     return timespec_get(&tm, TIME_UTC);
  }" CTR_HAVE_TIMESPEC_GET)
if(CTR_HAVE_TIMESPEC_GET)
  CTR_DEFINITION(CTR_HAVE_TIMESPEC_GET)
endif()

# gmtime_r() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_r(&tms.tv_sec, &tm);
  }" CTR_HAVE_GMTIME_R)
if(CTR_HAVE_GMTIME_R)
  CTR_DEFINITION(CTR_HAVE_GMTIME_R)
endif()

# gmtime_s() support
check_c_source_compiles("
  #include <time.h>
  int main() {
     struct tm tm;
     struct timespec tms;
     return gmtime_s(&tm, &tms.tv_sec);
  }" CTR_HAVE_GMTIME_S)
if(CTR_HAVE_GMTIME_S)
  CTR_DEFINITION(CTR_HAVE_GMTIME_S)
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
  }" CTR_HAVE_CLOCK_GET_TIME)
if(CTR_HAVE_CLOCK_GET_TIME)
  CTR_DEFINITION(CTR_HAVE_CLOCK_GET_TIME)
endif()

# getrandom()
check_c_source_compiles("
  #include <sys/random.h>
  int main() {
      unsigned int tmp;
      getrandom(tmp, sizeof(tmp), GRND_NONBLOCK);
      return 0;
  }" CTR_HAVE_GETRANDOM)
if(CTR_HAVE_GETRANDOM)
  CTR_DEFINITION(CTR_HAVE_GETRANDOM)
endif()


# FIXME: MessagePack support
check_c_source_compiles("
  #include \"../../../lib/msgpack-c/include/msgpack.h\"
  int main() {
     msgpack_packer pck;
     msgpack_sbuffer sbuf;
     return 0;
  }" CTR_HAVE_MSGPACK)

# Check if 'C Floppy' library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <cfl/cfl_found.h>
  int main() {
     return cfl_found();
  }" CTR_HAVE_CFL)
if(CTR_HAVE_CFL)
  CTR_DEFINITION(CTR_HAVE_CFL)
endif()

# Check if fluent-otel-proto library is available in the environment, if not,
# we will try to build a local copy at a later stage
check_c_source_compiles("
  #include <fluent-otel-proto/fluent-otel_found.h>
  int main() {
     return fluent_otel_found();
  }" CTR_HAVE_FLUENT_OTEL_PROTO)
if(CTR_HAVE_FLUENT_OTEL_PROTO)
  CTR_DEFINITION(CTR_HAVE_FLUENT_OTEL_PROTO)
endif()

configure_file(
  "${PROJECT_SOURCE_DIR}/include/ctraces/ctr_info.h.in"
  "${PROJECT_SOURCE_DIR}/include/ctraces/ctr_info.h"
  )

configure_file(
  "${PROJECT_SOURCE_DIR}/include/ctraces/ctr_version.h.in"
  "${PROJECT_SOURCE_DIR}/include/ctraces/ctr_version.h"
  )

# Installation Directories
# ========================
if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
  set(CTR_INSTALL_LIBDIR "lib")
  set(CTR_INSTALL_INCLUDEDIR "include")
else()
  set(CTR_INSTALL_LIBDIR "${CMAKE_INSTALL_PREFIX}/${CMAKE_INSTALL_LIBDIR}")
  set(CTR_INSTALL_INCLUDEDIR "${CMAKE_INSTALL_PREFIX}/include")
endif()

# mpack
if(NOT TARGET mpack-static)
  include_directories(lib/mpack/src/)
  add_subdirectory(lib/mpack EXCLUDE_FROM_ALL)

  if (CTR_INSTALL_TARGETS)
    install(TARGETS mpack-static
      RUNTIME DESTINATION ${CTR_INSTALL_BINDIR}
      LIBRARY DESTINATION ${CTR_INSTALL_LIBDIR}
      ARCHIVE DESTINATION ${CTR_INSTALL_LIBDIR}
      COMPONENT library)

    install(FILES lib/mpack/src/mpack/mpack.h
      DESTINATION ${CTR_INSTALL_INCLUDEDIR}/mpack
      COMPONENT headers
      PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ)
  endif()
endif()

# C Floppy
if (NOT CTR_HAVE_CFL)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CTR_PATH_LIB_CFL}/include)
  add_subdirectory(lib/cfl)
  CTR_DEFINITION(CTR_HAVE_CFL)
  CTR_DEFINITION(CTR_HAVE_CFL_INTERNAL)
endif()

# fluent-otel-proto
if (NOT CTR_HAVE_FLUENT_OTEL_PROTO)
  include_directories(${CMAKE_CURRENT_SOURCE_DIR}/${CTR_PATH_LIB_FLUENT_OTEL_PROTO}/include)
  CTR_OPTION(FLUENT_PROTO_EXAMPLES "off")
  add_subdirectory(lib/fluent-otel-proto)
  CTR_DEFINITION(CTR_HAVE_FLUENT_OTEL_PROTO)
  CTR_DEFINITION(CTR_HAVE_FLUENT_OTEL_PROTO_INTERNAL)
endif()

# Source code
add_subdirectory(include)
add_subdirectory(src)

# Examples
if (CTR_EXAMPLES)
  add_subdirectory(examples)
endif()

# Tests
if(CTR_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

# Output paths
set(CTRACES_ROOT "${CMAKE_CURRENT_SOURCE_DIR}")
set(CTRACES_BUILD_DIR "${CTRACES_ROOT}/build")

# Installer Generation (Cpack)
# ============================

set(CPACK_PACKAGE_VERSION ${CTR_VERSION_STR})
set(CPACK_PACKAGE_NAME "ctraces")
set(CPACK_PACKAGE_RELEASE 1)
set(CPACK_PACKAGE_CONTACT "Eduardo Silva <eduardo@calyptia.com>")
set(CPACK_PACKAGE_VENDOR "Calyptia")
set(CPACK_RESOURCE_FILE_LICENSE "${PROJECT_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGING_INSTALL_PREFIX "/")

set(CPACK_PACKAGE_FILE_NAME "${CPACK_PACKAGE_NAME}-${CPACK_PACKAGE_VERSION}-${CPACK_PACKAGE_RELEASE}.${CMAKE_SYSTEM_PROCESSOR}")

if(CTR_SYSTEM_WINDOWS)
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
  set(CPACK_PACKAGE_INSTALL_DIRECTORY "ctraces")
endif()

# CPack: macOS w/ productbuild
if(CTR_SYSTEM_MACOS)
  # Determine the platform suffix
  execute_process(
    COMMAND uname -m
    RESULT_VARIABLE UNAME_M_RESULT
    OUTPUT_VARIABLE UNAME_ARCH
    OUTPUT_STRIP_TRAILING_WHITESPACE
    )
  if (UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "arm64")
    set(CMETRICS_PKG ${CTRACES_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CTR_VERSION_STR}-apple)
  elseif(UNAME_M_RESULT EQUAL 0 AND UNAME_ARCH STREQUAL "x86_64")
    set(CMETRICS_PKG ${CTRACES_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CTR_VERSION_STR}-intel)
  else()
    set(CMETRICS_PKG ${CTRACES_BUILD_DIR}/${CPACK_PACKAGE_NAME}-${CTR_VERSION_STR}-${UNAME_ARCH})
  endif()

  if (CPACK_GENERATOR MATCHES "productbuild")
    set(CPACK_SET_DESTDIR "ON")
    configure_file(cpack/macos/welcome.txt.cmakein ${CTRACES_BUILD_DIR}/welcome.txt)
    configure_file(LICENSE ${CTRACES_BUILD_DIR}/LICENSE.txt)
    find_program(CONVERTER textutil)
    if (NOT CONVERTER)
      message(FATAL_ERROR "textutil not found.")
    endif()
    if (CONVERTER)
      execute_process(COMMAND ${CONVERTER} -convert html "${CMAKE_SOURCE_DIR}/README.md" -output "${CTRACES_BUILD_DIR}/README.html")
    endif()
    set(CPACK_PACKAGE_FILE_NAME "${CMETRICS_PKG}")
    set(CPACK_RESOURCE_FILE_WELCOME ${CTRACES_BUILD_DIR}/welcome.txt)
    set(CPACK_RESOURCE_FILE_LICENSE ${CTRACES_BUILD_DIR}/LICENSE.txt)
    set(CPACK_RESOURCE_FILE_README ${CTRACES_BUILD_DIR}/README.html)
    set(CPACK_PRODUCTBUILD_IDENTIFIER "com.calyptia.${CPACK_PACKAGE_NAME}")
  endif()
endif()

include(CPack)
