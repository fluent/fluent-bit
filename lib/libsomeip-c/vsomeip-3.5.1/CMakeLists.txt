# Copyright (C) 2015-2023 Bayerische Motoren Werke Aktiengesellschaft (BMW AG)
# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at http://mozilla.org/MPL/2.0/.

cmake_minimum_required (VERSION 3.13)
project (vsomeip)

set (VSOMEIP_NAME vsomeip3)
set (VSOMEIP_COMPAT_NAME vsomeip)

set (VSOMEIP_MAJOR_VERSION 3)
set (VSOMEIP_MINOR_VERSION 5)
set (VSOMEIP_PATCH_VERSION 1)
set (VSOMEIP_HOTFIX_VERSION 0)

set (VSOMEIP_VERSION ${VSOMEIP_MAJOR_VERSION}.${VSOMEIP_MINOR_VERSION}.${VSOMEIP_PATCH_VERSION})
set (PACKAGE_VERSION ${VSOMEIP_VERSION}) # Used in documentation/doxygen.in
set (CMAKE_VERBOSE_MAKEFILE off)

if (NOT GTEST_ROOT)
    if (DEFINED ENV{GTEST_ROOT})
        set(GTEST_ROOT $ENV{GTEST_ROOT})
    else()
        set(GTEST_ROOT "n/a" CACHE STRING "Path to root folder of googletest. Must be set for building the tests.")
    endif()
endif()

###################################################################################################
# see http://www.cmake.org/Wiki/CMake/Tutorials/How_to_create_a_ProjectConfig.cmake_file
###################################################################################################

# Offer the user the choice of overriding the installation directories
set (INSTALL_LIB_DIR lib CACHE PATH "Installation directory for libraries")
set (INSTALL_BIN_DIR bin CACHE PATH "Installation directory for executables")
set (INSTALL_INCLUDE_DIR include CACHE PATH "Installation directory for header files")

if (WIN32 AND NOT CYGWIN)
    set (DEF_INSTALL_CMAKE_DIR CMake)
else ()
    set (DEF_INSTALL_CMAKE_DIR lib/cmake/${VSOMEIP_NAME})
endif ()

set (INSTALL_CMAKE_DIR ${DEF_INSTALL_CMAKE_DIR} CACHE PATH "Installation directory for CMake files")

# Make relative paths absolute (needed later on)
foreach (p LIB BIN INCLUDE CMAKE)
    set (var INSTALL_${p}_DIR)
    if (NOT IS_ABSOLUTE "${${var}}")
        set (ABSOLUTE_${var} "${CMAKE_INSTALL_PREFIX}/${${var}}") # Add all targets to the build-tree export set
    endif ()
endforeach ()

###################################################################################################
# Set a default build type if none was specified
set(default_build_type "RelWithDebInfo")
if(NOT CMAKE_BUILD_TYPE)
  message(STATUS "Setting build type to '${default_build_type}' as none was specified.")
  set(CMAKE_BUILD_TYPE "${default_build_type}" CACHE STRING "Choose the type of build." FORCE)
  # Set the possible values of build type for cmake-gui
  set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS "Debug" "Release" "MinSizeRel" "RelWithDebInfo")
endif()

set(CMAKE_CXX_STANDARD 17)

# OS
if (${CMAKE_SYSTEM_NAME} MATCHES "Linux")
    set(DL_LIBRARY "dl")

if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    # This is only relevant for GCC and causes warnings on Clang
    set(EXPORTSYMBOLS "-Wl,-export-dynamic -Wl,--version-script=${CMAKE_CURRENT_SOURCE_DIR}/exportmap.gcc")
    set(OS_CXX_FLAGS "${OS_CXX_FLAGS} -pie -Wno-tsan -Wl,-z,relro,-z,now")
endif()

    set(NO_DEPRECATED "")
    set(OPTIMIZE "")
  if(NOT DEFINED _FORTIFY_SOURCE)
      set(_FORTIFY_SOURCE 2)
  endif()
    set(OS_CXX_FLAGS "${OS_CXX_FLAGS} -D_GLIBCXX_USE_NANOSLEEP -pthread -O -Wall -Wextra -Wformat -Wformat-security -Wconversion -fexceptions -fstrict-aliasing -fstack-protector-strong -fasynchronous-unwind-tables -fno-omit-frame-pointer -D_FORTIFY_SOURCE=${_FORTIFY_SOURCE} -Wformat -Wformat-security -Wpedantic -Werror -fPIE")

    # force all use of std::mutex and std::recursive_mutex to use runtime init
    # instead of static initialization so mutexes can be hooked to enable PI as needed
    add_definitions(-D_GTHREAD_USE_MUTEX_INIT_FUNC -D_GTHREAD_USE_RECURSIVE_MUTEX_INIT_FUNC)
endif (${CMAKE_SYSTEM_NAME} MATCHES "Linux")

if (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")
    set(DL_LIBRARY "")
    set(EXPORTSYMBOLS "")
    set(NO_DEPRECATED "-Wno-deprecated")
    set(OPTIMIZE "")
    set(OS_CXX_FLAGS "-pthread")
endif (${CMAKE_SYSTEM_NAME} MATCHES "FreeBSD")

############################################My lib link flags####################################
# Options
################################################################################

# DLT
if (DISABLE_DLT)
set (VSOMEIP_ENABLE_DLT 0)
else ()
set (VSOMEIP_ENABLE_DLT 1)
endif ()

# Signal handling
if (ENABLE_SIGNAL_HANDLING)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_ENABLE_SIGNAL_HANDLING")
endif ()

# Event caching
if (ENABLE_DEFAULT_EVENT_CACHING)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_ENABLE_DEFAULT_EVENT_CACHING")
endif ()

if (NOT MSVC)
    # Sanitizers
    if (ENABLE_UNDEFINED_SANITIZER)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=undefined")
    endif ()

    if (ENABLE_THREAD_SANITIZER)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=thread")
    endif ()

    if (ENABLE_LEAK_SANITIZER)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=leak")
    endif ()

    if (ENABLE_ADDRESS_SANITIZER)
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fsanitize=address")
    endif ()

    if (ENABLE_PROFILING)
        set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -pg")
    endif ()

    # Valgrind
    find_program(VALGRIND "valgrind")
    if (VALGRIND)
        if (DEFINED VALGRIND_TYPE AND NOT VALGRIND_TYPE STREQUAL "")
            set(TEST_ENTRYPOINT ${VALGRIND} --tool=${VALGRIND_TYPE})
        endif ()

        if (VALGRIND_TYPE STREQUAL "helgrind")
            set(TEST_ENTRYPOINT ${TEST_ENTRYPOINT} --suppressions=${VALGRIND_SUPPRESS_FILE} --gen-suppressions=all --log-file=${VALGRIND_LOGS_DIR}/test_name.out)
        endif ()

        if (VALGRIND_TYPE STREQUAL "massif")
            set(TEST_ENTRYPOINT ${TEST_ENTRYPOINT} --massif-out-file=${VALGRIND_LOGS_DIR}/test_name.out)
        endif ()

        if (VALGRIND_TYPE STREQUAL "memcheck")
            set(TEST_ENTRYPOINT ${TEST_ENTRYPOINT} --leak-check=yes --suppressions=${VALGRIND_SUPPRESS_FILE} --log-file=${VALGRIND_LOGS_DIR}/test_name.out)
        endif ()
    endif ()
endif (NOT MSVC)

# Compatibility
if (ENABLE_COMPAT)
set (VSOMEIP_ENABLE_COMPAT 1)
else ()
set (VSOMEIP_ENABLE_COMPAT 0)
endif ()

# Multiple routing managers
if (ENABLE_MULTIPLE_ROUTING_MANAGERS)
set (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS 1)
else ()
set (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS 0)
endif ()

# Security / Policy handling
if (DISABLE_SECURITY)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_DISABLE_SECURITY")
endif ()

# Suppress deprecation warnings for vSomeIP interfaces
add_definitions(-DVSOMEIP_INTERNAL_SUPPRESS_DEPRECATED)

################################################################################
# Dependencies
################################################################################

# Threads
find_package(Threads REQUIRED)

# Boost
find_package( Boost 1.66 COMPONENTS system thread filesystem REQUIRED )
if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    include_directories(${Boost_INCLUDE_DIR} )
else()
    include_directories(SYSTEM ${Boost_INCLUDE_DIR} )
endif()

if(Boost_FOUND)
  if(Boost_LIBRARY_DIR)
    MESSAGE( STATUS "Boost_LIBRARY_DIR not empty using it: ${Boost_LIBRARY_DIR}" )
  else()
    if(BOOST_LIBRARYDIR)
      MESSAGE( STATUS "Boost_LIBRARY_DIR empty but BOOST_LIBRARYDIR is set setting Boost_LIBRARY_DIR to: ${BOOST_LIBRARYDIR}" )
      set(Boost_LIBRARY_DIR ${BOOST_LIBRARYDIR})
    endif()
  endif()
else()
  MESSAGE( STATUS "Boost was not found!")
endif()

# cmake 3.15 introduced a new variable and a new format for the old one
if (DEFINED Boost_VERSION_MACRO)
  set(VSOMEIP_BOOST_VERSION ${Boost_VERSION_MACRO})
else()
  set(VSOMEIP_BOOST_VERSION ${Boost_VERSION})
endif()

message( STATUS "Using boost version: ${VSOMEIP_BOOST_VERSION}" )

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_BOOST_VERSION=${VSOMEIP_BOOST_VERSION}")

find_package(PkgConfig)

# DLT
if(VSOMEIP_ENABLE_DLT EQUAL 1)
pkg_check_modules(DLT "automotive-dlt >= 2.11")
if(DLT_FOUND)
     set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DUSE_DLT")
endif(DLT_FOUND)
endif()

# SystemD
pkg_check_modules(SystemD "libsystemd")

if(NOT SystemD_FOUND)
MESSAGE( STATUS "Systemd was not found, watchdog disabled!")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWITHOUT_SYSTEMD")
endif(NOT SystemD_FOUND)

# Multiple routing managers
if (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS EQUAL 1)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS")
endif ()

################################################################################
# Directories
################################################################################

include_directories(
    interface
)

include_directories(SYSTEM
    ${DLT_INCLUDE_DIRS}
)

link_directories(
    ${DLT_LIBDIR}
)

if (${VSOMEIP_HOTFIX_VERSION} EQUAL 0)
add_definitions(-DVSOMEIP_VERSION="${VSOMEIP_VERSION}")
else()
add_definitions(-DVSOMEIP_VERSION="${VSOMEIP_VERSION}.${VSOMEIP_HOTFIX_VERSION}")
endif()

if (MSVC)
    message("using MSVC Compiler")
    # add_definitions(-DVSOMEIP_DLL_COMPILATION) now it is controlled per target
    SET(BOOST_WINDOWS_VERSION "0x600" CACHE STRING "Set the same Version as the Version with which Boost was built, otherwise there will be errors. (normaly 0x600 is for Windows 7 and 0x501 is for Windows XP)")
    # Disable warning C4250 since it warns that the compiler is correctly following the C++ Standard. It's a "We-Are-Doing-Things-By-The-Book" notice, not a real warning.
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -D_CRT_SECURE_NO_WARNINGS -D_SCL_SECURE_NO_WARNINGS -D_WINSOCK_DEPRECATED_NO_WARNINGS -D_WIN32_WINNT=${BOOST_WINDOWS_VERSION} -DWIN32 -D_WIN32 -DBOOST_ASIO_DISABLE_IOCP /EHsc /wd4250")
    set(USE_RT "")
    link_directories(${Boost_LIBRARY_DIR_DEBUG})
    add_compile_options(/MD$<$<CONFIG:Debug>:d>)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    set(USE_RT "")
else()
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OS_CXX_FLAGS} -g ${OPTIMIZE} ${NO_DEPRECATED} ${EXPORTSYMBOLS}")
    set(USE_RT "rt")
endif()

################################################################################
# Configuration library
################################################################################
file(GLOB ${VSOMEIP_NAME}-cfg_SRC
    "implementation/configuration/src/*.cpp"
)
list(SORT ${VSOMEIP_NAME}-cfg_SRC)
if (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS EQUAL 0)
    add_library(${VSOMEIP_NAME}-cfg SHARED ${${VSOMEIP_NAME}-cfg_SRC})
    set_target_properties (${VSOMEIP_NAME}-cfg PROPERTIES VERSION ${VSOMEIP_VERSION} SOVERSION ${VSOMEIP_MAJOR_VERSION})
    target_compile_features(${VSOMEIP_NAME}-cfg PRIVATE cxx_std_17)
    if (MSVC)
        set_target_properties(${VSOMEIP_NAME}-cfg PROPERTIES COMPILE_DEFINITIONS "VSOMEIP_DLL_COMPILATION_PLUGIN")
    endif()

    target_link_libraries(${VSOMEIP_NAME}-cfg ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${USE_RT} ${DL_LIBRARY} ${SystemD_LIBRARIES})
endif ()

################################################################################
# Base library
################################################################################
file(GLOB ${VSOMEIP_NAME}_SRC
    "implementation/endpoints/src/*.cpp"
    "implementation/logger/src/*.cpp"
    "implementation/tracing/src/*.cpp"
    "implementation/message/src/*.cpp"
    "implementation/plugin/src/*.cpp"
    "implementation/protocol/src/*.cpp"
    "implementation/routing/src/*.cpp"
    "implementation/runtime/src/*.cpp"
    "implementation/security/src/*.cpp"
    "implementation/utility/src/*.cpp"
)
if (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS EQUAL 1)
list(APPEND ${VSOMEIP_NAME}_SRC "implementation/configuration/src/configuration_impl.cpp")
endif()

if (WIN32)
list(FILTER ${VSOMEIP_NAME}_SRC EXCLUDE REGEX ".*uds.*")
endif()

list(SORT ${VSOMEIP_NAME}_SRC)

add_library(${VSOMEIP_NAME} SHARED ${${VSOMEIP_NAME}_SRC})
set_target_properties (${VSOMEIP_NAME} PROPERTIES VERSION ${VSOMEIP_VERSION} SOVERSION ${VSOMEIP_MAJOR_VERSION})
target_compile_features(${VSOMEIP_NAME} PRIVATE cxx_std_17)
if (MSVC)
    set_target_properties(${VSOMEIP_NAME} PROPERTIES COMPILE_DEFINITIONS "VSOMEIP_DLL_COMPILATION")
    set_target_properties(${VSOMEIP_NAME} PROPERTIES WINDOWS_EXPORT_ALL_SYMBOLS ON)
else ()
    set_target_properties(${VSOMEIP_NAME} PROPERTIES LINK_FLAGS "-Wl,-wrap,socket -Wl,-wrap,accept -Wl,-wrap,open")
endif ()
target_include_directories(${VSOMEIP_NAME} INTERFACE
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/interface>
    $<BUILD_INTERFACE:${PROJECT_BINARY_DIR}>
    $<INSTALL_INTERFACE:${INSTALL_INCLUDE_DIR}>)
# PRIVATE means the listed libraries won't be included in the "link interface",
# meaning the exported ${VSOMEIP_NAME}Targets.cmake targets won't try to link against
# them (which shouldn't be required). ${Boost_LIBRARIES} includes absolute
# build host paths as of writing, which also makes this important as it breaks
# the build.
target_link_libraries(${VSOMEIP_NAME} PRIVATE ${Boost_LIBRARIES} ${USE_RT} ${DL_LIBRARY} ${DLT_LIBRARIES} ${SystemD_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})

if(NOT WIN32)
    target_link_options(${VSOMEIP_NAME} PRIVATE "LINKER:-as-needed")
endif()

################################################################################
# Service Discovery library
################################################################################
file(GLOB ${VSOMEIP_NAME}-sd_SRC
    "implementation/service_discovery/src/*.cpp"
)
list(SORT ${VSOMEIP_NAME}-sd_SRC)

add_library(${VSOMEIP_NAME}-sd SHARED ${${VSOMEIP_NAME}-sd_SRC})
target_compile_features(${VSOMEIP_NAME}-sd PRIVATE cxx_std_17)
set_target_properties (${VSOMEIP_NAME}-sd PROPERTIES VERSION ${VSOMEIP_VERSION} SOVERSION ${VSOMEIP_MAJOR_VERSION})
if (MSVC)
    set_target_properties(${VSOMEIP_NAME}-sd PROPERTIES COMPILE_DEFINITIONS "VSOMEIP_DLL_COMPILATION_PLUGIN")
endif ()

target_link_libraries(${VSOMEIP_NAME}-sd ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${USE_RT} ${DL_LIBRARY} ${SystemD_LIBRARIES} ${CMAKE_THREAD_LIBS_INIT})


################################################################################
# E2E library
################################################################################
file(GLOB_RECURSE ${VSOMEIP_NAME}-e2e_SRC
    "implementation/e2e_protection/src/*.cpp"
)
list(SORT ${VSOMEIP_NAME}-e2e_SRC)

add_library(${VSOMEIP_NAME}-e2e SHARED ${${VSOMEIP_NAME}-e2e_SRC})
target_compile_features(${VSOMEIP_NAME}-e2e PRIVATE cxx_std_17)
set_target_properties (${VSOMEIP_NAME}-e2e PROPERTIES VERSION ${VSOMEIP_VERSION} SOVERSION ${VSOMEIP_MAJOR_VERSION})
if (MSVC)
    set_target_properties(${VSOMEIP_NAME}-e2e PROPERTIES COMPILE_DEFINITIONS "VSOMEIP_DLL_COMPILATION_PLUGIN")
endif ()

target_link_libraries(${VSOMEIP_NAME}-e2e ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${USE_RT} ${DL_LIBRARY} ${SystemD_LIBRARIES})

if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    target_link_directories(${VSOMEIP_NAME} PUBLIC "${QNX_TARGET}/${CPUVARDIR}/io-sock/lib")
    target_link_libraries(${VSOMEIP_NAME}-e2e socket)
    target_link_libraries(${VSOMEIP_NAME}-cfg socket)
    target_link_libraries(${VSOMEIP_NAME}-sd socket)
    target_link_libraries(${VSOMEIP_NAME} PRIVATE socket)
endif()
################################################################################
# Compatibility library
################################################################################
if (VSOMEIP_ENABLE_COMPAT EQUAL 1)
set (VSOMEIP_COMPAT_MAJOR_VERSION 2)
set (VSOMEIP_COMPAT_VERSION ${VSOMEIP_COMPAT_MAJOR_VERSION}.99.99)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DVSOMEIP_ENABLE_COMPAT")

file(GLOB_RECURSE ${VSOMEIP_COMPAT_NAME}_SRC
    "implementation/compat/logging/src/*.cpp"
    "implementation/compat/message/src/*.cpp"
    "implementation/compat/runtime/src/*.cpp"
)
list(SORT ${VSOMEIP_COMPAT_NAME}_SRC)

add_library(${VSOMEIP_COMPAT_NAME} SHARED ${${VSOMEIP_COMPAT_NAME}_SRC})
target_compile_features(${VSOMEIP_COMPAT_NAME} PRIVATE cxx_std_17)
set_target_properties (${VSOMEIP_COMPAT_NAME} PROPERTIES VERSION ${VSOMEIP_COMPAT_VERSION} SOVERSION ${VSOMEIP_COMPAT_MAJOR_VERSION})
if (MSVC)
    set_target_properties(${VSOMEIP_COMPAT_NAME} PROPERTIES COMPILE_DEFINITIONS "VSOMEIP_DLL_COMPILATION_PLUGIN")
endif ()

target_include_directories(
    ${VSOMEIP_COMPAT_NAME}
    PUBLIC
    $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}/interface/compat>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_BINARY_DIR}> # for generated files in build mode
    $<INSTALL_INTERFACE:include/compat> # for clients in install mode
)
target_link_libraries(${VSOMEIP_COMPAT_NAME} PRIVATE ${VSOMEIP_NAME} ${Boost_LIBRARIES} ${USE_RT} ${DL_LIBRARY} ${SystemD_LIBRARIES})

endif ()

################################################################################
# Configuration files
################################################################################
set(EXAMPLE_CONFIG_FILES
    "config/vsomeip.json"
    "config/vsomeip-local.json"
    "config/vsomeip-tcp-client.json"
    "config/vsomeip-tcp-service.json"
    "config/vsomeip-udp-client.json"
    "config/vsomeip-udp-service.json"
)

################################################################################
# Configuration parameters
################################################################################
if(${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    set (VSOMEIP_BASE_PATH "/var")
else()
    set (VSOMEIP_BASE_PATH "/tmp")
endif()
if (BASE_PATH)
set (VSOMEIP_BASE_PATH ${BASE_PATH})
endif ()

set (VSOMEIP_DIAGNOSIS_ADDRESS "0x01")
if (DIAGNOSIS_ADDRESS)
set (VSOMEIP_DIAGNOSIS_ADDRESS ${DIAGNOSIS_ADDRESS})
endif ()

set (VSOMEIP_UNICAST_ADDRESS "127.0.0.1")
if (UNICAST_ADDRESS)
set (VSOMEIP_UNICAST_ADDRESS ${UNICAST_ADDRESS})
endif ()

set (VSOMEIP_ROUTING_READY_MESSAGE "SOME/IP routing ready.")
if (ROUTING_READY_MESSAGE)
set (VSOMEIP_ROUTING_READY_MESSAGE ${ROUTING_READY_MESSAGE})
endif ()

set (VSOMEIP_LOCAL_TCP_PORT_WAIT_TIME 100)
if (LOCAL_TCP_PORT_WAIT_TIME)
set (VSOMEIP_LOCAL_TCP_PORT_WAIT_TIME ${LOCAL_TCP_PORT_WAIT_TIME})
endif ()

set (VSOMEIP_LOCAL_TCP_PORT_MAX_WAIT_TIME 10000)
if (LOCAL_TCP_PORT_MAX_WAIT_TIME)
if (${LOCAL_TCP_PORT_MAX_WAIT_TIME} GREATER ${LOCAL_TCP_PORT_WAIT_TIME})
set (VSOMEIP_LOCAL_TCP_PORT_MAX_WAIT_TIME ${LOCAL_TCP_PORT_MAX_WAIT_TIME})
else ()
set (VSOMEIP_LOCAL_TCP_PORT_MAX_WAIT_TIME ${LOCAL_TCP_PORT_WAIT_TIME})
endif ()
endif ()

set(DEFAULT_CONFIGURATION_FOLDER "/etc/vsomeip" CACHE PATH "Default configuration folder")
message(STATUS "Default configuration folder: ${DEFAULT_CONFIGURATION_FOLDER}")

set(DEFAULT_CONFIGURATION_FILE "/etc/vsomeip.json" CACHE FILEPATH "Default configuration file")
message(STATUS "Default configuration file: ${DEFAULT_CONFIGURATION_FILE}")

message("Predefined base path: ${VSOMEIP_BASE_PATH}")
message("Predefined unicast address: ${VSOMEIP_UNICAST_ADDRESS}")
message("Predefined diagnosis address: ${VSOMEIP_DIAGNOSIS_ADDRESS}")
message("Predefined wait times for internal communication ports (TCP):\
 ${VSOMEIP_LOCAL_TCP_PORT_WAIT_TIME}\
 (max=${VSOMEIP_LOCAL_TCP_PORT_MAX_WAIT_TIME})")

################################################################################
# Installation
################################################################################
set(INCLUDE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/interface/vsomeip")

file (GLOB_RECURSE vsomeip_INCLUDE RELATIVE ${INCLUDE_PATH} "interface/*.h*"  )
list (SORT vsomeip_INCLUDE)

foreach ( file ${vsomeip_INCLUDE} )
    get_filename_component( dir ${file} DIRECTORY )
    install( FILES "${INCLUDE_PATH}/${file}" DESTINATION "${INSTALL_INCLUDE_DIR}/vsomeip/${dir}" COMPONENT dev)
endforeach()

install (
    TARGETS ${VSOMEIP_NAME}
    # IMPORTANT: Add the vsomeip library to the "export-set"
    EXPORT ${VSOMEIP_NAME}Targets
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT
    ARCHIVE DESTINATION "${INSTALL_LIB_DIR}"
    COMPONENT dev
)

install (
    TARGETS ${VSOMEIP_NAME}-e2e
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT shlib
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT bin
)

if (VSOMEIP_ENABLE_MULTIPLE_ROUTING_MANAGERS EQUAL 0)
install (
    TARGETS ${VSOMEIP_NAME}-cfg
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT shlib
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT bin
)
endif ()

install (
    TARGETS ${VSOMEIP_NAME}-sd
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT shlib
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT bin
)

if (VSOMEIP_ENABLE_COMPAT EQUAL 1)
install (
    TARGETS ${VSOMEIP_COMPAT_NAME}
    EXPORT vsomeipTargets
    LIBRARY DESTINATION "${INSTALL_LIB_DIR}" COMPONENT shlib
    RUNTIME DESTINATION "${INSTALL_BIN_DIR}" COMPONENT bin
)

export (TARGETS ${VSOMEIP_COMPAT_NAME} FILE "${PROJECT_BINARY_DIR}/vsomeipTargets.cmake")
export (PACKAGE ${VSOMEIP_COMPAT_NAME})

configure_file (vsomeipConfig.cmake.in "${PROJECT_BINARY_DIR}/vsomeipConfig.cmake" @ONLY)
configure_file (vsomeipConfigVersion.cmake.in "${PROJECT_BINARY_DIR}/vsomeipConfigVersion.cmake" @ONLY)

set (COMPAT_INSTALL_CMAKE_DIR "lib/cmake/${VSOMEIP_COMPAT_NAME}")

install (
    EXPORT vsomeipTargets
    DESTINATION "${COMPAT_INSTALL_CMAKE_DIR}"
    COMPONENT dev
)

install (
    FILES
    "${PROJECT_BINARY_DIR}/vsomeipConfig.cmake"
    "${PROJECT_BINARY_DIR}/vsomeipConfigVersion.cmake"
    DESTINATION "${COMPAT_INSTALL_CMAKE_DIR}"
    COMPONENT dev
)

configure_file(vsomeip.pc.in ${PROJECT_BINARY_DIR}/vsomeip.pc @ONLY)
install(FILES ${PROJECT_BINARY_DIR}/vsomeip.pc DESTINATION lib/pkgconfig)

endif ()

install (
  FILES ${EXAMPLE_CONFIG_FILES} DESTINATION etc/vsomeip COMPONENT config
)

# Add all targets to the build-tree export set
export (TARGETS ${VSOMEIP_NAME} FILE "${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}Targets.cmake")

# Export the package for use from the build-tree
# (this registers the build-tree with a global CMake-registry)
export (PACKAGE ${VSOMEIP_NAME})

# Create the ${VSOMEIP_NAME}Config.cmake and ${VSOMEIP_NAME}ConfigVersion files
configure_file (${VSOMEIP_NAME}Config.cmake.in "${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}Config.cmake" @ONLY)
configure_file (${VSOMEIP_NAME}ConfigVersion.cmake.in "${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}ConfigVersion.cmake" @ONLY)

# configure internal.hpp for correct version number
configure_file (
   "${PROJECT_SOURCE_DIR}/implementation/configuration/include/internal.hpp.in"
   "${PROJECT_SOURCE_DIR}/implementation/configuration/include/internal.hpp"
)

# Install the ${VSOMEIP_NAME}Config.cmake and ${VSOMEIP_NAME}ConfigVersion.cmake
install (
    FILES
    "${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}Config.cmake"
    "${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}ConfigVersion.cmake"
    DESTINATION "${INSTALL_CMAKE_DIR}"
    COMPONENT dev
)

# Install the export set for use with the install-tree
install (
    EXPORT ${VSOMEIP_NAME}Targets
    DESTINATION "${INSTALL_CMAKE_DIR}"
    COMPONENT dev
)

##############################################################################
# build documentation
##############################################################################
add_custom_target(doc)

find_package(Doxygen)
if (NOT DOXYGEN_FOUND)
    message(WARNING "Doxygen is not installed. Documentation can not be built.")
else()
    # set configuration variables for doxygen.in
    set(PROJECT "vsomeip")
    set(DOCDIR documentation)
    set(SRCDIR .)
    set(GENERATE_HTML YES)
    set(GENERATE_HTMLHELP NO)
    set(GENERATE_CHI NO)
    set(GENERATE_LATEX NO)
    set(GENERATE_PDF NO)
    set(GENERATE_RTF NO)
    set(GENERATE_MAN NO)
    set(GENERATE_XML NO)
    set(HAVE_DOT YES)

    if(HAVE_DOT)
        # Note: the @DOT_PATH@ variable won't be used in doxygen.in as doxygen
        # somehow manages to strip the last slash from the path and therfore no
        # graphs are generated. Therefore dot should be available in your $PATH
        FIND_PROGRAM(DOT_PATH dot)
        if ("${DOT_PATH}" STREQUAL "DOT_PATH-NOTFOUND")
            message(WARNING "dot (graphviz) is not installed. Graphs in documentation can't be generated.")
        else()
            message("dot found")
        endif()
    endif()

    configure_file(documentation/doxygen.in ${PROJECT_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doxygen-doc
                      COMMAND ${DOXYGEN_EXECUTABLE} ${PROJECT_BINARY_DIR}/Doxyfile
                      SOURCES ${PROJECT_BINARY_DIR}/Doxyfile)

    add_dependencies(doc doxygen-doc)
endif()

##############################################################################
# create pkg-config file
if(NOT WIN32)
        configure_file(${VSOMEIP_NAME}.pc.in ${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}.pc @ONLY)
        install(FILES ${PROJECT_BINARY_DIR}/${VSOMEIP_NAME}.pc DESTINATION lib/pkgconfig)
endif()

##############################################################################
# build routing manager daemon (Non-Windows only)
if (NOT MSVC)
add_subdirectory( examples/routingmanagerd )
endif()

# build tools
add_custom_target( tools )
add_subdirectory( tools/vsomeip_ctrl )

# build examples
add_custom_target( examples )
add_subdirectory( examples EXCLUDE_FROM_ALL )

##############################################################################
# add test directory
enable_testing()

add_subdirectory( test EXCLUDE_FROM_ALL )

if (${CMAKE_SYSTEM_NAME} MATCHES "QNX")
    install(DIRECTORY ${PROJECT_BINARY_DIR}/test/
        DESTINATION bin/vsomeip_tests/test
        PATTERN "CMakeFiles" EXCLUDE
        PATTERN "*.cmake" EXCLUDE
        PATTERN "Makefile" EXCLUDE
    )

    install(FILES ${PROJECT_BINARY_DIR}/examples/routingmanagerd/routingmanagerd
        DESTINATION bin/vsomeip_tests/examples/routingmanagerd)
endif()
