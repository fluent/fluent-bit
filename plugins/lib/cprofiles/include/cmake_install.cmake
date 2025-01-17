# Install script for directory: /Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include

# Set the install prefix
if(NOT DEFINED CMAKE_INSTALL_PREFIX)
  set(CMAKE_INSTALL_PREFIX "/usr/local")
endif()
string(REGEX REPLACE "/$" "" CMAKE_INSTALL_PREFIX "${CMAKE_INSTALL_PREFIX}")

# Set the install configuration name.
if(NOT DEFINED CMAKE_INSTALL_CONFIG_NAME)
  if(BUILD_TYPE)
    string(REGEX REPLACE "^[^A-Za-z0-9_]+" ""
           CMAKE_INSTALL_CONFIG_NAME "${BUILD_TYPE}")
  else()
    set(CMAKE_INSTALL_CONFIG_NAME "Debug")
  endif()
  message(STATUS "Install configuration: \"${CMAKE_INSTALL_CONFIG_NAME}\"")
endif()

# Set the component getting installed.
if(NOT CMAKE_INSTALL_COMPONENT)
  if(COMPONENT)
    message(STATUS "Install component: \"${COMPONENT}\"")
    set(CMAKE_INSTALL_COMPONENT "${COMPONENT}")
  else()
    set(CMAKE_INSTALL_COMPONENT)
  endif()
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

# Set path to fallback-tool for dependency-resolution.
if(NOT DEFINED CMAKE_OBJDUMP)
  set(CMAKE_OBJDUMP "/Library/Developer/CommandLineTools/usr/bin/objdump")
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "headers" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/cprofiles/cprof_decode_msgpack.h;/cprofiles/cprof_decode_opentelemetry.h;/cprofiles/cprof_encode_msgpack.h;/cprofiles/cprof_encode_opentelemetry.h;/cprofiles/cprof_encode_text.h;/cprofiles/cprof_mpack_utils.h;/cprofiles/cprof_mpack_utils_defs.h;/cprofiles/cprof_variant_utils.h;/cprofiles/cprofiles.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/cprofiles" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_decode_msgpack.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_decode_opentelemetry.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_encode_msgpack.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_encode_opentelemetry.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_encode_text.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_mpack_utils.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_mpack_utils_defs.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprof_variant_utils.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cprofiles/include/cprofiles/cprofiles.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/adheipsingh/parseable/fluent-bit/plugins/lib/cprofiles/include/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
