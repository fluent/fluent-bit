# Install script for directory: /home/shikugawa/dev/fluent-bit/lib/cmetrics/include

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

# Install shared libraries without execute permission?
if(NOT DEFINED CMAKE_INSTALL_SO_NO_EXE)
  set(CMAKE_INSTALL_SO_NO_EXE "1")
endif()

# Is this installation the result of a crosscompile?
if(NOT DEFINED CMAKE_CROSSCOMPILING)
  set(CMAKE_CROSSCOMPILING "FALSE")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/cmetrics/cmetrics.h;/usr/local/include/cmetrics/cmt_atomic.h;/usr/local/include/cmetrics/cmt_cat.h;/usr/local/include/cmetrics/cmt_compat.h;/usr/local/include/cmetrics/cmt_counter.h;/usr/local/include/cmetrics/cmt_decode_msgpack.h;/usr/local/include/cmetrics/cmt_encode_influx.h;/usr/local/include/cmetrics/cmt_encode_msgpack.h;/usr/local/include/cmetrics/cmt_encode_prometheus.h;/usr/local/include/cmetrics/cmt_encode_prometheus_remote_write.h;/usr/local/include/cmetrics/cmt_encode_text.h;/usr/local/include/cmetrics/cmt_gauge.h;/usr/local/include/cmetrics/cmt_hash.h;/usr/local/include/cmetrics/cmt_info.h;/usr/local/include/cmetrics/cmt_label.h;/usr/local/include/cmetrics/cmt_log.h;/usr/local/include/cmetrics/cmt_map.h;/usr/local/include/cmetrics/cmt_math.h;/usr/local/include/cmetrics/cmt_metric.h;/usr/local/include/cmetrics/cmt_mpack_utils.h;/usr/local/include/cmetrics/cmt_mpack_utils_defs.h;/usr/local/include/cmetrics/cmt_opts.h;/usr/local/include/cmetrics/cmt_sds.h;/usr/local/include/cmetrics/cmt_time.h;/usr/local/include/cmetrics/cmt_untyped.h;/usr/local/include/cmetrics/cmt_version.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include/cmetrics" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmetrics.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_atomic.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_cat.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_compat.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_counter.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_msgpack.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_influx.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_msgpack.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_prometheus.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_prometheus_remote_write.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_text.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_gauge.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_hash.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_info.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_label.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_log.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_map.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_math.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_metric.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_mpack_utils.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_mpack_utils_defs.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_opts.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_sds.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_time.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_untyped.h"
    "/home/shikugawa/dev/fluent-bit/lib/cmetrics/include/cmetrics/cmt_version.h"
    )
endif()

