# Install script for directory: /Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include

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
   "/usr/local/include/cmetrics/cmetrics.h;/usr/local/include/cmetrics/cmt_atomic.h;/usr/local/include/cmetrics/cmt_cat.h;/usr/local/include/cmetrics/cmt_compat.h;/usr/local/include/cmetrics/cmt_counter.h;/usr/local/include/cmetrics/cmt_decode_msgpack.h;/usr/local/include/cmetrics/cmt_decode_opentelemetry.h;/usr/local/include/cmetrics/cmt_decode_prometheus.h;/usr/local/include/cmetrics/cmt_decode_prometheus_remote_write.h;/usr/local/include/cmetrics/cmt_decode_statsd.h;/usr/local/include/cmetrics/cmt_encode_cloudwatch_emf.h;/usr/local/include/cmetrics/cmt_encode_influx.h;/usr/local/include/cmetrics/cmt_encode_msgpack.h;/usr/local/include/cmetrics/cmt_encode_opentelemetry.h;/usr/local/include/cmetrics/cmt_encode_prometheus.h;/usr/local/include/cmetrics/cmt_encode_prometheus_remote_write.h;/usr/local/include/cmetrics/cmt_encode_splunk_hec.h;/usr/local/include/cmetrics/cmt_encode_text.h;/usr/local/include/cmetrics/cmt_filter.h;/usr/local/include/cmetrics/cmt_gauge.h;/usr/local/include/cmetrics/cmt_histogram.h;/usr/local/include/cmetrics/cmt_info.h;/usr/local/include/cmetrics/cmt_label.h;/usr/local/include/cmetrics/cmt_log.h;/usr/local/include/cmetrics/cmt_map.h;/usr/local/include/cmetrics/cmt_math.h;/usr/local/include/cmetrics/cmt_metric.h;/usr/local/include/cmetrics/cmt_mpack_utils.h;/usr/local/include/cmetrics/cmt_mpack_utils_defs.h;/usr/local/include/cmetrics/cmt_opts.h;/usr/local/include/cmetrics/cmt_summary.h;/usr/local/include/cmetrics/cmt_time.h;/usr/local/include/cmetrics/cmt_untyped.h;/usr/local/include/cmetrics/cmt_variant_utils.h;/usr/local/include/cmetrics/cmt_version.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/include/cmetrics" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmetrics.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_atomic.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_cat.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_compat.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_counter.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_msgpack.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_opentelemetry.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_prometheus.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_prometheus_remote_write.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_decode_statsd.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_cloudwatch_emf.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_influx.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_msgpack.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_opentelemetry.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_prometheus.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_prometheus_remote_write.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_splunk_hec.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_encode_text.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_filter.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_gauge.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_histogram.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_info.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_label.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_log.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_map.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_math.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_metric.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_mpack_utils.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_mpack_utils_defs.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_opts.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_summary.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_time.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_untyped.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_variant_utils.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/cmetrics/cmt_version.h"
    )
endif()

if(CMAKE_INSTALL_COMPONENT STREQUAL "headers" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/prometheus_remote_write/protobuf-c.h;/usr/local/include/prometheus_remote_write/remote.pb-c.h;/usr/local/include/prometheus_remote_write/types.pb-c.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  file(INSTALL DESTINATION "/usr/local/include/prometheus_remote_write" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/prometheus_remote_write/protobuf-c.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/prometheus_remote_write/remote.pb-c.h"
    "/Users/adheipsingh/parseable/fluent-bit/lib/cmetrics/include/prometheus_remote_write/types.pb-c.h"
    )
endif()

string(REPLACE ";" "\n" CMAKE_INSTALL_MANIFEST_CONTENT
       "${CMAKE_INSTALL_MANIFEST_FILES}")
if(CMAKE_INSTALL_LOCAL_ONLY)
  file(WRITE "/Users/adheipsingh/parseable/fluent-bit/plugins/lib/cmetrics/include/install_local_manifest.txt"
     "${CMAKE_INSTALL_MANIFEST_CONTENT}")
endif()
