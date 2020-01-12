# Install script for directory: /home/atibhi/Desktop/CNCF/fluent-bit/include

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

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xUnspecifiedx" OR NOT CMAKE_INSTALL_COMPONENT)
  file(INSTALL DESTINATION "${CMAKE_INSTALL_PREFIX}/include/fluent-bit" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_api.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_bits.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_compat.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_config.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_config_map.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_dlfcn_win32.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_endian.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_engine.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_engine_dispatch.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_env.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_error.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_filter.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_filter_plugin.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_gzip.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_hash.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_http_client.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_http_server.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_info.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_input.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_input_chunk.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_input_plugin.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_io.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_io_tls.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_io_tls_rw.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_kernel.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_kv.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_langinfo.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_lib.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_log.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_luajit.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_macros.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_mem.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_meta.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_metrics.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_metrics_exporter.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_mp.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_network.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_oauth2.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_output.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_output_plugin.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_pack.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_parser.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_parser_decoder.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_pipe.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_plugin.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_plugin_proxy.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_plugins.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_ra_key.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_record_accessor.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_regex.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_router.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_scheduler.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_sds.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_sha512.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_signv4.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_slist.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_socket.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_sosreport.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_sqldb.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_storage.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_str.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_strptime.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_task.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_task_map.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_thread.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_thread_libco.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_thread_storage.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_time.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_time_utils.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_tls.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_unescape.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_upstream.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_upstream_ha.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_upstream_node.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_uri.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_utf8.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_utils.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_version.h"
    "/home/atibhi/Desktop/CNCF/fluent-bit/include/fluent-bit/flb_worker.h"
    )
endif()

