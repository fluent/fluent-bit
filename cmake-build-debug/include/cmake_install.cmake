# Install script for directory: /home/shikugawa/dev/fluent-bit/include

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
   "/usr/local/include/fluent-bit.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/shikugawa/dev/fluent-bit/include/fluent-bit.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/fluent-bit/flb_api.h;/usr/local/include/fluent-bit/flb_avro.h;/usr/local/include/fluent-bit/flb_aws_credentials.h;/usr/local/include/fluent-bit/flb_aws_util.h;/usr/local/include/fluent-bit/flb_bits.h;/usr/local/include/fluent-bit/flb_callback.h;/usr/local/include/fluent-bit/flb_compat.h;/usr/local/include/fluent-bit/flb_config.h;/usr/local/include/fluent-bit/flb_config_map.h;/usr/local/include/fluent-bit/flb_coro.h;/usr/local/include/fluent-bit/flb_custom.h;/usr/local/include/fluent-bit/flb_custom_plugin.h;/usr/local/include/fluent-bit/flb_dlfcn_win32.h;/usr/local/include/fluent-bit/flb_dump.h;/usr/local/include/fluent-bit/flb_endian.h;/usr/local/include/fluent-bit/flb_engine.h;/usr/local/include/fluent-bit/flb_engine_dispatch.h;/usr/local/include/fluent-bit/flb_env.h;/usr/local/include/fluent-bit/flb_error.h;/usr/local/include/fluent-bit/flb_filter.h;/usr/local/include/fluent-bit/flb_filter_plugin.h;/usr/local/include/fluent-bit/flb_fstore.h;/usr/local/include/fluent-bit/flb_gzip.h;/usr/local/include/fluent-bit/flb_hash.h;/usr/local/include/fluent-bit/flb_help.h;/usr/local/include/fluent-bit/flb_http_client.h;/usr/local/include/fluent-bit/flb_http_client_debug.h;/usr/local/include/fluent-bit/flb_http_server.h;/usr/local/include/fluent-bit/flb_info.h;/usr/local/include/fluent-bit/flb_input.h;/usr/local/include/fluent-bit/flb_input_chunk.h;/usr/local/include/fluent-bit/flb_input_metric.h;/usr/local/include/fluent-bit/flb_input_plugin.h;/usr/local/include/fluent-bit/flb_intermediate_metric.h;/usr/local/include/fluent-bit/flb_io.h;/usr/local/include/fluent-bit/flb_jsmn.h;/usr/local/include/fluent-bit/flb_kernel.h;/usr/local/include/fluent-bit/flb_kv.h;/usr/local/include/fluent-bit/flb_langinfo.h;/usr/local/include/fluent-bit/flb_lib.h;/usr/local/include/fluent-bit/flb_log.h;/usr/local/include/fluent-bit/flb_luajit.h;/usr/local/include/fluent-bit/flb_macros.h;/usr/local/include/fluent-bit/flb_mem.h;/usr/local/include/fluent-bit/flb_meta.h;/usr/local/include/fluent-bit/flb_metrics.h;/usr/local/include/fluent-bit/flb_metrics_exporter.h;/usr/local/include/fluent-bit/flb_mp.h;/usr/local/include/fluent-bit/flb_net_dns.h;/usr/local/include/fluent-bit/flb_network.h;/usr/local/include/fluent-bit/flb_oauth2.h;/usr/local/include/fluent-bit/flb_output.h;/usr/local/include/fluent-bit/flb_output_plugin.h;/usr/local/include/fluent-bit/flb_output_thread.h;/usr/local/include/fluent-bit/flb_pack.h;/usr/local/include/fluent-bit/flb_parser.h;/usr/local/include/fluent-bit/flb_parser_decoder.h;/usr/local/include/fluent-bit/flb_pipe.h;/usr/local/include/fluent-bit/flb_plugin.h;/usr/local/include/fluent-bit/flb_plugin_proxy.h;/usr/local/include/fluent-bit/flb_plugins.h;/usr/local/include/fluent-bit/flb_pthread.h;/usr/local/include/fluent-bit/flb_ra_key.h;/usr/local/include/fluent-bit/flb_random.h;/usr/local/include/fluent-bit/flb_record_accessor.h;/usr/local/include/fluent-bit/flb_regex.h;/usr/local/include/fluent-bit/flb_router.h;/usr/local/include/fluent-bit/flb_routes_mask.h;/usr/local/include/fluent-bit/flb_s3_local_buffer.h;/usr/local/include/fluent-bit/flb_scheduler.h;/usr/local/include/fluent-bit/flb_sds.h;/usr/local/include/fluent-bit/flb_sha512.h;/usr/local/include/fluent-bit/flb_signv4.h;/usr/local/include/fluent-bit/flb_slist.h;/usr/local/include/fluent-bit/flb_snappy.h;/usr/local/include/fluent-bit/flb_socket.h;/usr/local/include/fluent-bit/flb_sosreport.h;/usr/local/include/fluent-bit/flb_sqldb.h;/usr/local/include/fluent-bit/flb_stacktrace.h;/usr/local/include/fluent-bit/flb_storage.h;/usr/local/include/fluent-bit/flb_str.h;/usr/local/include/fluent-bit/flb_strptime.h;/usr/local/include/fluent-bit/flb_task.h;/usr/local/include/fluent-bit/flb_task_map.h;/usr/local/include/fluent-bit/flb_thread_pool.h;/usr/local/include/fluent-bit/flb_thread_storage.h;/usr/local/include/fluent-bit/flb_time.h;/usr/local/include/fluent-bit/flb_time_utils.h;/usr/local/include/fluent-bit/flb_tls.h;/usr/local/include/fluent-bit/flb_unescape.h;/usr/local/include/fluent-bit/flb_upstream.h;/usr/local/include/fluent-bit/flb_upstream_conn.h;/usr/local/include/fluent-bit/flb_upstream_ha.h;/usr/local/include/fluent-bit/flb_upstream_node.h;/usr/local/include/fluent-bit/flb_upstream_queue.h;/usr/local/include/fluent-bit/flb_uri.h;/usr/local/include/fluent-bit/flb_utf8.h;/usr/local/include/fluent-bit/flb_utils.h;/usr/local/include/fluent-bit/flb_version.h;/usr/local/include/fluent-bit/flb_worker.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include/fluent-bit" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_api.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_avro.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_aws_credentials.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_aws_util.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_bits.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_callback.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_compat.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_config.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_config_map.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_coro.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_custom.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_custom_plugin.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_dlfcn_win32.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_dump.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_endian.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_engine.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_engine_dispatch.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_env.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_error.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_filter.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_filter_plugin.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_fstore.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_gzip.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_hash.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_help.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_http_client.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_http_client_debug.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_http_server.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_info.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_input.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_input_chunk.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_input_metric.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_input_plugin.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_intermediate_metric.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_io.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_jsmn.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_kernel.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_kv.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_langinfo.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_lib.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_log.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_luajit.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_macros.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_mem.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_meta.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_metrics.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_metrics_exporter.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_mp.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_net_dns.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_network.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_oauth2.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_output.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_output_plugin.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_output_thread.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_pack.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_parser.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_parser_decoder.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_pipe.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_plugin.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_plugin_proxy.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_plugins.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_pthread.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_ra_key.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_random.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_record_accessor.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_regex.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_router.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_routes_mask.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_s3_local_buffer.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_scheduler.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_sds.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_sha512.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_signv4.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_slist.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_snappy.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_socket.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_sosreport.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_sqldb.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_stacktrace.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_storage.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_str.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_strptime.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_task.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_task_map.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_thread_pool.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_thread_storage.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_time.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_time_utils.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_tls.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_unescape.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_upstream.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_upstream_conn.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_upstream_ha.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_upstream_node.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_upstream_queue.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_uri.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_utf8.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_utils.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_version.h"
    "/home/shikugawa/dev/fluent-bit/include/fluent-bit/flb_worker.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheadersx" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/fluent-bit/tls/flb_tls.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include/fluent-bit/tls" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/shikugawa/dev/fluent-bit/include/fluent-bit/tls/flb_tls.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheaders-extrax" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/monkey/mk_core.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include/monkey" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core.h")
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheaders-extrax" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/monkey/mk_core/mk_core_info.h;/usr/local/include/monkey/mk_core/mk_dep_unistd.h;/usr/local/include/monkey/mk_core/mk_dirent.h;/usr/local/include/monkey/mk_core/mk_event.h;/usr/local/include/monkey/mk_core/mk_event_epoll.h;/usr/local/include/monkey/mk_core/mk_event_kqueue.h;/usr/local/include/monkey/mk_core/mk_event_libevent.h;/usr/local/include/monkey/mk_core/mk_event_select.h;/usr/local/include/monkey/mk_core/mk_file.h;/usr/local/include/monkey/mk_core/mk_getopt.h;/usr/local/include/monkey/mk_core/mk_iov.h;/usr/local/include/monkey/mk_core/mk_limits.h;/usr/local/include/monkey/mk_core/mk_list.h;/usr/local/include/monkey/mk_core/mk_macros.h;/usr/local/include/monkey/mk_core/mk_memory.h;/usr/local/include/monkey/mk_core/mk_pipe.h;/usr/local/include/monkey/mk_core/mk_pthread.h;/usr/local/include/monkey/mk_core/mk_rconf.h;/usr/local/include/monkey/mk_core/mk_sleep.h;/usr/local/include/monkey/mk_core/mk_string.h;/usr/local/include/monkey/mk_core/mk_thread.h;/usr/local/include/monkey/mk_core/mk_thread_channel.h;/usr/local/include/monkey/mk_core/mk_uio.h;/usr/local/include/monkey/mk_core/mk_unistd.h;/usr/local/include/monkey/mk_core/mk_utils.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include/monkey/mk_core" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_core_info.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_dep_unistd.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_dirent.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_event.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_event_epoll.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_event_kqueue.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_event_libevent.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_event_select.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_file.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_getopt.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_iov.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_limits.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_list.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_macros.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_memory.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_pipe.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_pthread.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_rconf.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_sleep.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_string.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_thread.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_thread_channel.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_uio.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_unistd.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/monkey/include/monkey/mk_core/mk_utils.h"
    )
endif()

if("x${CMAKE_INSTALL_COMPONENT}x" STREQUAL "xheaders-extrax" OR NOT CMAKE_INSTALL_COMPONENT)
  list(APPEND CMAKE_ABSOLUTE_DESTINATION_FILES
   "/usr/local/include/libco.h;/usr/local/include/settings.h")
  if(CMAKE_WARN_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(WARNING "ABSOLUTE path INSTALL DESTINATION : ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
  if(CMAKE_ERROR_ON_ABSOLUTE_INSTALL_DESTINATION)
    message(FATAL_ERROR "ABSOLUTE path INSTALL DESTINATION forbidden (by caller): ${CMAKE_ABSOLUTE_DESTINATION_FILES}")
  endif()
file(INSTALL DESTINATION "/usr/local/include" TYPE FILE PERMISSIONS OWNER_READ OWNER_WRITE GROUP_READ WORLD_READ FILES
    "/home/shikugawa/dev/fluent-bit/include/../lib/flb_libco/libco.h"
    "/home/shikugawa/dev/fluent-bit/include/../lib/flb_libco/settings.h"
    )
endif()

