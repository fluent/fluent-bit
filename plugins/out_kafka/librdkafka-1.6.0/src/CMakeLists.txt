set(LIBVER 1)

set(
    sources
    crc32c.c
    rdaddr.c
    rdavl.c
    rdbuf.c
    rdcrc32.c
    rdfnv1a.c
    rdkafka.c
    rdkafka_assignor.c
    rdkafka_broker.c
    rdkafka_buf.c
    rdkafka_cgrp.c
    rdkafka_conf.c
    rdkafka_event.c
    rdkafka_feature.c
    rdkafka_lz4.c
    rdkafka_metadata.c
    rdkafka_metadata_cache.c
    rdkafka_msg.c
    rdkafka_msgset_reader.c
    rdkafka_msgset_writer.c
    rdkafka_offset.c
    rdkafka_op.c
    rdkafka_partition.c
    rdkafka_pattern.c
    rdkafka_queue.c
    rdkafka_range_assignor.c
    rdkafka_request.c
    rdkafka_roundrobin_assignor.c
    rdkafka_sasl.c
    rdkafka_sasl_plain.c
    rdkafka_sticky_assignor.c
    rdkafka_subscription.c
    rdkafka_assignment.c
    rdkafka_timer.c
    rdkafka_topic.c
    rdkafka_transport.c
    rdkafka_interceptor.c
    rdkafka_header.c
    rdkafka_admin.c
    rdkafka_aux.c
    rdkafka_background.c
    rdkafka_idempotence.c
    rdkafka_txnmgr.c
    rdkafka_cert.c
    rdkafka_coord.c
    rdkafka_mock.c
    rdkafka_mock_handlers.c
    rdkafka_mock_cgrp.c
    rdkafka_error.c
    rdlist.c
    rdlog.c
    rdmurmur2.c
    rdports.c
    rdrand.c
    rdregex.c
    rdstring.c
    rdunittest.c
    rdvarint.c
    rdmap.c
    snappy.c
    tinycthread.c
    tinycthread_extra.c
    rdxxhash.c
)

if(WITH_SSL)
  list(APPEND sources rdkafka_ssl.c)
endif()

if(WITH_HDRHISTOGRAM)
  list(APPEND sources rdhdrhistogram.c)
endif()

if(WITH_LIBDL OR WIN32)
  list(APPEND sources rddl.c)
endif()

if(WITH_PLUGINS)
  list(APPEND sources rdkafka_plugin.c)
endif()

if(WIN32)
  list(APPEND sources rdkafka_sasl_win32.c)
elseif(WITH_SASL_CYRUS)
  list(APPEND sources rdkafka_sasl_cyrus.c)
endif()

if(WITH_SASL_SCRAM)
  list(APPEND sources rdkafka_sasl_scram.c)
endif()

if(WITH_SASL_OAUTHBEARER)
  list(APPEND sources rdkafka_sasl_oauthbearer.c)
endif()

if(WITH_ZLIB)
  list(APPEND sources rdgz.c)
endif()

if(WITH_ZSTD)
  list(APPEND sources rdkafka_zstd.c)
endif()

if(NOT WITH_LZ4_EXT)
  list(APPEND sources lz4.c lz4frame.c lz4hc.c)
endif()

if(NOT HAVE_REGEX)
  list(APPEND sources regexp.c)
endif()

# Define flags with cmake instead of by defining them on win32_config.h
if(WITHOUT_WIN32_CONFIG)
  list(APPEND rdkafka_compile_definitions WITHOUT_WIN32_CONFIG)
  if(WITH_SSL)
    list(APPEND rdkafka_compile_definitions WITH_SSL=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_SSL=0)
  endif(WITH_SSL)
  if(WITH_ZLIB)
    list(APPEND rdkafka_compile_definitions WITH_ZLIB=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_ZLIB=0)
  endif(WITH_ZLIB)
  if(WITH_SNAPPY)
    list(APPEND rdkafka_compile_definitions WITH_SNAPPY=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_SNAPPY=0)
  endif(WITH_SNAPPY)
  if(WITH_ZSTD)
    list(APPEND rdkafka_compile_definitions WITH_ZSTD=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_ZSTD=0)
  endif(WITH_ZSTD)
  if(WITH_SASL_SCRAM)
    list(APPEND rdkafka_compile_definitions WITH_SASL_SCRAM=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_SASL_SCRAM=0)
  endif(WITH_SASL_SCRAM)
  if(WITH_SASL_OAUTHBEARER)
    list(APPEND rdkafka_compile_definitions WITH_SASL_OAUTHBEARER=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_SASL_OAUTHBEARER=0)
  endif(WITH_SASL_OAUTHBEARER)
  if(ENABLE_DEVEL)
    list(APPEND rdkafka_compile_definitions ENABLE_DEVEL=1)
  else()
    list(APPEND rdkafka_compile_definitions ENABLE_DEVEL=0)
  endif(ENABLE_DEVEL)
  if(WITH_PLUGINS)
    list(APPEND rdkafka_compile_definitions WITH_PLUGIN=1)
  else()
    list(APPEND rdkafka_compile_definitions WITH_PLUGIN=0)
  endif(WITH_PLUGINS)
endif()

if(RDKAFKA_BUILD_STATIC)
  set(CMAKE_POSITION_INDEPENDENT_CODE ON)
  set(RDKAFKA_BUILD_MODE STATIC)
else()
  set(RDKAFKA_BUILD_MODE SHARED)
endif()

add_library(rdkafka ${RDKAFKA_BUILD_MODE} ${sources})
if(NOT RDKAFKA_BUILD_STATIC)
  set_property(TARGET rdkafka PROPERTY SOVERSION ${LIBVER})
endif()

if(MINGW)
  # Target Windows 8.1 to match the VS projects (MinGW defaults to an older WinAPI version)
  list(APPEND rdkafka_compile_definitions WINVER=0x0603 _WIN32_WINNT=0x0603 UNICODE)
endif(MINGW)

# Support '#include <rdkafka.h>'
target_include_directories(rdkafka PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>")
target_compile_definitions(rdkafka PUBLIC ${rdkafka_compile_definitions})
if(RDKAFKA_BUILD_STATIC)
  target_compile_definitions(rdkafka PUBLIC LIBRDKAFKA_STATICLIB)
endif()

if(MINGW)
	message(STATUS "Detected MinGW build")
  # MinGW ignores `#pragma comment(lib, ...)` so we need to specify link libs
  target_link_libraries(rdkafka PUBLIC crypt32 ws2_32 secur32)
endif(MINGW)

if(WIN32)  
  if(RDKAFKA_BUILD_STATIC)
    target_link_libraries(rdkafka PUBLIC crypt32)
  else()
    target_compile_definitions(rdkafka PRIVATE LIBRDKAFKA_EXPORTS)
  endif()
endif()

# We need 'dummy' directory to support `#include "../config.h"` path
set(dummy "${GENERATED_DIR}/dummy")
file(MAKE_DIRECTORY "${dummy}")
target_include_directories(rdkafka PUBLIC "$<BUILD_INTERFACE:${dummy}>")

if(WITH_HDRHISTOGRAM)
  target_link_libraries(rdkafka PUBLIC m)
endif()

if(WITH_ZLIB)
  find_package(ZLIB REQUIRED)
  target_include_directories(rdkafka PUBLIC ${ZLIB_INCLUDE_DIRS})
  target_link_libraries(rdkafka PUBLIC ZLIB::ZLIB)
endif()

if(WITH_ZSTD)
  target_link_libraries(rdkafka PUBLIC ${ZSTD_LIBRARY})
  target_include_directories(rdkafka PUBLIC ${ZSTD_INCLUDE_DIR})
  message(STATUS "Found ZSTD: ${ZSTD_LIBRARY}")
endif()

if(WITH_SSL)
  if(WITH_BUNDLED_SSL) # option from 'h2o' parent project
    if(NOT TARGET bundled-ssl)
      message(FATAL_ERROR "bundled-ssl target not exist")
    endif()
    target_include_directories(rdkafka BEFORE PUBLIC ${BUNDLED_SSL_INCLUDE_DIR})
    target_link_libraries(rdkafka PUBLIC ${BUNDLED_SSL_LIBRARIES})
    add_dependencies(rdkafka bundled-ssl)
  else()
    find_package(OpenSSL REQUIRED)
    target_include_directories(rdkafka PUBLIC ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(rdkafka PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

if(LINK_ATOMIC)
  target_link_libraries(rdkafka PUBLIC "-latomic")
endif()

find_package(Threads REQUIRED)
target_link_libraries(rdkafka PUBLIC Threads::Threads)

if(WITH_SASL_CYRUS)
  target_include_directories(rdkafka PUBLIC ${SASL_INCLUDE_DIRS})
  target_link_libraries(rdkafka PUBLIC ${SASL_LIBRARIES})
endif()

if(WITH_LIBDL)
  target_link_libraries(rdkafka PUBLIC ${CMAKE_DL_LIBS})
endif()

if(WITH_LZ4_EXT)
  target_include_directories(rdkafka PUBLIC ${LZ4_INCLUDE_DIRS})
  target_link_libraries(rdkafka PUBLIC LZ4::LZ4)
endif()

# Set up path to these sources for other sub-projects (tests, examples)
# to be able to reach them.
#set(rdkafka_SRC_DIR ${PROJECT_SOURCE_DIR}
#    CACHE INTERNAL "${PROJECT_NAME} source dir" FORCE)

# Generate pkg-config file
set(PKG_CONFIG_NAME
    "librdkafka"
)
set(PKG_CONFIG_DESCRIPTION
    "The Apache Kafka C/C++ library"
)
set(PKG_CONFIG_VERSION
    "${PROJECT_VERSION}"
)
set(PKG_CONFIG_REQUIRES "")
if(WITH_ZLIB)
  string(APPEND PKG_CONFIG_REQUIRES "zlib ")
endif()
if(WITH_SSL)
    string(APPEND PKG_CONFIG_REQUIRES "libssl ")
endif()
if(WITH_SASL_CYRUS)
  string(APPEND PKG_CONFIG_REQUIRES "libsasl2 ")
endif()
if(WITH_ZSTD)
    string(APPEND PKG_CONFIG_REQUIRES "libzstd ")
endif()
if(WITH_LZ4_EXT)
    string(APPEND PKG_CONFIG_REQUIRES "liblz4 ")
endif()
set(PKG_CONFIG_CFLAGS
    "-I\${includedir}"
)
set(PKG_CONFIG_LIBS
    "-L\${libdir} -lrdkafka"
)
set(PKG_CONFIG_LIBS_PRIVATE
    "-lpthread"
)
find_library(RT_LIBRARY rt)
if(RT_LIBRARY)
  string(APPEND PKG_CONFIG_LIBS_PRIVATE " -lrt")
endif()
if(WITH_PLUGINS)
  string(APPEND PKG_CONFIG_LIBS_PRIVATE " -ldl")
endif()
if(WITH_HDRHISTOGRAM)
  string(APPEND PKG_CONFIG_LIBS_PRIVATE " -lm")
endif()
configure_file(
  "../packaging/cmake/rdkafka.pc.in"
  "${GENERATED_DIR}/rdkafka.pc"
  @ONLY
)
install(FILES ${GENERATED_DIR}/rdkafka.pc
  DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
)
if(RDKAFKA_BUILD_STATIC)
  set(PKG_CONFIG_NAME
    "librdkafka-static"
  )
  set(PKG_CONFIG_DESCRIPTION
    "The Apache Kafka C/C++ library (static)"
  )
  set(PKG_CONFIG_LIBS
    "-L\${libdir} \${libdir}/librdkafka.a"
  )
  configure_file(
    "../packaging/cmake/rdkafka.pc.in"
    "${GENERATED_DIR}/rdkafka-static.pc"
    @ONLY
  )
  install(FILES ${GENERATED_DIR}/rdkafka.pc
    DESTINATION "${CMAKE_INSTALL_LIBDIR}/pkgconfig"
  )
endif()

install(
    TARGETS rdkafka
    EXPORT "${targets_export_name}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    FILES "rdkafka.h" "rdkafka_mock.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/librdkafka"
)
