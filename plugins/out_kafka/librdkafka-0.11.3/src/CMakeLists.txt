set(
    sources
    crc32c.c
    rdaddr.c
    rdavl.c
    rdbuf.c
    rdcrc32.c
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
    rdkafka_subscription.c
    rdkafka_timer.c
    rdkafka_topic.c
    rdkafka_transport.c
    rdkafka_interceptor.c
    rdlist.c
    rdlog.c
    rdports.c
    rdrand.c
    rdregex.c
    rdstring.c
    rdunittest.c
    rdvarint.c
    snappy.c
    tinycthread.c
    xxhash.c
    lz4.c
    lz4frame.c
    lz4hc.c
)

if(WITH_LIBDL)
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

if(WITH_ZLIB)
  list(APPEND sources rdgz.c)
endif()

if(NOT HAVE_REGEX)
  list(APPEND sources regexp.c)
endif()

add_library(rdkafka SHARED ${sources})

# Support '#include <rdkafka.h>'
target_include_directories(rdkafka PUBLIC "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}>")

# We need 'dummy' directory to support `#include "../config.h"` path
set(dummy "${GENERATED_DIR}/dummy")
file(MAKE_DIRECTORY "${dummy}")
target_include_directories(rdkafka PUBLIC "$<BUILD_INTERFACE:${dummy}>")

if(WITH_ZLIB)
  find_package(ZLIB REQUIRED)
  target_link_libraries(rdkafka PUBLIC ZLIB::ZLIB)
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
    target_link_libraries(rdkafka PUBLIC OpenSSL::SSL OpenSSL::Crypto)
  endif()
endif()

if(LINK_ATOMIC)
  target_link_libraries(rdkafka PUBLIC "-latomic")
endif()

find_package(Threads REQUIRED)
target_link_libraries(rdkafka PUBLIC Threads::Threads)

if(WITH_SASL_CYRUS)
  target_link_libraries(rdkafka PUBLIC ${SASL_LIBRARIES})
endif()

if(WITH_LIBDL)
  target_link_libraries(rdkafka PUBLIC ${CMAKE_DL_LIBS})
endif()

# Set up path to these sources for other sub-projects (tests, examples)
# to be able to reach them.
#set(rdkafka_SRC_DIR ${PROJECT_SOURCE_DIR}
#    CACHE INTERNAL "${PROJECT_NAME} source dir" FORCE)

install(
    TARGETS rdkafka
    EXPORT "${targets_export_name}"
    LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}"
    RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}"
    INCLUDES DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}"
)

install(
    FILES "rdkafka.h"
    DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/librdkafka"
)
