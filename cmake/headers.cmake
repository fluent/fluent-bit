if(NOT FLB_PATH_ROOT_SOURCE)
  set(FLB_PATH_ROOT_SOURCE ${FLB_ROOT})
endif()

if(NOT DEFINED FLB_PATH_ROOT_BINARY_DIR)
  set(FLB_PATH_ROOT_BINARY_DIR ${CMAKE_CURRENT_BINARY_DIR})
endif()

include_directories(
  ${FLB_PATH_ROOT_SOURCE}/include/
  ${FLB_PATH_ROOT_SOURCE}/lib/

  # fluent-otel-proto
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/include/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_FLUENT_OTEL}/proto_c/

  # CFL
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CFL}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CFL}/lib/xxhash

  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CO}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RBTREE}

  # Chunk I/O generate headers also in the binary path
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CHUNKIO}/include
  ${FLB_PATH_ROOT_BINARY_DIR}/lib/chunkio/include

  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MONKEY}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MONKEY}/include/monkey
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MBEDTLS}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MPACK}/src
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MINIZ}/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SNAPPY}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CMETRICS}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CTRACES}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CPROFILES}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RING_BUFFER}/lwrb/src/include

  ${FLB_PATH_ROOT_BINARY_DIR}/${FLB_PATH_LIB_JANSSON}/include
  ${FLB_PATH_ROOT_BINARY_DIR}/lib/cmetrics
  ${FLB_PATH_ROOT_BINARY_DIR}/lib/cprofiles/include
  ${FLB_PATH_ROOT_BINARY_DIR}/include

  ${FLB_PATH_ROOT_BINARY_DIR}/lib/monkey/include/
  ${FLB_PATH_ROOT_BINARY_DIR}/lib/monkey/include/monkey/
  )

if(FLB_UTF8_ENCODER)
  include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_TUTF8E}/include)
endif()

# On Windows, the core uses libevent
if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  include_directories(
    lib/monkey/mk_core/deps/libevent/include
    ${PROJECT_BINARY_DIR}/lib/monkey/mk_core/deps/libevent/include
    )
endif()
