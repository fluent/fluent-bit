if(NOT FLB_PATH_ROOT_SOURCE)
  set(FLB_PATH_ROOT_SOURCE ${FLB_ROOT})
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
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MSGPACK}/include

  # Chunk I/O generate headers also in the binary path
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CHUNKIO}/include
  ${CMAKE_CURRENT_BINARY_DIR}/lib/chunkio/include

  # LuaJIT
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_LUAJIT}/src
  ${CMAKE_CURRENT_BINARY_DIR}/lib/luajit-cmake

  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MONKEY}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MONKEY}/include/monkey
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MBEDTLS}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SQLITE}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MPACK}/src
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MINIZ}/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ONIGMO}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SNAPPY}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CMETRICS}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CTRACES}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CARES}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RING_BUFFER}/lwrb/src/include

  ${CMAKE_CURRENT_BINARY_DIR}/${FLB_PATH_LIB_CARES}
  ${CMAKE_CURRENT_BINARY_DIR}/${FLB_PATH_LIB_JANSSON}/include
  ${CMAKE_CURRENT_BINARY_DIR}/lib/cmetrics
  ${CMAKE_CURRENT_BINARY_DIR}/include

  ${CMAKE_CURRENT_BINARY_DIR}/lib/monkey/include/
  ${CMAKE_CURRENT_BINARY_DIR}/lib/monkey/include/monkey/
  )

if(FLB_IN_KAFKA OR FLB_OUT_KAFKA)
    include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RDKAFKA}/src/)
endif()

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
