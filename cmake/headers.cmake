if(NOT FLB_PATH_ROOT_SOURCE)
  set(FLB_PATH_ROOT_SOURCE ${FLB_ROOT})
endif()

include_directories(
  ${FLB_PATH_ROOT_SOURCE}/include/
  ${FLB_PATH_ROOT_SOURCE}/lib/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CO}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_RBTREE}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MSGPACK}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_CHUNKIO}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_LUAJIT}/src
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MONKEY}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MBEDTLS}/include
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SQLITE}
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MPACK}/src
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MINIZ}/
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ONIGMO}
  ${CMAKE_CURRENT_BINARY_DIR}/include
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
