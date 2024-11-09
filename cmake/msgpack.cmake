# msgpack cmake
option(MSGPACK_ENABLE_CXX             OFF)
option(MSGPACK_ENABLE_SHARED          OFF)
option(MSGPACK_BUILD_TESTS            OFF)
option(MSGPACK_BUILD_EXAMPLES         OFF)
include_directories(
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_MSGPACK}/include
)
add_subdirectory(${FLB_PATH_LIB_MSGPACK} EXCLUDE_FROM_ALL)
set(MSGPACK_LIBRARIES "msgpack-c-static")
