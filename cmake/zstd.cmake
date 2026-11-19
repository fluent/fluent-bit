# zstd cmake
if(MSVC)
  # Zstd checks C++ compiler flags on MSVC even when only building the C library.
  enable_language(CXX)
endif()

set(ZSTD_BUILD_STATIC ON)
set(ZSTD_BUILD_SHARED OFF)
set(ZSTD_BUILD_COMPRESSION ON)
set(ZSTD_BUILD_DECOMPRESSION ON)
set(ZSTD_BUILD_DICTBUILDER OFF)
set(ZSTD_BUILD_DEPRECATED OFF)
include_directories(${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_ZSTD}/lib)
add_subdirectory(${FLB_PATH_LIB_ZSTD}/build/cmake EXCLUDE_FROM_ALL)
set(LIBZSTD_LIBRARIES "libzstd_static")
