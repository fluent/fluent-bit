# RocksDB Configuration for Fluent Bit (Vendored Library)
# ========================================================

message(STATUS "Using vendored RocksDB from lib/rocksdb")

# Set C++17 for RocksDB
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Minimal build options
set(WITH_TESTS OFF CACHE BOOL "" FORCE)
set(WITH_TOOLS OFF CACHE BOOL "" FORCE)
set(WITH_BENCHMARK_TOOLS OFF CACHE BOOL "" FORCE)
set(WITH_GFLAGS OFF CACHE BOOL "" FORCE)
set(ROCKSDB_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(WITH_SNAPPY OFF CACHE BOOL "" FORCE)
set(WITH_LZ4 OFF CACHE BOOL "" FORCE)
set(WITH_ZLIB OFF CACHE BOOL "" FORCE)
set(WITH_ZSTD OFF CACHE BOOL "" FORCE)
set(WITH_BZ2 OFF CACHE BOOL "" FORCE)
set(PORTABLE ON CACHE BOOL "" FORCE)
set(FAIL_ON_WARNINGS OFF CACHE BOOL "" FORCE)

# Disable jemalloc in RocksDB to avoid build dependency issues
set(WITH_JEMALLOC OFF CACHE BOOL "" FORCE)

# Add RocksDB
add_subdirectory(${FLB_PATH_LIB_ROCKSDB} EXCLUDE_FROM_ALL)

# Reset to C++11 for Fluent Bit
set(CMAKE_CXX_STANDARD 11)

# Export variables
set(ROCKSDB_LIBRARIES rocksdb)
set(ROCKSDB_TARGET rocksdb)