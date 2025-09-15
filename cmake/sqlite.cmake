# sqlite cmake
include_directories(
  ${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SQLITE}
)
add_subdirectory(${FLB_PATH_LIB_SQLITE})
set(SQLITE_LIBRARIES "sqlite3")
