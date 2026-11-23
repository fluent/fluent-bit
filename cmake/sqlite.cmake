# Library sources are prepared by tools/update-sqlite.py and committed.
# Configuration and compilation never download or regenerate SQLite sources.
set(flb_sqlite_dir "${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SQLITE}")
include_directories("${flb_sqlite_dir}")

include("${flb_sqlite_dir}/sources.cmake")

add_library(sqlite3 STATIC ${flb_sqlite_sources})
target_include_directories(sqlite3 PRIVATE "${flb_sqlite_dir}" "${flb_sqlite_dir}/src")
target_link_libraries(sqlite3 ${CMAKE_DL_LIBS})

target_compile_definitions(sqlite3 PRIVATE SQLITE_CORE)
# Keep implementation symbols private when linking SQLite into the shared core.
if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|IntelLLVM")
  set_target_properties(sqlite3 PROPERTIES C_VISIBILITY_PRESET hidden)
  target_compile_definitions(sqlite3 PRIVATE
    "SQLITE_API=__attribute__((visibility(\"default\")))")
endif()

set(SQLITE_LIBRARIES "sqlite3")
