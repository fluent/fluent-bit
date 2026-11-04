# Both source forms are prepared by tools/update-sqlite.py and committed.
# Configuration and compilation never download or regenerate SQLite sources.
set(flb_sqlite_dir "${FLB_PATH_ROOT_SOURCE}/${FLB_PATH_LIB_SQLITE}")
include_directories("${flb_sqlite_dir}")

if(FLB_SQLITE_AMALGAMATION)
  set(flb_sqlite_sources "${flb_sqlite_dir}/sqlite3.c")
else()
  include("${flb_sqlite_dir}/sources.cmake")
endif()

add_library(sqlite3 STATIC ${flb_sqlite_sources})
target_include_directories(sqlite3 PRIVATE "${flb_sqlite_dir}" "${flb_sqlite_dir}/src")
target_link_libraries(sqlite3 ${CMAKE_DL_LIBS})

if(NOT FLB_SQLITE_AMALGAMATION)
  target_compile_definitions(sqlite3 PRIVATE SQLITE_CORE)
  # Amalgamation makes internal functions static. Preserve that visibility
  # when the same functions are linked across separate translation units.
  if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang|IntelLLVM")
    set_target_properties(sqlite3 PROPERTIES C_VISIBILITY_PRESET hidden)
    target_compile_definitions(sqlite3 PRIVATE
      "SQLITE_API=__attribute__((visibility(\"default\")))")
  endif()
endif()

set(SQLITE_LIBRARIES "sqlite3")
