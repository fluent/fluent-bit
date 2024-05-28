include_directories(${CMAKE_CURRENT_SOURCE_DIR})

# find_package(FLEX REQUIRED)
# find_package(BISON REQUIRED)

add_subdirectory(parser)

set(src
    sql_config.c
    sql.c)

FLB_PLUGIN(processor_sql "${src}" "processor-sql-parser")
