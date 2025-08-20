
set (CJSON_DIR ${CMAKE_CURRENT_LIST_DIR})

include_directories(${CJSON_DIR})


file (GLOB_RECURSE source_all ${CJSON_DIR}/*.c)

set (CJSON_SOURCE ${source_all})

