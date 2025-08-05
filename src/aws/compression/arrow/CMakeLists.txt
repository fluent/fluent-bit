set(src
    compress.c)

add_library(flb-aws-arrow STATIC ${src})

target_include_directories(flb-aws-arrow PRIVATE ${ARROW_GLIB_INCLUDE_DIRS})
target_link_libraries(flb-aws-arrow ${ARROW_GLIB_LIBRARIES})
if (ARROW_GLIB_PARQUET_FOUND)
target_include_directories(flb-aws-arrow PRIVATE ${ARROW_GLIB_PARQUET_INCLUDE_DIRS})
target_link_libraries(flb-aws-arrow ${ARROW_GLIB_PARQUET_LIBRARIES})
endif()
