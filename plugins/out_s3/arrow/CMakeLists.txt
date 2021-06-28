set(src
    compress.c)

add_library(out-s3-arrow STATIC ${src})

target_include_directories(out-s3-arrow PRIVATE ${ARROW_GLIB_INCLUDE_DIRS})
target_link_libraries(out-s3-arrow ${ARROW_GLIB_LDFLAGS})
