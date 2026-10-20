set(src
    compress.c)

if(FLB_PROTOBUF)
  list(APPEND src protobuf.cpp)
endif()

add_library(flb-aws-arrow STATIC ${src})

target_include_directories(flb-aws-arrow PRIVATE ${ARROW_GLIB_INCLUDE_DIRS})
target_link_libraries(flb-aws-arrow ${ARROW_GLIB_LDFLAGS})

if(FLB_PROTOBUF)
  target_compile_features(flb-aws-arrow PRIVATE cxx_std_11)
  target_link_libraries(flb-aws-arrow protobuf::libprotobuf)
endif()

if (ARROW_GLIB_PARQUET_FOUND)
target_include_directories(flb-aws-arrow PRIVATE ${ARROW_GLIB_PARQUET_INCLUDE_DIRS})
target_link_libraries(flb-aws-arrow ${ARROW_GLIB_PARQUET_LDFLAGS})
endif()

if(FLB_JEMALLOC)
  target_link_libraries(flb-aws-arrow ${JEMALLOC_LIBRARIES})
endif()
