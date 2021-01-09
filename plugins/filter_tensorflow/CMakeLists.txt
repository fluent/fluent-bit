set(src
  tensorflow.c)

FLB_PLUGIN(filter_tensorflow "${src}" "")
target_include_directories(flb-plugin-filter_tensorflow PRIVATE ${Tensorflow_DIR})
target_link_libraries(flb-plugin-filter_tensorflow -ltensorflowlite_c)
