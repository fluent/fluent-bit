set(src
  tda.c)

FLB_PLUGIN(processor_tda "${src}" "")
target_link_libraries(flb-plugin-processor_tda ripser-static flb-ripser-wrapper-static)
