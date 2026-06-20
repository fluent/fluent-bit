set(src
  out_lib.c)

FLB_PLUGIN(out_lib "${src}" "")
#target_link_libraries(flb-plugin-out_lib msgpack)
