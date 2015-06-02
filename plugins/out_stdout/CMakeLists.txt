set(src
  stdout.c)

FLB_PLUGIN(out_stdout "${src}" "")
target_link_libraries(flb-plugin-out_stdout msgpack)
