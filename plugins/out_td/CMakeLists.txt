set(src
  td_config.c
  td.c)

FLB_PLUGIN(out_td "${src}" "mk_config")
target_link_libraries(flb-plugin-out_td "z")
