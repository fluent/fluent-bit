set(src
  td_http.c
  td_config.c
  td.c)

FLB_PLUGIN(out_td "${src}" "mk_core")
target_link_libraries(flb-plugin-out_td)
