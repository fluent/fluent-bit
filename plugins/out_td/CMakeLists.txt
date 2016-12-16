set(src
  td_http.c
  td_config.c
  td.c)

# Tweak Miniz library
add_definitions("-DMINIZ_NO_ARCHIVE_APIS -DMINIZ_NO_STDIO -DMINIZ_NO_TIME")

FLB_PLUGIN(out_td "${src}" "mk_core")
target_link_libraries(flb-plugin-out_td)
