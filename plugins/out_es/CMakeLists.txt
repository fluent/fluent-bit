set(src
  es_bulk.c
  es.c)

FLB_PLUGIN(out_es "${src}" "mk_core")
target_link_libraries(flb-plugin-out_es "cJSON" "m")
