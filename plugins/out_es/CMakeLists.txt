set(src
  es_bulk.c
  es_type.c
  es_conf_parse.c
  es_conf.c
  es.c
  murmur3.c)

FLB_PLUGIN(out_es "${src}" "mk_core")
target_link_libraries(flb-plugin-out_es)
