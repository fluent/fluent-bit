set(src
  es_bulk.c
  es_http.c
  es_config.c
  es.c)

FLB_PLUGIN(out_es "${src}" "mk_core")
