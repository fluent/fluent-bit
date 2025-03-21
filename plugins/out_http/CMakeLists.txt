set(src
  http.c
  http_conf.c
  )

FLB_PLUGIN(out_http "${src}" "mk_core")
