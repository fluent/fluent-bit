set(src
  http.c
  http_conn.c
  http_prot.c
  http_config.c
  )

FLB_PLUGIN(in_http2 "${src}" "monkey-core-static" "nghttp2")
