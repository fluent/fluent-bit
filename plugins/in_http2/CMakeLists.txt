set(src
  http2.c
  http2_prot.c
  http2_config.c

  flb_http_server.c
  flb_http_common.c
  flb_http_server_http1.c
  flb_http_server_http2.c
  )

FLB_PLUGIN(in_http2 "${src}" "monkey-core-static" "nghttp2")
