set(src
  http2.c
  http2_prot.c
  http2_config.c
  )

FLB_PLUGIN(in_http2 "${src}" "")
