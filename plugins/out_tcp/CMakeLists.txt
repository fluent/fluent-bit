set(src
  tcp.c
  tcp_conf.c
  )

FLB_PLUGIN(out_tcp "${src}" "mk_core")
