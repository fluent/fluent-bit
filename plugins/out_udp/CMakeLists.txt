set(src
  udp.c
  udp_conf.c
  )

FLB_PLUGIN(out_udp "${src}" "mk_core")
