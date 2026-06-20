set(src
  udp.c
  udp_conn.c
  udp_config.c)

FLB_PLUGIN(in_udp "${src}" "")
