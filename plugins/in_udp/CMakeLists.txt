set(src
  udp_conf.c
  udp_server.c
  udp_conn.c
  udp_prot.c
  udp.c)

FLB_PLUGIN(in_udp "${src}" "")
