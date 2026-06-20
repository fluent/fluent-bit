set(src
  tcp.c
  tcp_conn.c
  tcp_config.c)

FLB_PLUGIN(in_tcp "${src}" "")
