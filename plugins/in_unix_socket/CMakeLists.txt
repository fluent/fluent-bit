set(src
  unix_socket.c
  unix_socket_conn.c
  unix_socket_config.c)

FLB_PLUGIN(in_unix_socket "${src}" "")
