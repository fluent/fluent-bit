set(src
  websocket_conf.c
  websocket.c)

FLB_PLUGIN(out_websocket "${src}" "")
