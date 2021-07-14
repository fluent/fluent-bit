set(src
  nginx_stub_status.c
  nginx_stub_status_config.c)

FLB_PLUGIN(in_nginx_stub_status "${src}" "")
