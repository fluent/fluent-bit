set(src
  nginx_status.c
  nginx_status_config.c)

FLB_PLUGIN(in_nginx_status "${src}" "")
