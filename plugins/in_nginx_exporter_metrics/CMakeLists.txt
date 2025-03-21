set(src
  nginx.c)

FLB_PLUGIN(in_nginx_exporter_metrics "${src}" "")
