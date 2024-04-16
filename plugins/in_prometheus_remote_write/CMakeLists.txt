if(NOT FLB_METRICS)
  message(FATAL_ERROR "Prometheus remote write input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  in_prometheus_remote_write.c
  in_prometheus_remote_write_prot.c
  in_prometheus_remote_write_conn.c
  in_prometheus_remote_write_config.c
  )

FLB_PLUGIN(in_prometheus_remote_write "${src}" "monkey-core-static")
