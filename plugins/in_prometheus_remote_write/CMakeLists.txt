if(NOT FLB_METRICS)
  message(FATAL_ERROR "Prometheus remote write input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  prom_rw.c
  prom_rw_prot.c
  prom_rw_conn.c
  prom_rw_config.c
  )

FLB_PLUGIN(in_prometheus_remote_write "${src}" "monkey-core-static")
