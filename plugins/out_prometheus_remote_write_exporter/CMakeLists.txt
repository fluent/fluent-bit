set(src
  prom.c
  )

FLB_PLUGIN(out_prometheus_remote_write_exporter "${src}" "")
