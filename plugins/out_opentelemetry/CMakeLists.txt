set(src
  opentelemetry_common.pb-c.c
  opentelemetry_logs.pb-c.c
  opentelemetry_logs_service.pb-c.c
  opentelemetry.c
  opentelemetry_conf.c
  )

FLB_PLUGIN(out_opentelemetry "${src}" "")
