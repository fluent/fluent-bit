if(NOT FLB_METRICS)
  message(FATAL_ERROR "OpenTelemetry input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  http_conn.c
  opentelemetry.c
  opentelemetry_prot.c
  opentelemetry_config.c
  )

FLB_PLUGIN(in_opentelemetry "${src}" "monkey-core-static")
