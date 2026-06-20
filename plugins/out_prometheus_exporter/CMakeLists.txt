if(NOT FLB_HTTP_SERVER)
  message(
    FATAL_ERROR
    "Prometheus Exporter output plugin requires built-in HTTP Server be enabled:
     Use -DFLB_HTTP_SERVER=On option to enable it"
    )
endif()

set(src
  prom_http.c
  prom.c
  )

FLB_PLUGIN(out_prometheus_exporter "${src}" "")
