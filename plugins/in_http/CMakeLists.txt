if(NOT FLB_METRICS)
  message(FATAL_ERROR "HTTP input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  http.c
  http_conn.c
  http_prot.c
  http_config.c
  )

FLB_PLUGIN(in_http "${src}" "monkey-core-static")
