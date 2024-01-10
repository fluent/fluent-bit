if(NOT FLB_HTTP_SERVER)
  message(
    FATAL_ERROR
    "Vivo Exporter output plugin requires built-in HTTP Server be enabled:
     Use -DFLB_HTTP_SERVER=On option to enable it"
    )
endif()

set(src
  vivo_http.c
  vivo_stream.c
  vivo.c
  )

FLB_PLUGIN(out_vivo_exporter "${src}" "")
