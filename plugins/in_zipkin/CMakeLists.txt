if(NOT FLB_HTTP_SERVER)
  message(FATAL_ERROR "Zipkin input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  zipkin.c
  zipkin_decoder.c
  )

FLB_PLUGIN(in_zipkin "${src}" "monkey-core-static")
