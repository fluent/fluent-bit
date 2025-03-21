if(NOT FLB_METRICS)
  message(FATAL_ERROR "Splunk input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  splunk.c
  splunk_conn.c
  splunk_prot.c
  splunk_config.c
  )

FLB_PLUGIN(in_splunk "${src}" "monkey-core-static")
