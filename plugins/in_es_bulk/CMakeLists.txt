if(NOT FLB_METRICS)
  message(FATAL_ERROR "ES Bulk input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  es_bulk.c
  es_bulk_conn.c
  es_bulk_prot.c
  es_bulk_config.c
  )

FLB_PLUGIN(in_es_bulk "${src}" "monkey-core-static")
