if(NOT FLB_METRICS)
  message(FATAL_ERROR "Elasticsearch input plugin requires FLB_HTTP_SERVER=On.")
endif()

set(src
  in_elasticsearch.c
  in_elasticsearch_config.c
  in_elasticsearch_bulk_conn.c
  in_elasticsearch_bulk_prot.c
  )

FLB_PLUGIN(in_elasticsearch "${src}" "")
