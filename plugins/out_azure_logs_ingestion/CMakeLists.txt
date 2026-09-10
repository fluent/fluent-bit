set(src
  azure_logs_ingestion.c
  azure_logs_ingestion_conf.c
  )

if(FLB_SQLDB)
  list(APPEND src azure_logs_ingestion_batch.c)
endif()

FLB_PLUGIN(out_azure_logs_ingestion "${src}" "")
