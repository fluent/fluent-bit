set(src
  azure_logs_ingestion.c
  azure_logs_ingestion_conf.c
  )

FLB_PLUGIN(out_azure_logs_ingestion "${src}" "")
