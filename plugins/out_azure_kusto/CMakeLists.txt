set(src
  azure_kusto.c
  azure_kusto_conf.c
  azure_kusto_ingest.c
  azure_msiauth.c
  azure_kusto_store.c
  )

FLB_PLUGIN(out_azure_kusto "${src}" "")