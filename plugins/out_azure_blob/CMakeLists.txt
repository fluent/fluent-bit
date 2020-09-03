set(src
  azure_blob.c
  azure_blob_conf.c
  )

FLB_PLUGIN(out_azure_blob "${src}" "")
