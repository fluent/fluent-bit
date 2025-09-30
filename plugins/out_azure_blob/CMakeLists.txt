set(src
  azure_blob.c
  azure_blob_uri.c
  azure_blob_conf.c
  azure_blob_http.c
  azure_blob_db.c
  azure_blob_appendblob.c
  azure_blob_blockblob.c
  azure_blob_store.c
  )

FLB_PLUGIN(out_azure_blob "${src}" "")
