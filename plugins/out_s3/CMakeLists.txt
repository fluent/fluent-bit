set(src
  s3.c
  s3_store.c
  s3_multipart.c)

FLB_PLUGIN(out_s3 "${src}" "")
