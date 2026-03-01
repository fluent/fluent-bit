set(src
  s3.c
  s3_store.c
  s3_stream.c
  s3_multipart.c
  s3_blob.c
  s3_auth.c
  s3_queue.c)

FLB_PLUGIN(out_s3 "${src}" "")
