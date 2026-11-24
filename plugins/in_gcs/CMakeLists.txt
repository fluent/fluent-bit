set(src
  gcs.c
  gcs_api.c
  gcs_record.c
  gcs_db.c)

FLB_PLUGIN(in_gcs "${src}" "")
