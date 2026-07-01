set(src
  bigquery_conf.c
  bigquery.c
  )

FLB_PLUGIN(out_bigquery "${src}" "")
