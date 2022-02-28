set(src
  opentelemetry.c
  opentelemetry_conf.c
  )

FLB_PLUGIN(out_opentelemetry "${src}" "")
