set(src
  datadog.c
  datadog_conf.c
  datadog_remap.c)

FLB_PLUGIN(out_datadog "${src}" "")
