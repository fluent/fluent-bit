set(src
  datadog.c
  datadog_conf.c)

FLB_PLUGIN(out_datadog "${src}" "")
