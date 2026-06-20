set(src
  metrics.c
  )

FLB_PLUGIN(in_fluentbit_metrics "${src}" "")
