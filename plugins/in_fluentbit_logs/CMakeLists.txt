set(src
  fluentbit_logs.c
  )

FLB_PLUGIN(in_fluentbit_logs "${src}" "")
