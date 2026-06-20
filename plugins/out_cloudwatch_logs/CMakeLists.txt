set(src
  cloudwatch_logs.c
  cloudwatch_api.c)

FLB_PLUGIN(out_cloudwatch_logs "${src}" "")
