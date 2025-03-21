set(src
  kinesis.c
  kinesis_api.c)

FLB_PLUGIN(out_kinesis_streams "${src}" "")
