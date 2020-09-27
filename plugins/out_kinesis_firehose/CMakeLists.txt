set(src
  firehose.c
  firehose_api.c)

FLB_PLUGIN(out_kinesis_firehose "${src}" "")
