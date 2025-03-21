set(src
  kafka_conf.c
  kafka.c)

FLB_PLUGIN(out_kafka_rest "${src}" "")
