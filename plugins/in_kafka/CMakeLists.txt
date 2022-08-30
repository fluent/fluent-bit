set(src
  in_kafka.c
  )

FLB_PLUGIN(in_kafka "${src}" "rdkafka")
target_link_libraries(flb-plugin-in_kafka -lpthread)
