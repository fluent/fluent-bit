set(src
  in_kafka.c
  )

FLB_PLUGIN(in_kafka "${src}" ${KAFKA_LIBRARIES} flb-aws)
target_include_directories(flb-plugin-in_kafka PUBLIC ${KAFKA_INCLUDEDIR}/librdkafka)
target_link_libraries(flb-plugin-in_kafka -lpthread)
