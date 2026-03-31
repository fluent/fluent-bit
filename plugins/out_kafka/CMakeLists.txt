# Fluent Bit Kafka Output plugin
set(src
  kafka_config.c
  kafka_topic.c
  kafka.c)

FLB_PLUGIN(out_kafka "${src}" ${KAFKA_LIBRARIES} flb-aws)
if(DEFINED KAFKA_INCLUDEDIR)
  target_include_directories(flb-plugin-out_kafka PUBLIC ${KAFKA_INCLUDEDIR}/librdkafka)
endif()
target_link_libraries(flb-plugin-out_kafka -lpthread)
