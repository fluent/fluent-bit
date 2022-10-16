# Fluent Bit Kafka Output plugin
set(src
  kafka_config.c
  kafka_topic.c
  kafka.c)

FLB_PLUGIN(out_kafka "${src}" "rdkafka")
if (NOT MSVC)
  target_link_libraries(flb-plugin-out_kafka -lpthread)
endif()
