# Build librdkafka
FLB_OPTION(RDKAFKA_BUILD_STATIC    On)
FLB_OPTION(RDKAFKA_BUILD_EXAMPLES Off)
FLB_OPTION(RDKAFKA_BUILD_TESTS    Off)
add_subdirectory(librdkafka-0.11.6 EXCLUDE_FROM_ALL)

# librdkafka headers
include_directories(librdkafka-0.11.6/src/)

# Fluent Bit Kafka Output plugin
set(src
  kafka_config.c
  kafka_topic.c
  kafka.c)

FLB_PLUGIN(out_kafka "${src}" "rdkafka")
target_link_libraries(flb-plugin-out_kafka -lpthread)
