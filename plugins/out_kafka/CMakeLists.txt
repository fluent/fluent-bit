# Fluent Bit Kafka Output plugin
set(src
  kafka_config.c
  kafka_schema_registry.c
  kafka_topic.c
  kafka.c)

FLB_PLUGIN(out_kafka "${src}" ${KAFKA_LIBRARIES} flb-aws)
if(DEFINED KAFKA_INCLUDEDIR)
  target_include_directories(flb-plugin-out_kafka PUBLIC ${KAFKA_INCLUDEDIR}/librdkafka)
endif()
target_link_libraries(flb-plugin-out_kafka -lpthread)

if(FLB_PROTOBUF_ENCODER)
  target_sources(flb-plugin-out_kafka PRIVATE kafka_protobuf.cpp)
  target_compile_features(flb-plugin-out_kafka PRIVATE cxx_std_11)
  target_link_libraries(flb-plugin-out_kafka protobuf::libprotobuf protobuf::libprotoc)
endif()
if(FLB_AVRO_ENCODER OR FLB_PROTOBUF_ENCODER)
  target_link_libraries(flb-plugin-out_kafka jansson)
endif()
