set(src
  in_kafka.c
  )

FLB_PLUGIN(in_kafka "${src}" ${KAFKA_LIBRARIES} flb-aws)
if(DEFINED KAFKA_INCLUDEDIR)
  target_include_directories(flb-plugin-in_kafka PUBLIC ${KAFKA_INCLUDEDIR}/librdkafka)
endif()
target_link_libraries(flb-plugin-in_kafka -lpthread)
