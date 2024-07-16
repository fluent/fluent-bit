if(WIN32)
    set(win32_sources ../win32/wingetopt.c ../win32/wingetopt.h)
endif(WIN32)

add_executable(producer producer.c ${win32_sources})
target_link_libraries(producer PUBLIC rdkafka)

add_executable(producer_cpp producer.cpp ${win32_sources})
target_link_libraries(producer_cpp PUBLIC rdkafka++)

add_executable(consumer consumer.c ${win32_sources})
target_link_libraries(consumer PUBLIC rdkafka)

add_executable(rdkafka_performance rdkafka_performance.c ${win32_sources})
target_link_libraries(rdkafka_performance PUBLIC rdkafka)

add_executable(rdkafka_example_cpp rdkafka_example.cpp ${win32_sources})
target_link_libraries(rdkafka_example_cpp PUBLIC rdkafka++)

add_executable(rdkafka_complex_consumer_example_cpp rdkafka_complex_consumer_example.cpp ${win32_sources})
target_link_libraries(rdkafka_complex_consumer_example_cpp PUBLIC rdkafka++)

add_executable(openssl_engine_example_cpp openssl_engine_example.cpp ${win32_sources})
target_link_libraries(openssl_engine_example_cpp PUBLIC rdkafka++)

add_executable(misc misc.c ${win32_sources})
target_link_libraries(misc PUBLIC rdkafka)

add_executable(idempotent_producer idempotent_producer.c ${win32_sources})
target_link_libraries(idempotent_producer PUBLIC rdkafka)

add_executable(transactions transactions.c ${win32_sources})
target_link_libraries(transactions PUBLIC rdkafka)

add_executable(delete_records delete_records.c ${win32_sources})
target_link_libraries(delete_records PUBLIC rdkafka)

add_executable(list_consumer_groups list_consumer_groups.c ${win32_sources})
target_link_libraries(list_consumer_groups PUBLIC rdkafka)

add_executable(describe_consumer_groups describe_consumer_groups.c ${win32_sources})
target_link_libraries(describe_consumer_groups PUBLIC rdkafka)

add_executable(list_consumer_group_offsets list_consumer_group_offsets.c ${win32_sources})
target_link_libraries(list_consumer_group_offsets PUBLIC rdkafka)

add_executable(alter_consumer_group_offsets alter_consumer_group_offsets.c ${win32_sources})
target_link_libraries(alter_consumer_group_offsets PUBLIC rdkafka)

add_executable(incremental_alter_configs incremental_alter_configs.c ${win32_sources})
target_link_libraries(incremental_alter_configs PUBLIC rdkafka)

add_executable(user_scram user_scram.c ${win32_sources})
target_link_libraries(user_scram PUBLIC rdkafka)

add_executable(describe_topics describe_topics.c ${win32_sources})
target_link_libraries(describe_topics PUBLIC rdkafka)

add_executable(describe_cluster describe_cluster.c ${win32_sources})
target_link_libraries(describe_cluster PUBLIC rdkafka)

add_executable(list_offsets list_offsets.c ${win32_sources})
target_link_libraries(list_offsets PUBLIC rdkafka)

# The targets below has Unix include dirs and do not compile on Windows.
if(NOT WIN32)
    add_executable(rdkafka_example rdkafka_example.c)
    target_link_libraries(rdkafka_example PUBLIC rdkafka)

    add_executable(rdkafka_complex_consumer_example rdkafka_complex_consumer_example.c)
    target_link_libraries(rdkafka_complex_consumer_example PUBLIC rdkafka)

    add_executable(kafkatest_verifiable_client kafkatest_verifiable_client.cpp)
    target_link_libraries(kafkatest_verifiable_client PUBLIC rdkafka++)

endif(NOT WIN32)
