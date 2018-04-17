if(WIN32)
    set(win32_sources ../win32/wingetopt.c ../win32/wingetopt.h)
    set(win32_compile_defs "LIBRDKAFKACPP_EXPORTS=0")
endif(WIN32)

add_executable(rdkafka_simple_producer rdkafka_simple_producer.c ${win32_sources})
target_link_libraries(rdkafka_simple_producer PUBLIC rdkafka)

add_executable(rdkafka_performance rdkafka_performance.c ${win32_sources})
target_link_libraries(rdkafka_performance PUBLIC rdkafka)

add_executable(rdkafka_example_cpp rdkafka_example.cpp ${win32_sources})
target_link_libraries(rdkafka_example_cpp PUBLIC rdkafka++)
target_compile_definitions(rdkafka_example_cpp PRIVATE ${win32_compile_defs})

add_executable(rdkafka_consumer_example_cpp rdkafka_consumer_example.cpp ${win32_sources})
target_link_libraries(rdkafka_consumer_example_cpp PUBLIC rdkafka++)
target_compile_definitions(rdkafka_consumer_example_cpp PRIVATE ${win32_compile_defs})

# The targets below has Unix include dirs and do not compile on Windows.
if(NOT WIN32)
    add_executable(rdkafka_example rdkafka_example.c)
    target_link_libraries(rdkafka_example PUBLIC rdkafka)
    
    add_executable(rdkafka_consumer_example rdkafka_consumer_example.c)
    target_link_libraries(rdkafka_consumer_example PUBLIC rdkafka)
    
    add_executable(kafkatest_verifiable_client kafkatest_verifiable_client.cpp)
    target_link_libraries(kafkatest_verifiable_client PUBLIC rdkafka++)
endif(NOT WIN32)