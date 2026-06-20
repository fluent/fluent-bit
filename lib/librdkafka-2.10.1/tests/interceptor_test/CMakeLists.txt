set(
    sources
    interceptor_test.c
)


add_library(interceptor_test SHARED ${sources})

target_include_directories(interceptor_test PUBLIC ${PROJECT_SOURCE_DIR}/src)

target_link_libraries(interceptor_test PUBLIC rdkafka)

# Remove "lib" prefix
set_target_properties(interceptor_test PROPERTIES PREFIX "")
set_target_properties(interceptor_test PROPERTIES
                      LIBRARY_OUTPUT_DIRECTORY ${tests_OUTPUT_DIRECTORY}/interceptor_test/)
