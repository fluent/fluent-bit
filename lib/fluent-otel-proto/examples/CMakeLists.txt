set(src test-api.c)

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(${PROJECT_SOURCE_DIR}/proto_c)

add_executable(test-api ${src})
target_link_libraries(test-api fluent-otel-proto)
