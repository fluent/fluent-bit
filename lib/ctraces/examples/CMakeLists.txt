# example: simple C api usage
set(src
	simple-c-api.c
	)

add_executable(ctraces-simple-c-api ${src})
target_link_libraries(ctraces-simple-c-api ctraces-static fluent-otel-proto)

# example: opentelemetry decoder -> ctrace
set(src
	otlp-decoder.c
	)

add_executable(ctraces-otlp-decoder ${src})
target_link_libraries(ctraces-otlp-decoder ctraces-static)
configure_file(sample_trace.bin sample_trace.bin COPYONLY)

# example: opentelemetry encoder
set(src
	otlp-encoder/otlp-encoder.c
	)

add_executable(ctraces-otlp-encoder ${src})
target_link_libraries(ctraces-otlp-encoder ctraces-static curl)