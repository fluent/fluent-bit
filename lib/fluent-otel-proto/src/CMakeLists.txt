set(OTEL_C_FILES ${PROJECT_SOURCE_DIR}/proto_c/opentelemetry)

set(src
	fluent-otel.c
	${PROJECT_SOURCE_DIR}/proto_c/protobuf-c/protobuf-c.c
	)

include_directories(
	${PROJECT_SOURCE_DIR}/include
	${PROJECT_BINARY_DIR}
	${PROJECT_SOURCE_DIR}/proto_c/
	)

if (FLUENT_PROTO_COMMON)
	set(src ${src} ${OTEL_C_FILES}/proto/common/v1/common.pb-c.c)
endif()

if (FLUENT_PROTO_RESOURCE)
	set(src ${src} ${OTEL_C_FILES}/proto/resource/v1/resource.pb-c.c)
endif()

if (FLUENT_PROTO_TRACE)
	set(src ${src} ${OTEL_C_FILES}/proto/trace/v1/trace.pb-c.c)
	set(src ${src} ${OTEL_C_FILES}/proto/collector/trace/v1/trace_service.pb-c.c)
endif()

if (FLUENT_PROTO_LOGS)
	set(src ${src} ${OTEL_C_FILES}/proto/logs/v1/logs.pb-c.c)
	set(src ${src} ${OTEL_C_FILES}/proto/collector/logs/v1/logs_service.pb-c.c)
endif()

if (FLUENT_PROTO_METRICS)
	set(src ${src} ${OTEL_C_FILES}/proto/metrics/v1/metrics.pb-c.c)
	set(src ${src} ${OTEL_C_FILES}/proto/collector/metrics/v1/metrics_service.pb-c.c)
endif()

if (FLUENT_PROTO_PROFILES)
	set(src ${src} ${OTEL_C_FILES}/proto/profiles/v1development/profiles.pb-c.c)
	set(src ${src} ${OTEL_C_FILES}/proto/profiles/v1development/pprofextended.pb-c.c)
	set(src ${src} ${OTEL_C_FILES}/proto/collector/profiles/v1development/profiles_service.pb-c.c)
endif()

add_library(fluent-otel-proto STATIC ${src})
