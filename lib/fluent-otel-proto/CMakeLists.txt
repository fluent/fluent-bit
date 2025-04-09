cmake_minimum_required(VERSION 3.20)
project(fluent-opentelemetry-proto C)

# Include helpers
include(cmake/macros.cmake)

# We only regenerate files if it has been enabled
option(FLUENT_PROTO_REGENERATE "Regenerate .[ch] files only"  "No")

# build options for files generation
option(FLUENT_PROTO_COMMON   "Include common.proto"          "Yes")
option(FLUENT_PROTO_RESOURCE "Include resource.proto"        "Yes")
option(FLUENT_PROTO_TRACE    "Include trace.proto"           "Yes")
option(FLUENT_PROTO_LOGS     "Include logs.proto"            "Yes")
option(FLUENT_PROTO_METRICS  "Inlcude metrics.proto"         "Yes")
option(FLUENT_PROTO_PROFILES "Includes profiles proto files" "Yes")
option(FLUENT_PROTO_EXAMPLES "Add example programs"          "Yes")

# extra options
option(FLUENT_PROTO_TOOLS    "Generate tools"                "No")

if(FLUENT_PROTO_REGENERATE AND (NOT PROTOBUF_C_SOURCE_DIR OR NOT OTEL_PROTO_DIR))
	if (NOT PROTOBUF_C_SOURCE_DIR)
		message(FATAL_ERROR
			"\n"
			"The variable PROTOBUF_C_SOURCE_DIR has not been defined. "
			"You have to specify which directory contains the source code "
			"of the repository https://github.com/fluent/protobuf-c\n"
			"Define the path with: -DPROTOBUF_C_SOURCE_DIR=/path/to/protobuf-c")
	endif()

	if (NOT OTEL_PROTO_DIR)
		message(FATAL_ERROR
			"\n"
			"The variable OTEL_PROTO_DIR has not been defined. "
			"You have to specify which directory contains the source code "
			"of the repository https://github.com/open-telemetry/opentelemetry-proto\n"
			"Define the path with: -DOTEL_PROTO_DIR=/path/to/opentelemetry-proto")
	endif()
else()
	if (FLUENT_PROTO_REGENERATE)
		message(STATUS "protobuf-c directory: ${PROTOBUF_C_SOURCE_DIR}")
	endif()
endif()

# Paths
set(PROTOC_BIN                "/opt/protobuf-c/bin/protoc-c")
set(PROTOC_ARG_OUT            "--c_out=${PROJECT_SOURCE_DIR}/proto_c/")
set(PROTOC_ARG_PATH           "--proto_path=${OTEL_PROTO_DIR}/")

if (FLUENT_PROTO_REGENERATE)
	# final protoc base command
	message(STATUS "base command: ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH}")

	# Protobuf-c headers (this is not working, I ended up copying protobuf-c headers inside include/)
	set(PROTOC_HEADERS "/opt/protobuf-c/include/")
	include_directories(PROTOC_HEADERS)

	if (FLUENT_PROTO_COMMON)
		message(STATUS "processing common.proto")
		set(proto_file ${OTEL_PROTO_DIR}/opentelemetry/proto/common/v1/common.proto)
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/common/v1/)
		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_COMMON)
	endif()

	if (FLUENT_PROTO_RESOURCE)
		message(STATUS "processing resource.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/resource/v1/resource.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/resource/v1/)
		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_RESOURCE)
	endif()

	if (FLUENT_PROTO_TRACE)
		message(STATUS "processing trace.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/trace/v1/trace.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/trace/v1/)

		message(STATUS "processing trace_service.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/collector/trace/v1/trace_service.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/collector/trace/v1)
		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_TRACE)
	endif()

	if (FLUENT_PROTO_LOGS)
		message(STATUS "processing logs.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/logs/v1/logs.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/logs/v1/)

		message(STATUS "processing logs_service.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/collector/logs/v1/logs_service.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})
		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/collector/logs/v1/)

		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_LOGS)
	endif()

	if (FLUENT_PROTO_METRICS)
		message(STATUS "processing metrics.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/metrics/v1/metrics.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})

		message(STATUS "processing metrics_service.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/collector/metrics/v1/metrics_service.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})

		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/metrics/v1/)
		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_METRICS)
	endif()

	if (FLUENT_PROTO_PROFILES)
		message(STATUS "processing profiles.proto")
		set(proto_file "${OTEL_PROTO_DIR}/opentelemetry/proto/profiles/v1development/profiles.proto")
		execute_process(COMMAND ${PROTOC_BIN} ${PROTOC_ARG_OUT} ${PROTOC_ARG_PATH} ${proto_file})

		include_directories(${PROJECT_BINARY_DIR}/opentelemetry/proto/profiles/v1development/)
		FLUENT_OTEL_DEFINITION(FLUENT_OTEL_HAVE_PROFILES)
	endif()

	configure_file(
	  "${PROJECT_SOURCE_DIR}/include/fluent-otel-proto/fluent-otel-info.h.in"
	  "${PROJECT_SOURCE_DIR}/include/fluent-otel-proto/fluent-otel-info.h"
	  )

	# protobuf-c dependency
	configure_file(
		"${PROTOBUF_C_SOURCE_DIR}/protobuf-c/protobuf-c.c"
		"${PROJECT_SOURCE_DIR}/proto_c/protobuf-c/protobuf-c.c" COPYONLY)

	configure_file(
		"${PROTOBUF_C_SOURCE_DIR}/protobuf-c/protobuf-c.h"
		"${PROJECT_SOURCE_DIR}/proto_c/protobuf-c/protobuf-c.h" COPYONLY)

endif()

# build library
add_subdirectory(src)

# build example
if (FLUENT_PROTO_EXAMPLES)
	add_subdirectory(examples)
endif()

# build tools
if (FLUENT_PROTO_TOOLS)
	add_subdirectory(tools)
endif()
