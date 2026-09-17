# Experimental browser cross-compilation profile, distinct from FLB_WASM
# (which embeds WAMR in a native Fluent Bit process).
if(NOT CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  message(FATAL_ERROR
    "FLB_WASM_BROWSER requires Emscripten. Use: "
    "emcmake cmake -S . -B build-wasm -DFLB_WASM_BROWSER=ON")
endif()

# Keep compiler and runtime shims in lockstep. Check before downloading or
# compiling dependencies; a different SDK needs the complete validation matrix.
file(STRINGS "${CMAKE_CURRENT_LIST_DIR}/../.emscripten-version" FLB_WASM_EMSCRIPTEN_VERSION LIMIT_COUNT 1)
if(NOT EMSCRIPTEN_VERSION VERSION_EQUAL FLB_WASM_EMSCRIPTEN_VERSION)
  message(FATAL_ERROR
    "FLB_WASM_BROWSER requires Emscripten ${FLB_WASM_EMSCRIPTEN_VERSION} (found '${EMSCRIPTEN_VERSION}')")
endif()

# Reject incompatible overrides instead of silently producing a native or
# browser-incompatible build. These are profile constraints, not defaults.
foreach(option_name
    FLB_ALL FLB_DEV FLB_BINARY FLB_SHARED_LIB FLB_EXAMPLES
    FLB_TESTS_RUNTIME FLB_TESTS_INTERNAL FLB_TESTS_INTERNAL_FUZZ
    FLB_TESTS_OSSFUZZ FLB_BENCHMARKS FLB_COVERAGE
    FLB_TLS FLB_AWS FLB_SIGNV4 FLB_AWS_ERROR_REPORTER
    FLB_HTTP_SERVER FLB_CHUNK_TRACE FLB_SQLDB
    FLB_JEMALLOC FLB_BACKTRACE FLB_VALGRIND FLB_MTRACE FLB_INOTIFY
    FLB_LUAJIT FLB_WASM FLB_WAMRC FLB_WASM_STACK_PROTECT
    FLB_KAFKA FLB_ZIG FLB_RIPSER FLB_USE_RIPSER
    FLB_PROXY_GO FLB_CUSTOM_CALYPTIA FLB_AVRO_ENCODER FLB_ARROW
    FLB_UNICODE_ENCODER FLB_USE_SIMDUTF FLB_STATIC_CONF
    FLB_EVENT_LOOP_EPOLL FLB_EVENT_LOOP_KQUEUE
    FLB_EVENT_LOOP_SELECT FLB_EVENT_LOOP_LIBEVENT
    FLB_PREFER_SYSTEM_LIBS FLB_PREFER_SYSTEM_LIB_BACKTRACE
    FLB_PREFER_SYSTEM_LIB_CARES FLB_PREFER_SYSTEM_LIB_JEMALLOC
    FLB_PREFER_SYSTEM_LIB_KAFKA FLB_PREFER_SYSTEM_LIB_LUAJIT
    FLB_PREFER_SYSTEM_LIB_MSGPACK FLB_PREFER_SYSTEM_LIB_NGHTTP2
    FLB_PREFER_SYSTEM_LIB_SQLITE FLB_PREFER_SYSTEM_LIB_ZSTD)
  if(${option_name})
    message(FATAL_ERROR "${option_name} is not supported by the browser build profile")
  endif()
  set(${option_name} OFF CACHE BOOL "Disabled by the browser build profile")
endforeach()

set(FLB_SIMD "Off" CACHE STRING "Enable SIMD support (On, Off, Auto)")
set(FLB_IPO "Off" CACHE STRING "Build with interprocedural optimization")
set(FLB_SECURITY "Off" CACHE STRING "Build with security optimizations")
set(FLB_EVENT_LOOP_POLL ON CACHE BOOL "Enable poll(2) event loop backend")
set(CIO_BACKEND_FILESYSTEM ON CACHE BOOL "Enable browser virtual filesystem chunks" FORCE)
set(FLB_CONFIG_YAML ON CACHE BOOL "Enable browser YAML configuration")
set(FLB_WASM_LUA ON CACHE BOOL "Enable portable Lua in the browser build")
set(LIBCO_TESTS ON CACHE BOOL "Build coroutine tests")

# Emscripten supplies linkable stubs for several unavailable OS services.
# Compilation probes cannot establish that these services work in a browser.
foreach(feature FLB_HAVE_FORK FLB_HAVE_SYS_WAIT_H FLB_HAVE_ACCEPT4 FLB_HAVE_UNIX_SOCKET)
  set(${feature} OFF CACHE INTERNAL "Unavailable in browsers" FORCE)
endforeach()

# Candidate local-data plugins and the Fetch-backed HTTP output. Inclusion is a compilation
# target, not a claim of browser runtime support. Keep new plugins opt-in.
set(FLB_WASM_BROWSER_PLUGINS
  FLB_IN_DUMMY
  FLB_IN_EMITTER
  FLB_IN_EVENT_TYPE
  FLB_IN_FLUENTBIT_METRICS
  FLB_IN_FLUENTBIT_LOGS
  FLB_IN_LIB
  FLB_IN_RANDOM
  FLB_IN_STORAGE_BACKLOG
  FLB_PROCESSOR_CONTENT_MODIFIER
  FLB_PROCESSOR_CUMULATIVE_TO_DELTA
  FLB_PROCESSOR_LABELS
  FLB_PROCESSOR_METRICS_SELECTOR
  FLB_PROCESSOR_OPENTELEMETRY_ENVELOPE
  FLB_PROCESSOR_SQL
  FLB_PROCESSOR_SAMPLING
  FLB_FILTER_ALTER_SIZE
  FLB_FILTER_EXPECT
  FLB_FILTER_GREP
  FLB_FILTER_LOG_TO_METRICS
  FLB_FILTER_LUA
  FLB_FILTER_MODIFY
  FLB_FILTER_MULTILINE
  FLB_FILTER_NEST
  FLB_FILTER_PARSER
  FLB_FILTER_RECORD_MODIFIER
  FLB_FILTER_REWRITE_TAG
  FLB_FILTER_STDOUT
  FLB_FILTER_THROTTLE
  FLB_FILTER_TYPE_CONVERTER
  FLB_OUT_COUNTER
  FLB_OUT_FLOWCOUNTER
  FLB_OUT_HTTP
  FLB_OUT_LOKI
  FLB_OUT_OPENTELEMETRY
  FLB_OUT_LIB
  FLB_OUT_NULL
  FLB_OUT_STDOUT)

if(NOT FLB_WASM_LUA)
  list(REMOVE_ITEM FLB_WASM_BROWSER_PLUGINS FLB_FILTER_LUA)
endif()

# Compile every dependency with the same threading ABI. The embedding API
# must dispatch engine operations to a worker, never the browser main thread.
add_compile_options(-pthread)
set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -pthread")
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -pthread")

message(STATUS "Experimental browser profile: worker runtime, virtual filesystem, and Fetch HTTPS output")
