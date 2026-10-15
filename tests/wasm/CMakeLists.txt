# Exercise dependencies, event/coroutine portability, and the in-memory engine.
if(NOT FLB_YYJSON)
  message(FATAL_ERROR "The browser dependency smoke test requires FLB_YYJSON=ON")
endif()

add_executable(flb-wasm-dependencies dependencies.c)
target_link_libraries(flb-wasm-dependencies
  cmetrics-static ctraces-static cprofiles-static yyjson)
set_target_properties(flb-wasm-dependencies PROPERTIES
  LINK_FLAGS "-sASSERTIONS=2 -sEXIT_RUNTIME=1")

# Emscripten supplies Node through CMAKE_CROSSCOMPILING_EMULATOR.
if(CMAKE_CROSSCOMPILING_EMULATOR)
  add_test(NAME flb-wasm-dependencies COMMAND flb-wasm-dependencies)
endif()

if(FLB_CONFIG_YAML AND FLB_IN_DUMMY AND FLB_OUT_STDOUT AND
   FLB_PROCESSOR_CONTENT_MODIFIER AND FLB_PROCESSOR_SQL)
  add_executable(flb-wasm-demo demo.c)
  target_link_libraries(flb-wasm-demo fluent-bit-static)
  set_target_properties(flb-wasm-demo PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=8 -sSTACK_SIZE=262144 -sALLOW_MEMORY_GROWTH=1")
endif()

if(FLB_WASM_LUA)
  # Native internal tests are disabled in this profile. Generate their shared
  # harness in the build tree so a clean checkout can compile the Lua tests.
  set(FLB_TESTS_DATA_PATH "${PROJECT_SOURCE_DIR}/tests/internal/")
  configure_file("${PROJECT_SOURCE_DIR}/tests/internal/flb_tests_internal.h.in"
                 "${CMAKE_CURRENT_BINARY_DIR}/flb_tests_internal.h" @ONLY)
  add_executable(flb-wasm-lua "${PROJECT_SOURCE_DIR}/tests/internal/lua.c")
  target_include_directories(flb-wasm-lua PRIVATE
    "${CMAKE_CURRENT_BINARY_DIR}" "${PROJECT_SOURCE_DIR}/tests/internal")
  target_compile_definitions(flb-wasm-lua PRIVATE FLB_TEST_INIT_NOP FLB_TEST_FINI_NOP)
  target_link_libraries(flb-wasm-lua fluent-bit-static)
  set_target_properties(flb-wasm-lua PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1")
  add_test(NAME flb-wasm-lua COMMAND flb-wasm-lua --no-exec)
  set_tests_properties(flb-wasm-lua PROPERTIES TIMEOUT 30)
endif()

add_test(NAME flb-wasm-build-profile
  COMMAND ${CMAKE_COMMAND}
    -DTEST_BINARY_ROOT=${CMAKE_CURRENT_BINARY_DIR}/profile-tests
    -P ${CMAKE_CURRENT_SOURCE_DIR}/check_profile.cmake)

add_executable(flb-wasm-http http.c)
target_link_libraries(flb-wasm-http fluent-bit-static)
set_target_properties(flb-wasm-http PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sASYNCIFY=1 -sFORCE_FILESYSTEM=1")
add_test(NAME flb-wasm-http COMMAND flb-wasm-http)
set_tests_properties(flb-wasm-http PROPERTIES TIMEOUT 30)

add_executable(flb-wasm-http-lifecycle http_lifecycle.c)
target_link_libraries(flb-wasm-http-lifecycle fluent-bit-static)
set_target_properties(flb-wasm-http-lifecycle PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=1 -sSTACK_SIZE=262144 -sFORCE_FILESYSTEM=1")
add_test(NAME flb-wasm-http-lifecycle COMMAND flb-wasm-http-lifecycle)
set_tests_properties(flb-wasm-http-lifecycle PROPERTIES TIMEOUT 30)

add_executable(flb-wasm-http-ng http_ng.c)
target_link_libraries(flb-wasm-http-ng fluent-bit-static)
set_target_properties(flb-wasm-http-ng PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=1 -sSTACK_SIZE=262144")
add_test(NAME flb-wasm-http-ng COMMAND flb-wasm-http-ng)
set_tests_properties(flb-wasm-http-ng PROPERTIES TIMEOUT 30)
add_test(NAME flb-wasm-http-ng-objects COMMAND flb-wasm-http-ng --objects-only)
set_tests_properties(flb-wasm-http-ng-objects PROPERTIES TIMEOUT 30)

if(FLB_IN_LIB AND FLB_OUT_LIB AND FLB_FILTER_MODIFY AND FLB_FILTER_GREP)
  add_executable(flb-wasm-pipeline pipeline.c)
  target_link_libraries(flb-wasm-pipeline fluent-bit-static)
  set_target_properties(flb-wasm-pipeline PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=8 -sSTACK_SIZE=262144 -sALLOW_MEMORY_GROWTH=1")
  add_test(NAME flb-wasm-pipeline COMMAND flb-wasm-pipeline)
  set_tests_properties(flb-wasm-pipeline PROPERTIES TIMEOUT 45)
endif()

add_executable(flb-wasm-events "${PROJECT_SOURCE_DIR}/lib/monkey/test/wasm/events.c")
target_link_libraries(flb-wasm-events mk_core "-sASYNCIFY=1")
set_target_properties(flb-wasm-events PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=2 -sSTACK_SIZE=262144")
add_test(NAME flb-wasm-events COMMAND flb-wasm-events)
set_tests_properties(flb-wasm-events PROPERTIES TIMEOUT 30)

add_executable(flb-wasm-event-fiber event_fiber.c)
target_include_directories(flb-wasm-event-fiber PRIVATE "${PROJECT_SOURCE_DIR}/lib/flb_libco")
target_link_libraries(flb-wasm-event-fiber mk_core co)
set_target_properties(flb-wasm-event-fiber PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=2 -sSTACK_SIZE=262144")
add_test(NAME flb-wasm-event-fiber COMMAND flb-wasm-event-fiber)
set_tests_properties(flb-wasm-event-fiber PROPERTIES TIMEOUT 30)

add_executable(flb-wasm-storage "${PROJECT_SOURCE_DIR}/lib/chunkio/tests/browser_storage.c")
target_include_directories(flb-wasm-storage PRIVATE "${PROJECT_SOURCE_DIR}/lib/chunkio/deps")
target_link_libraries(flb-wasm-storage chunkio-static flb-wasm-filesystem)
set_target_properties(flb-wasm-storage PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=1 -sALLOW_MEMORY_GROWTH=1")
add_test(NAME flb-wasm-storage COMMAND flb-wasm-storage)
set_tests_properties(flb-wasm-storage PROPERTIES TIMEOUT 30)

if(FLB_CONFIG_YAML AND FLB_PROCESSOR_SQL AND
   FLB_PROCESSOR_CONTENT_MODIFIER AND FLB_PROCESSOR_CUMULATIVE_TO_DELTA AND
   FLB_PROCESSOR_LABELS AND FLB_PROCESSOR_METRICS_SELECTOR AND
   FLB_PROCESSOR_OPENTELEMETRY_ENVELOPE AND FLB_PROCESSOR_SAMPLING AND
   FLB_IN_LIB AND FLB_IN_EVENT_TYPE)
  add_executable(flb-wasm-yaml yaml.c)
  target_link_libraries(flb-wasm-yaml fluent-bit-static)
  set_property(TARGET flb-wasm-yaml PROPERTY LINK_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/data/processors.yaml")
  set_target_properties(flb-wasm-yaml PROPERTIES LINK_FLAGS
    "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=8 -sSTACK_SIZE=262144 -sALLOW_MEMORY_GROWTH=1 --embed-file ${CMAKE_CURRENT_SOURCE_DIR}/data@/wasm-tests")
  add_test(NAME flb-wasm-yaml COMMAND flb-wasm-yaml)
  set_tests_properties(flb-wasm-yaml PROPERTIES TIMEOUT 45)
endif()
