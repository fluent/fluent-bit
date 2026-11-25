cmake_minimum_required(VERSION 3.20)
project(monkey_wasm_tests C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  message(FATAL_ERROR "Use emcmake to configure the browser event-loop tests")
endif()

if(NOT EMSCRIPTEN_VERSION VERSION_EQUAL "6.0.9")
  message(FATAL_ERROR "The browser event-loop tests require Emscripten 6.0.9")
endif()

enable_testing()
add_compile_options(-pthread)
add_definitions(-D_GNU_SOURCE)
set(CMAKE_REQUIRED_FLAGS "${CMAKE_REQUIRED_FLAGS} -pthread")
set(MK_EVENT_LOOP_POLL ON)
set(MK_EVENT_LOOP_EPOLL OFF)
set(MK_EVENT_LOOP_KQUEUE OFF)
set(MK_EVENT_LOOP_SELECT OFF)
set(MK_EVENT_LOOP_LIBEVENT OFF)
get_filename_component(MONKEY_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories("${MONKEY_SOURCE_DIR}/include" "${MONKEY_SOURCE_DIR}/include/monkey"
  "${PROJECT_BINARY_DIR}/include/monkey")
add_subdirectory("${MONKEY_SOURCE_DIR}/mk_core" mk_core)

add_executable(mk-test-wasm-events events.c)
target_link_libraries(mk-test-wasm-events mk_core -pthread "-sASYNCIFY=1")
set_target_properties(mk-test-wasm-events PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=2 -sSTACK_SIZE=262144")
add_test(NAME mk-test-wasm-events COMMAND mk-test-wasm-events)
set_tests_properties(mk-test-wasm-events PROPERTIES TIMEOUT 30)
