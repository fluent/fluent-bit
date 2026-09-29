cmake_minimum_required(VERSION 3.12)
project(libco_consumer C)

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Emscripten")
  message(FATAL_ERROR "Use emcmake to configure the browser consumer test")
endif()

set(LIBCO_TESTS OFF CACHE BOOL "Build coroutine tests" FORCE)
set(LIBCO_TESTS_ASAN OFF CACHE BOOL "Test ASan diagnostics" FORCE)
add_subdirectory(../.. libco)

# Only link the public target: no manually supplied pthread or Asyncify flags.
add_executable(co-consumer ../emscripten.c)
target_include_directories(co-consumer PRIVATE ../..)
target_link_libraries(co-consumer co)
set_target_properties(co-consumer PROPERTIES LINK_FLAGS
  "-sASSERTIONS=2 -sEXIT_RUNTIME=1 -sPROXY_TO_PTHREAD=1 -sPTHREAD_POOL_SIZE=4 -sSTACK_SIZE=262144")
enable_testing()
add_test(NAME co-consumer COMMAND co-consumer)
set_tests_properties(co-consumer PROPERTIES TIMEOUT 30)
