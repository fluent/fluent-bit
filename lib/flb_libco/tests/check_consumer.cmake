# Validate an independent consumer with the library tests disabled.
execute_process(
  COMMAND "${CMAKE_COMMAND}" -S "${CONSUMER_SOURCE}" -B "${CONSUMER_BINARY}"
    -G "${TEST_GENERATOR}"
    "-DCMAKE_TOOLCHAIN_FILE=${TEST_TOOLCHAIN}"
    "-DCMAKE_BUILD_TYPE=${TEST_BUILD_TYPE}"
    "-DCMAKE_C_FLAGS=${TEST_C_FLAGS}"
    "-DCMAKE_EXE_LINKER_FLAGS=${TEST_LINK_FLAGS}"
    "-DCMAKE_CROSSCOMPILING_EMULATOR=${TEST_EMULATOR}"
  RESULT_VARIABLE result TIMEOUT 45)
if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Consumer configure failed: ${result}")
endif()
execute_process(
  COMMAND "${CMAKE_COMMAND}" --build "${CONSUMER_BINARY}" --target co-consumer
  RESULT_VARIABLE result TIMEOUT 60)
if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Consumer build failed: ${result}")
endif()
execute_process(
  COMMAND "${CMAKE_CTEST_COMMAND}" --test-dir "${CONSUMER_BINARY}" --output-on-failure
  RESULT_VARIABLE result TIMEOUT 35)
if(NOT "${result}" STREQUAL "0")
  message(FATAL_ERROR "Consumer execution failed: ${result}")
endif()
