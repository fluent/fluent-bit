# libco Emscripten regression test; license: public domain
execute_process(
  COMMAND ${TEST_EMULATOR} "${TEST_PROGRAM}" "${FAULT}"
  RESULT_VARIABLE result
  OUTPUT_VARIABLE output
  ERROR_VARIABLE error
  TIMEOUT 30)

if(FAULT STREQUAL "limits")
  set(diagnostic "stack overflow")
else()
  set(diagnostic "AddressSanitizer: ${FAULT}-buffer-overflow")
endif()

# A generic nonzero exit could be an unrelated abort or runtime failure.
if(NOT result MATCHES "^[1-9][0-9]*$" OR
   NOT "${output}\n${error}" MATCHES "${diagnostic}" OR
   "${output}\n${error}" MATCHES "AddressSanitizer: CHECK failed|ASan is ignoring requested")
  message(FATAL_ERROR "Expected ${diagnostic}; exit=${result}\n${output}\n${error}")
endif()
message(STATUS "Fiber fault correctly detected: ${diagnostic}")
