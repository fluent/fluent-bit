# Discover Acutest cases from the compiled executable when CTest loads its tests.
# This respects conditional TEST_LIST entries without parsing C sources or building
# another executable for each case.
set(FLB_ACUTEST_MODULE "${CMAKE_CURRENT_LIST_FILE}")

function(flb_add_runtime_test_cases target)
  set(include_file "${CMAKE_CURRENT_BINARY_DIR}/${target}_include.cmake")
  set(config_file "${CMAKE_CURRENT_BINARY_DIR}/${target}_$<CONFIG>_include.cmake")

  file(GENERATE OUTPUT "${config_file}" CONTENT
"include([=[${FLB_ACUTEST_MODULE}]=])
flb_discover_runtime_test_cases([=[$<TARGET_FILE:${target}>]=]
  [=[${target}]=] [=[${CMAKE_HOME_DIRECTORY}/build]=])
")

  # Multi-config generators select their executable with ctest -C; single-config
  # generators use CMAKE_BUILD_TYPE, including the empty default configuration.
  if(CMAKE_CONFIGURATION_TYPES)
    file(WRITE "${include_file}"
"if(CTEST_CONFIGURATION_TYPE)
  include(\"${CMAKE_CURRENT_BINARY_DIR}/${target}_\${CTEST_CONFIGURATION_TYPE}_include.cmake\")
else()
  message(FATAL_ERROR \"Select a test configuration with ctest -C\")
endif()
")
  else()
    file(WRITE "${include_file}"
      "include([=[${CMAKE_CURRENT_BINARY_DIR}/${target}_${CMAKE_BUILD_TYPE}_include.cmake]=])\n")
  endif()
  set_property(DIRECTORY APPEND PROPERTY TEST_INCLUDE_FILES "${include_file}")
endfunction()

function(flb_discover_runtime_test_cases executable test_name working_directory)
  if(NOT EXISTS "${executable}")
    add_test("${test_name}/not_built" "${executable}")
    return()
  endif()

  execute_process(COMMAND "${executable}" --list
    RESULT_VARIABLE result OUTPUT_VARIABLE output ERROR_VARIABLE error TIMEOUT 30)
  if(NOT result EQUAL 0)
    message(FATAL_ERROR "Cannot discover ${test_name} cases (${result}): ${error}")
  endif()

  string(REPLACE "\r\n" "\n" output "${output}")
  string(REPLACE "\n" ";" lines "${output}")
  set(cases "")
  foreach(line ${lines})
    if(line MATCHES "^  (.+)$")
      set(case_name "${CMAKE_MATCH_1}")
      list(FIND cases "${case_name}" duplicate)
      if(NOT duplicate EQUAL -1)
        message(FATAL_ERROR "Duplicate ${test_name} case: ${case_name}")
      endif()
      list(APPEND cases "${case_name}")

      # CTest supplies process isolation, so Acutest does not need another child.
      add_test("${test_name}/${case_name}" "${executable}" --no-exec -- "${case_name}")
      set_tests_properties("${test_name}/${case_name}" PROPERTIES
        LABELS "runtime" WORKING_DIRECTORY "${working_directory}" TIMEOUT 60)
    endif()
  endforeach()
  if(NOT cases)
    message(FATAL_ERROR "No Acutest cases found in ${test_name}")
  endif()
endfunction()
