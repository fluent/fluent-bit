# Can also run without Emscripten:
# cmake -DTEST_BINARY_ROOT=/tmp/flb-wasm-profile-tests -P tests/wasm/check_profile.cmake
cmake_minimum_required(VERSION 3.12)

if(NOT TEST_BINARY_ROOT)
  message(FATAL_ERROR "Set TEST_BINARY_ROOT to a scratch build directory")
endif()

# Each invocation needs fresh caches, including the intentional native-to-WASM
# transition below. Keep the generated trees for diagnosing failures.
string(RANDOM LENGTH 12 ALPHABET 0123456789abcdef test_run_id)
set(TEST_BINARY_ROOT "${TEST_BINARY_ROOT}/${test_run_id}")

function(check_profile name expected_error)
  execute_process(
    COMMAND "${CMAKE_COMMAND}"
      -S "${CMAKE_CURRENT_LIST_DIR}/profile"
      -B "${TEST_BINARY_ROOT}/${name}" ${ARGN}
    RESULT_VARIABLE result
    OUTPUT_VARIABLE output
    ERROR_VARIABLE error)

  if(expected_error)
    string(FIND "${output}${error}" "${expected_error}" error_index)
    if(result EQUAL 0 OR error_index EQUAL -1)
      message(FATAL_ERROR "${name}: expected '${expected_error}':\n${output}${error}")
    endif()
  elseif(NOT result EQUAL 0)
    message(FATAL_ERROR "${name}: ${output}${error}")
  endif()
  message(STATUS "${name}: passed")
endfunction()

check_profile(defaults "")
check_profile(old_sdk "FLB_WASM_BROWSER requires Emscripten 6.0.9" -DEMSCRIPTEN_VERSION=5.0.7)
check_profile(unvalidated_sdk "FLB_WASM_BROWSER requires Emscripten 6.0.9" -DEMSCRIPTEN_VERSION=6.0.10)
check_profile(minimal "" -DFLB_MINIMAL=ON)
check_profile(disable_filter "" -DFLB_FILTER_GREP=OFF)
check_profile(disable_lua "" -DFLB_WASM_LUA=OFF -DFLB_FILTER_LUA=OFF)
check_profile(reject_lua_without_backend "FLB_FILTER_LUA is not supported by the browser build profile"
  -DFLB_WASM_LUA=OFF -DFLB_FILTER_LUA=ON)
check_profile(native_defaults "" -DPROFILE_TEST_MODE=native)
check_profile(wrong_toolchain "FLB_WASM_BROWSER requires Emscripten" -DPROFILE_TEST_MODE=wrong_toolchain)
foreach(incompatible IN ITEMS FLB_IN_HTTP FLB_OUT_TCP FLB_FILTER_WASM FLB_FILTER_CHECKLIST
    FLB_WASM FLB_TLS FLB_ALL FLB_DEV FLB_SHARED_LIB FLB_PREFER_SYSTEM_LIBS FLB_LUAJIT
    FLB_RIPSER FLB_PROCESSOR_TDA)
  check_profile(reject_${incompatible}
    "${incompatible} is not supported by the browser build profile" -D${incompatible}=ON)
endforeach()

# A reused cache must not silently retain a formerly enabled native plugin.
check_profile(stale_cache "" -DPROFILE_TEST_MODE=native)
check_profile(stale_cache "is not supported by the browser build profile" -DPROFILE_TEST_MODE=browser)
