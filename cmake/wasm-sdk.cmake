# Public browser SDK; independent from the test/demo executables.
# Command main(), engine and log collector each need one pthread.
set(FLB_WASM_PTHREAD_POOL_SIZE 3 CACHE STRING "Browser SDK pthread pool size (3-16)")
if(NOT FLB_WASM_PTHREAD_POOL_SIZE MATCHES "^([3-9]|1[0-6])$")
  message(FATAL_ERROR "FLB_WASM_PTHREAD_POOL_SIZE must be an integer from 3 to 16")
endif()
add_executable(fluent-bit-runtime "${PROJECT_SOURCE_DIR}/src/wasm/sdk.c")
target_link_libraries(fluent-bit-runtime fluent-bit-static)
set(FLB_BROWSER_SDK_DIR "${CMAKE_BINARY_DIR}/sdk/browser")
set(sdk_link_flags
  "-sMODULARIZE=1" "-sEXPORT_ES6=1" "-sEXPORT_NAME=createFluentBitRuntime"
  "-sENVIRONMENT=web,worker" "-sASSERTIONS=2" "-sEXIT_RUNTIME=1"
  "-sPROXY_TO_PTHREAD=1" "-sPTHREAD_POOL_SIZE=${FLB_WASM_PTHREAD_POOL_SIZE}" "-sSTACK_SIZE=262144"
  "-sALLOW_MEMORY_GROWTH=1" "-sMAXIMUM_MEMORY=1073741824"
  "-sINCOMING_MODULE_JS_API=['instantiateWasm','locateFile','mainScriptUrlOrBlob','onAbort','onExit','onRuntimeInitialized','preRun','print','printErr']"
  "-sEXPORTED_FUNCTIONS=['_main','_malloc','_free','_flb_wasm_sdk_submit']"
  "-sEXPORTED_RUNTIME_METHODS=['FS','HEAPU8']")
string(REPLACE ";" " " sdk_link_flags "${sdk_link_flags}")
set_target_properties(fluent-bit-runtime PROPERTIES
  RUNTIME_OUTPUT_DIRECTORY "${FLB_BROWSER_SDK_DIR}"
  OUTPUT_NAME "fluent-bit-runtime"
  SUFFIX ".js"
  LINK_FLAGS "${sdk_link_flags}")
file(MAKE_DIRECTORY "${FLB_BROWSER_SDK_DIR}")
foreach(asset fluent-bit.js fluent-bit-pthread.js fluent-bit.d.ts package.json README.md)
  configure_file("${PROJECT_SOURCE_DIR}/sdk/browser/${asset}"
                 "${FLB_BROWSER_SDK_DIR}/${asset}" COPYONLY)
endforeach()
# Keep the worker's resource bound identical to the linked Emscripten pool.
file(READ "${PROJECT_SOURCE_DIR}/sdk/browser/fluent-bit-worker.js" sdk_worker_source)
string(REPLACE "const PTHREAD_POOL_SIZE = 3;"
               "const PTHREAD_POOL_SIZE = ${FLB_WASM_PTHREAD_POOL_SIZE};"
               sdk_worker_source "${sdk_worker_source}")
file(WRITE "${FLB_BROWSER_SDK_DIR}/fluent-bit-worker.js" "${sdk_worker_source}")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
             "${PROJECT_SOURCE_DIR}/sdk/browser/fluent-bit-worker.js")
configure_file("${PROJECT_SOURCE_DIR}/LICENSE" "${FLB_BROWSER_SDK_DIR}/LICENSE" COPYONLY)
install(DIRECTORY "${FLB_BROWSER_SDK_DIR}/" DESTINATION share/fluent-bit/browser
        COMPONENT wasm-sdk)

if(CMAKE_CROSSCOMPILING_EMULATOR)
  add_test(NAME flb-wasm-sdk-api COMMAND ${CMAKE_CROSSCOMPILING_EMULATOR}
    --test "${PROJECT_SOURCE_DIR}/tests/wasm/sdk_unit_test.mjs"
    "${PROJECT_SOURCE_DIR}/tests/wasm/sdk_worker_unit_test.mjs")
  set_tests_properties(flb-wasm-sdk-api PROPERTIES TIMEOUT 30)
endif()
