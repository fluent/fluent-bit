set(WAMR_ROOT_DIR ../../${FLB_PATH_LIB_WASM_MICRO_RUNTIME})
set(WASM_INCLUDE_DIRS
  ${WAMR_ROOT_DIR}/core/iwasm/include
  )

set(src
  in_exec_wasi.c)

FLB_PLUGIN(in_exec_wasi "${src}" "")
target_include_directories(flb-plugin-in_exec_wasi PRIVATE ${WASM_INCLUDE_DIRS})
target_link_libraries(flb-plugin-in_exec_wasi flb-wasm-static vmlib-static)
