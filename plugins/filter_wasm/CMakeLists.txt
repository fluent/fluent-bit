set(WAMR_ROOT_DIR ../../${FLB_PATH_LIB_WASM_MICRO_RUNTIME})
set(WASM_INCLUDE_DIRS
  ${WAMR_ROOT_DIR}/core/iwasm/include
  )

set(src
  filter_wasm.c)

FLB_PLUGIN(filter_wasm "${src}" "")
target_include_directories(flb-plugin-filter_wasm PRIVATE ${WASM_INCLUDE_DIRS})
target_link_libraries(flb-plugin-filter_wasm flb-wasm-static vmlib-static)
