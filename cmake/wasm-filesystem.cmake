# Browser filesystem glue, kept outside the portable ChunkIO library.
add_library(flb-wasm-filesystem INTERFACE)
target_link_libraries(flb-wasm-filesystem INTERFACE
  "-lidbfs.js" "--pre-js=${PROJECT_SOURCE_DIR}/src/wasm/storage.js")
set_property(TARGET flb-wasm-filesystem PROPERTY INTERFACE_LINK_DEPENDS
  "${PROJECT_SOURCE_DIR}/src/wasm/storage.js")
