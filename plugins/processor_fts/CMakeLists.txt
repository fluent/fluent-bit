# Embed the Lua helper sources as C string literals.
function(fts_embed_lua variable file)
  file(READ "${CMAKE_CURRENT_SOURCE_DIR}/${file}" content)
  string(REPLACE "\\" "\\\\" content "${content}")
  string(REPLACE "\"" "\\\"" content "${content}")
  string(REPLACE "\n" "\\n\"\n\"" content "${content}")
  set(${variable} "${content}" PARENT_SCOPE)
  set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${file})
endfunction()

fts_embed_lua(FTS_VALUE_HELPERS fts_value_helpers.lua)
fts_embed_lua(FTS_LOG_HELPERS fts_log_helpers.lua)
fts_embed_lua(FTS_TELEMETRY_HELPERS fts_telemetry_helpers.lua)
configure_file(fts_helpers.h.in fts_helpers.h @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

set(src
  fts.c
  fts_runtime.c
  fts_values.c
  fts_logs.c
  fts_proto.c
  fts_telemetry.c
  fts_metrics.c
  fts_traces.c
  )

FLB_PLUGIN(processor_fts "${src}" "")
