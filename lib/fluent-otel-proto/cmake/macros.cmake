# Macro to set definitions
macro(FLUENT_OTEL_DEFINITION var)
  add_definitions(-D${var})
  set(FLUENT_OTEL_BUILD_FLAGS "${FLUENT_OTEL_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(FLUENT_OTEL_INFO_FLAGS "${FLUENT_OTEL_INFO_FLAGS} ${var}")
endmacro()
