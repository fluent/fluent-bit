# Macro to set definitions
macro(CPROF_DEFINITION var)
  add_definitions(-D${var})
  set(CPROF_BUILD_FLAGS "${CPROF_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CPROF_INFO_FLAGS "${CPROF_INFO_FLAGS} ${var}")
endmacro()

macro(CPROF_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
