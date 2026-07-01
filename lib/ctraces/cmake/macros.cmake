# Macro to set definitions
macro(CTR_DEFINITION var)
  add_definitions(-D${var})
  set(CTR_BUILD_FLAGS "${CTR_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CTR_INFO_FLAGS "${CTR_INFO_FLAGS} ${var}")
endmacro()

macro(CTR_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
