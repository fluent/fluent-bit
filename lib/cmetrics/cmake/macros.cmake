# Macro to set definitions
macro(CMT_DEFINITION var)
  add_definitions(-D${var})
  set(CMT_BUILD_FLAGS "${CMT_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CMT_INFO_FLAGS "${CMT_INFO_FLAGS} ${var}")
endmacro()

macro(CMT_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
