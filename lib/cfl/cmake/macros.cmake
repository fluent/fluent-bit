# Macro to set definitions
macro(CFL_DEFINITION var)
  add_definitions(-D${var})
  set(CFL_BUILD_FLAGS "${CFL_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CFL_INFO_FLAGS "${CFL_INFO_FLAGS} ${var}")
endmacro()

macro(CFL_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
