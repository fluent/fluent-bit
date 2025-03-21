# Macro to set definitions
macro(FLB_DEFINITION var)
  add_definitions(-D${var})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(FLB_INFO_FLAGS "${FLB_INFO_FLAGS} ${var}")
endmacro()

macro(FLB_DEFINITION_VAL var val)
  add_definitions(-D${var}=${val})
  set(FLB_BUILD_FLAGS "${FLB_BUILD_FLAGS}#ifndef ${var}\n#define ${var} \"${val}\"\n#endif\n")
endmacro()

macro(FLB_OPTION option value)
  set(${option} ${value} CACHE INTERNAL "" FORCE)
endmacro()
