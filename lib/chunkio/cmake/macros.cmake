# Macro to set definitions
macro(CIO_DEFINITION var)
  add_definitions(-D${var})
  set(CIO_BUILD_FLAGS "${CIO_BUILD_FLAGS}#ifndef ${var}\n#define ${var}\n#endif\n")
  set(CIO_INFO_FLAGS "${CIO_INFO_FLAGS} ${var}")
endmacro()
