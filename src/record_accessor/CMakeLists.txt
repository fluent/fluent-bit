flex_target(lexer   ra.l "${CMAKE_CURRENT_BINARY_DIR}/ra_lex.c"
            DEFINES_FILE "${CMAKE_CURRENT_BINARY_DIR}/ra_lex.h"
            )
bison_target(parser ra.y "${CMAKE_CURRENT_BINARY_DIR}/ra_parser.c")

set(sources
  flb_ra_parser.c
  )

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  FLB_DEFINITION(YY_NO_UNISTD_H)
  message(STATUS "Specifying YY_NO_UNISTD_H")
endif()

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  )

add_library(flb-ra-parser STATIC
    ${sources}
    "${CMAKE_CURRENT_BINARY_DIR}/ra_lex.c"
    "${CMAKE_CURRENT_BINARY_DIR}/ra_parser.c"
    )

add_flex_bison_dependency(lexer parser)
add_dependencies(flb-ra-parser onigmo-static)

if(FLB_JEMALLOC)
  target_link_libraries(flb-ra-parser ${JEMALLOC_LIBRARIES})
endif()
