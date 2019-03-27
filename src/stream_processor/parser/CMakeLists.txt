flex_target(lexer   sql.l "${CMAKE_CURRENT_BINARY_DIR}/sql_lex.c"
            DEFINES_FILE "${CMAKE_CURRENT_BINARY_DIR}/sql_lex.h"
            )
bison_target(parser sql.y "${CMAKE_CURRENT_BINARY_DIR}/sql_parser.c")

set(sources
  flb_sp_parser.c
  )

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  )

add_library(flb-sp-parser STATIC
    ${sources}
    "${CMAKE_CURRENT_BINARY_DIR}/sql_lex.c"
    "${CMAKE_CURRENT_BINARY_DIR}/sql_parser.c"
    )

#add_executable(test-sp-parser
#    ${sources}
#    "${CMAKE_CURRENT_BINARY_DIR}/sql_lex.c"
#    "${CMAKE_CURRENT_BINARY_DIR}/sql_parser.c"
#    )

add_flex_bison_dependency(lexer parser)
add_dependencies(flb-sp-parser libonigmo)
