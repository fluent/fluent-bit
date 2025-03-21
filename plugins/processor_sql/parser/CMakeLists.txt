flex_target(lexer sql-parser.l "${CMAKE_CURRENT_BINARY_DIR}/processor-sql-parser_lex.c"
            DEFINES_FILE       "${CMAKE_CURRENT_BINARY_DIR}/processor-sql-parser_lex.h"
            )
bison_target(parser sql-parser.y "${CMAKE_CURRENT_BINARY_DIR}/processor-sql_parser.c")

if(CMAKE_SYSTEM_NAME MATCHES "Windows")
  FLB_DEFINITION(YY_NO_UNISTD_H)
  message(STATUS "Specifying YY_NO_UNISTD_H")
endif()

set(sources
  sql_parser.c
  sql_expression.c
  )

include_directories(
  ${CMAKE_CURRENT_SOURCE_DIR}
  ${CMAKE_CURRENT_BINARY_DIR}
  )

add_library(processor-sql-parser STATIC
    ${sources}
    "${CMAKE_CURRENT_BINARY_DIR}/processor-sql-parser_lex.c"
    "${CMAKE_CURRENT_BINARY_DIR}/processor-sql_parser.c"
    )

add_flex_bison_dependency(lexer parser)

if (FLB_JEMALLOC AND (NOT JEMALLOC_FOUND))
  add_dependencies(processor-sql-parser libjemalloc)
  include_directories("${CMAKE_BINARY_DIR}/include/")
endif ()