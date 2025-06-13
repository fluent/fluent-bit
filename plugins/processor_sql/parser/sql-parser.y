%define api.pure full
%parse-param { struct sql_query *query };
%lex-param   { void *scanner }
%parse-param { void *scanner }

%{

#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>

#include "processor-sql_parser.h"
#include "processor-sql-parser_lex.h"

#include "sql.h"
#include "sql_expression.h"
#include "parser/sql_parser.h"

extern int yylex(YYSTYPE * yylval_param , yyscan_t yyscanner);

void yyerror (struct sql_query *query, void *scanner, const char *str)
{
    fprintf(stderr, "error: %s\n", str);
}

%} /* EOF C code */


/* Known Tokens */
%token SELECT AS FROM FROM_STREAM FROM_TAG TAG WHERE IDENTIFIER QUOTE QUOTED

/* Aggregation functions */
%token AVG SUM COUNT MAX MIN

/* Record functions */
%token RECORD CONTAINS

/* NULL keyword */
%token IS NUL

/* Logical operation tokens */
%token AND OR NOT NEQ LT LTE GT GTE

/* Value types */
%token INTEGER FLOATING STRING BOOLTYPE

/* Union and field types */
%union
{
  int boolean;
  int integer;
  float fval;
  char *string;
  struct sql_expression *expression;
  struct sql_query *query;
}

%type <string>     IDENTIFIER
%type <integer>    INTEGER
%type <fval>       FLOATING
%type <string>     STRING
%type <boolean>    BOOLTYPE

%type <string>     record_keys
%type <string>     record_key
%type <string>     alias
%type <expression> condition
%type <expression> comparison
%type <expression> key
%type <expression> value
%type <expression> null
%type <expression> record_func

%% /* rules section */

select: SELECT keys FROM source where ';'
      {
      }
      keys: record_keys
      record_keys: record_key
                   |
                   record_keys ',' record_key
      record_key: '*'
                  {
                    sql_parser_query_key_add(query, NULL, NULL);
                  }
                  |
                  IDENTIFIER
                  {
                    sql_parser_query_key_add(query, $1, NULL);
                    flb_free($1);
                  }
                  |
                  IDENTIFIER AS alias
                  {
                     sql_parser_query_key_add(query, $1, $3);
                     flb_free($1);
                     flb_free($3);
                  }
      alias: IDENTIFIER
      source:
               FROM_STREAM IDENTIFIER
                   {
                     /* Reserved for future use case */
                     //flb_sp_cmd_source(cmd, FLB_SP_STREAM, $2);
                     flb_free($2);
                   }
               |
               FROM_STREAM
                   {
                     /* Reserved for future use case */
                   }
      where: %empty
             |
             WHERE condition
             {
               sql_expression_condition_add(query, $2);

             }
      condition: comparison
                 |
                 key
                 {
                   $$ = sql_expression_operation(query, $1, NULL, SQL_EXP_OR);
                 }
                 |
                 value
                 {
                   $$ = sql_expression_operation(query, NULL, $1, SQL_EXP_OR);
                 }
                 |
                 '(' condition ')'
                 {
                   $$ = sql_expression_operation(query, $2, NULL, SQL_EXP_PAR);
                 }
                 |
                 NOT condition
                 {
                   $$ = sql_expression_operation(query, $2, NULL, SQL_EXP_NOT);
                 }
                 |
                 condition AND condition
                 {
                   $$ = sql_expression_operation(query, $1, $3, SQL_EXP_AND);
                 }
                 |
                 condition OR condition
                 {
                   $$ = sql_expression_operation(query, $1, $3, SQL_EXP_OR);
                 }
      key: IDENTIFIER
                {
                  $$ = sql_expression_condition_key(query, $1);
                  flb_free($1);
                }
            //  |
            //  IDENTIFIER record_subkey
            //        {
            //          flb_free($1);
            //        }
      value:   INTEGER
               {
                 $$ = sql_expression_condition_integer(query, $1);
               }
               |
               FLOATING
               {

                 $$ = sql_expression_condition_float(query, $1);
               }
               |
               STRING
               {
                 $$ = sql_expression_condition_string(query, $1);
                 flb_free($1);
               }
               |
               BOOLTYPE
               {
                 $$ = sql_expression_condition_boolean(query, $1);
               }
      null: NUL
              {
                 $$ = sql_expression_condition_null(query);
              }
      comparison:
                  key IS null
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_EQ);
                  }
                  |
                  key IS NOT null
                  {
                    $$ = sql_expression_operation(query,
                             sql_expression_comparison(query, $1, $4, SQL_EXP_EQ),
                             NULL, SQL_EXP_NOT);
                  }
                  |
                  key '=' value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_EQ);
                  }
                  |
                  record_func
                  {
                    $$ = sql_expression_comparison(query,
                             $1,
                             sql_expression_condition_boolean(query, true),
                             SQL_EXP_EQ);
                  }
                  |
                  record_func '=' value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_EQ);
                  }
                  |
                  record_func NEQ value
                  {
                    $$ = sql_expression_operation(query,
                             sql_expression_comparison(query, $1, $3, SQL_EXP_EQ),
                                 NULL, SQL_EXP_NOT)
                    ;
                  }
                  |
                  record_func LT value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_LT);
                  }
                  |
                  record_func LTE value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_LTE);
                  }
                  |
                  record_func GT value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_GT);
                  }
                  |
                  record_func GTE value
                  {
                    $$ = sql_expression_comparison(query, $1, $3, SQL_EXP_GTE);
                  }
    record_func: key /* Similar to an identity function */
                     |
                     RECORD '.' CONTAINS '(' key ')'
                     {
                       //$$ = flb_sp_record_function_add(cmd, "contains", $5);
                     }
                 ;
