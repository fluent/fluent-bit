%define api.pure full
%parse-param { struct flb_sp_cmd *cmd };
%parse-param { const char *query };
%lex-param   { void *scanner }
%parse-param { void *scanner }

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#include "sql_parser.h"
#include "sql_lex.h"

extern int yylex();

void yyerror(struct flb_sp_cmd *cmd, const char *query, void *scanner,
             const char *str)
{
    flb_error("[sp] %s at '%s'", str, query);
}

%} /* EOF C code */


/* Known Tokens (refer to sql.l) */

/* Keywords */
%token IDENTIFIER QUOTE QUOTED

/* Basic keywords for statements */
%token CREATE STREAM WITH SELECT AS FROM FROM_STREAM FROM_TAG WHERE WINDOW GROUP_BY

/* Null keywords */
%token IS NUL

/* Aggregation functions */
%token AVG SUM COUNT MAX MIN

/* Record functions */
%token RECORD CONTAINS TIME

/* Time functions */
%token NOW UNIX_TIMESTAMP

 /* Record functions */
%token RECORD_TAG RECORD_TIME

/* Value types */
%token INTEGER FLOATING STRING BOOLTYPE

/* Logical operation tokens */
%token AND OR NOT LT LTE GT GTE

/* Time tokens */
%token HOUR MINUTE SECOND

/* Window tokens */
%token TUMBLING HOPPING ADVANCE_BY

%define parse.error verbose

/* Union and field types */
%union
{
    bool boolean;
    int integer;
    float fval;
    char *string;
    struct flb_sp_cmd *cmd;
    struct flb_exp *expression;
}

%type <string>     IDENTIFIER
%type <integer>    INTEGER
%type <fval>       FLOATING
%type <string>     STRING
%type <boolean>    BOOLTYPE
%type <string>     record_keys
%type <string>     record_key
%type <string>     alias
%type <string>     prop_key
%type <string>     prop_val
%type <expression> condition
%type <expression> comparison
%type <expression> key
%type <expression> record_func
%type <expression> value
%type <expression> null
%type <integer>    time

%destructor { flb_free ($$); } IDENTIFIER

%% /* rules section */

statements: create | select

/* Parser for 'CREATE STREAM' statement */
create:
      CREATE STREAM IDENTIFIER AS select
      {
        flb_sp_cmd_stream_new(cmd, $3);
        flb_free($3);
      }
      |
      CREATE STREAM IDENTIFIER WITH '(' properties ')' AS select
      {
        flb_sp_cmd_stream_new(cmd, $3);
        flb_free($3);
      }
      properties: property
                  |
                  properties ',' property
      property: prop_key '=' prop_val
                  {
                    flb_sp_cmd_stream_prop_add(cmd, $1, $3);
                    flb_free($1);
                    flb_free($3);
                  }
      prop_key: IDENTIFIER
      prop_val: STRING

/* Parser for 'SELECT' statement */
select: SELECT keys FROM source window where groupby ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      keys: record_keys
      record_keys: record_key
                   |
                   record_keys ',' record_key
      record_key: '*'
                  {
                    flb_sp_cmd_key_add(cmd, -1, NULL, NULL);
                  }
                  |
                  IDENTIFIER
                  {
                    flb_sp_cmd_key_add(cmd, -1, $1, NULL);
                    flb_free($1);
                  }
                  |
                  IDENTIFIER AS alias
                  {
                    flb_sp_cmd_key_add(cmd, -1, $1, $3);
                    flb_free($1);
                    flb_free($3);
                  }
                  |
                  IDENTIFIER record_subkey
                  {
                    flb_sp_cmd_key_add(cmd, -1, $1, NULL);
                    flb_free($1);
                  }
                  |
                  IDENTIFIER record_subkey AS alias
                  {
                    flb_sp_cmd_key_add(cmd, -1, $1, $4);
                    flb_free($1);
                    flb_free($4);
                  }
                  |
                  AVG '(' IDENTIFIER ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_AVG, $3, NULL);
                    flb_free($3);
                  }
                  |
                  AVG '(' IDENTIFIER ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_AVG, $3, $6);
                    flb_free($3);
                    flb_free($6);
                  }
                  |
                  AVG '(' IDENTIFIER record_subkey ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_AVG, $3, NULL);
                    flb_free($3);
                  }
                  |
                  AVG '(' IDENTIFIER record_subkey ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_AVG, $3, $7);
                    flb_free($3);
                    flb_free($7);
                  }
                  |
                  SUM '(' IDENTIFIER ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_SUM, $3, NULL);
                    flb_free($3);
                  }
                  |
                  SUM '(' IDENTIFIER ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_SUM, $3, $6);
                    flb_free($3);
                    flb_free($6);
                  }
                  |
                  SUM '(' IDENTIFIER record_subkey ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_SUM, $3, NULL);
                    flb_free($3);
                  }
                  |
                  SUM '(' IDENTIFIER record_subkey ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_SUM, $3, $7);
                    flb_free($3);
                    flb_free($7);
                  }
                  |
                  COUNT '(' '*' ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, NULL, NULL);
                  }
                  |
                  COUNT '(' '*' ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, NULL, $6);
                    flb_free($6);
                  }
                  |
                  COUNT '(' IDENTIFIER ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, $3, NULL);
                    flb_free($3);
                  }
                  |
                  COUNT '(' IDENTIFIER ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, $3, $6);
                    flb_free($3);
                    flb_free($6);
                  }
                  |
                  COUNT '(' IDENTIFIER record_subkey ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, $3, NULL);
                    flb_free($3);
                  }
                  |
                  COUNT '(' IDENTIFIER record_subkey ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_COUNT, $3, $7);
                    flb_free($3);
                    flb_free($7);
                  }
                  |
                  MIN '(' IDENTIFIER ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MIN, $3, NULL);
                    flb_free($3);
                  }
                  |
                  MIN '(' IDENTIFIER ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MIN, $3, $6);
                    flb_free($3);
                    flb_free($6);
                  }
                  |
                  MIN '(' IDENTIFIER record_subkey ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MIN, $3, NULL);
                    flb_free($3);
                  }
                  |
                  MIN '(' IDENTIFIER record_subkey ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MIN, $3, $7);
                    flb_free($3);
                    flb_free($7);
                  }
                  |
                  MAX '(' IDENTIFIER ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MAX, $3, NULL);
                    flb_free($3);
                  }
                  |
                  MAX '(' IDENTIFIER ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MAX, $3, $6);
                    flb_free($3);
                    flb_free($6);
                  }
                  |
                  MAX '(' IDENTIFIER record_subkey ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MAX, $3, NULL);
                    flb_free($3);
                  }
                  |
                  MAX '(' IDENTIFIER record_subkey ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_MAX, $3, $7);
                    flb_free($3);
                    flb_free($7);
                  }
                  |
                  NOW '(' ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_NOW, NULL, NULL);
                  }
                  |
                  NOW '(' ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_NOW, NULL, $5);
                    flb_free($5);
                  }
                  |
                  UNIX_TIMESTAMP '(' ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_UNIX_TIMESTAMP, NULL, NULL);
                  }
                  |
                  UNIX_TIMESTAMP '(' ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_UNIX_TIMESTAMP, NULL, $5);
                    flb_free($5);
                  }
                  |
                  RECORD_TAG '(' ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_RECORD_TAG, NULL, NULL);
                  }
                  |
                  RECORD_TAG '(' ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_RECORD_TAG, NULL, $5);
                    flb_free($5);
                  }
                  |
                  RECORD_TIME '(' ')'
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_RECORD_TIME, NULL, NULL);
                  }
                  |
                  RECORD_TIME '(' ')' AS alias
                  {
                    flb_sp_cmd_key_add(cmd, FLB_SP_RECORD_TIME, NULL, $5);
                    flb_free($5);
                  }
      alias: IDENTIFIER
      record_subkey: '[' STRING ']'
             {
               flb_slist_add(cmd->tmp_subkeys, $2);
               flb_free($2);
             }
             |
             record_subkey record_subkey
      source: FROM_STREAM IDENTIFIER
              {
                flb_sp_cmd_source(cmd, FLB_SP_STREAM, $2);
                flb_free($2);
              }
              |
              FROM_TAG STRING
              {
                flb_sp_cmd_source(cmd, FLB_SP_TAG, $2);
                flb_free($2);
              }
      window: %empty
              |
              WINDOW window_spec
      where: %empty
             |
             WHERE condition
             {
               flb_sp_cmd_condition_add(cmd, $2);
             }
      groupby: %empty
               |
               GROUP_BY gb_keys
      window_spec:
              TUMBLING '(' INTEGER time ')'
              {
                flb_sp_cmd_window(cmd, FLB_SP_WINDOW_TUMBLING, $3, $4, 0, 0);
              }
              |
              HOPPING '(' INTEGER time ',' ADVANCE_BY INTEGER time ')'
              {
                flb_sp_cmd_window(cmd, FLB_SP_WINDOW_HOPPING, $3, $4, $7, $8);
              }
      condition: comparison
                 |
                 key
                 {
                   $$ = flb_sp_cmd_operation(cmd, $1, NULL, FLB_EXP_OR);
                 }
                 |
                 value
                 {
                   $$ = flb_sp_cmd_operation(cmd, NULL, $1, FLB_EXP_OR);
                 }
                 |
                 '(' condition ')'
                 {
                   $$ = flb_sp_cmd_operation(cmd, $2, NULL, FLB_EXP_PAR);
                 }
                 |
                 NOT condition
                 {
                   $$ = flb_sp_cmd_operation(cmd, $2, NULL, FLB_EXP_NOT);
                 }
                 |
                 condition AND condition
                 {
                   $$ = flb_sp_cmd_operation(cmd, $1, $3, FLB_EXP_AND);
                 }
                 |
                 condition OR condition
                 {
                   $$ = flb_sp_cmd_operation(cmd, $1, $3, FLB_EXP_OR);
                 }
      comparison:
                  key IS null
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_EQ);
                  }
                  |
                  key IS NOT null
                  {
                    $$ = flb_sp_cmd_operation(cmd,
                             flb_sp_cmd_comparison(cmd, $1, $4, FLB_EXP_EQ),
                             NULL, FLB_EXP_NOT);
                  }
                  |
                  record_func
                  {
                    $$ = flb_sp_cmd_comparison(cmd,
                             $1,
                             flb_sp_cmd_condition_boolean(cmd, true),
                             FLB_EXP_EQ);
                  }
                  |
                  record_func '=' value
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_EQ);
                  }
                  |
                  record_func LT value
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_LT);
                  }
                  |
                  record_func LTE value
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_LTE);
                  }
                  |
                  record_func GT value
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_GT);
                  }
                  |
                  record_func GTE value
                  {
                    $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_GTE);
                  }
        record_func: key /* Similar to an identity function */
                     |
                     RECORD '.' CONTAINS '(' key ')'
                     {
                       $$ = flb_sp_record_function_add(cmd, "contains", $5);
                     }
                     |
                     RECORD '.' TIME '(' ')'
                     {
                       $$ = flb_sp_record_function_add(cmd, "time", NULL);
                     }
        key: IDENTIFIER
                   {
                     $$ = flb_sp_cmd_condition_key(cmd, $1);
                     flb_free($1);
                   }
             |
             IDENTIFIER subkey
                   {
                     $$ = flb_sp_cmd_condition_key(cmd, $1);
                     flb_free($1);
                   }
        subkey: '[' STRING ']'
                   {
                     flb_slist_add(cmd->tmp_subkeys, $2);
                     flb_free($2);
                   }
             |
             subkey subkey
        value: INTEGER
               {
                 $$ = flb_sp_cmd_condition_integer(cmd, $1);
               }
               |
               FLOATING
               {
                 $$ = flb_sp_cmd_condition_float(cmd, $1);
               }
               |
               STRING
               {
                 $$ = flb_sp_cmd_condition_string(cmd, $1);
                 flb_free($1);
               }
               |
               BOOLTYPE
               {
                 $$ = flb_sp_cmd_condition_boolean(cmd, $1);
               }
        null: NUL
              {
                 $$ = flb_sp_cmd_condition_null(cmd);
              }
        time: SECOND
              {
                $$ = FLB_SP_TIME_SECOND;
              }
              |
              MINUTE
              {
                $$ = FLB_SP_TIME_MINUTE;
              }
              |
              HOUR
              {
                $$ = FLB_SP_TIME_HOUR;
              }
        gb_keys: IDENTIFIER
                 {
                   flb_sp_cmd_gb_key_add(cmd, $1);
                   flb_free($1);
                 }
                 |
                 IDENTIFIER ',' gb_keys
                 {
                   flb_sp_cmd_gb_key_add(cmd, $1);
                   flb_free($1);
                 }
                 ;
