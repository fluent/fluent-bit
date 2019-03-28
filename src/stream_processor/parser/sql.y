%define api.pure full
%parse-param { struct flb_sp_cmd *cmd };
%lex-param   { void *scanner }
%parse-param { void *scanner }

%{
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#include "sql_parser.h"
#include "sql_lex.h"

extern int yylex();

void yyerror (struct flb_sp_cmd *cmd, void *scanner, const char *str)
{
    fprintf(stderr, "error: %s\n", str);
}

%} /* EOF C code */


/* Known Tokens (refer to sql.l) */

/* Keywords */
%token IDENTIFIER QUOTE QUOTED

/* Basic keywords for statements */
%token CREATE STREAM WITH SELECT AS FROM FROM_STREAM FROM_TAG WHERE WINDOW GROUP_BY

/* Aggregation functions */
%token AVG SUM COUNT MAX MIN

/* Time functions */
%token NOW UNIX_TIMESTAMP

 /* Record functions */
%token RECORD_TAG RECORD_TIME

/* Value types */
%token INTEGER FLOAT STRING BOOLEAN

/* Logical operation tokens */
%token AND OR NOT LT LTE GT GTE

/* Time tokens */
%token HOUR MINUTE SECOND

/* Window tokens */
%token TUMBLING

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
%type <fval>       FLOAT
%type <string>     STRING
%type <boolean>    BOOLEAN
%type <string>     record_keys
%type <string>     record_key
%type <string>     alias
%type <string>     prop_key
%type <string>     prop_val
%type <expression> condition
%type <expression> comparison
%type <expression> key
%type <expression> value
%type <integer>    time

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
select: SELECT keys FROM source ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      |
      SELECT keys FROM source GROUP_BY gb_keys ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      |
      SELECT keys FROM source WINDOW window ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      |
      SELECT keys FROM source WINDOW window GROUP_BY gb_keys ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      |
      SELECT keys FROM source WHERE condition ';'
      {
        cmd->type = FLB_SP_SELECT;
        flb_sp_cmd_condition_add(cmd, $6); /* no flb_free for $6 */
      }
      |
      SELECT keys FROM source WHERE condition GROUP_BY gb_keys ';'
      {
        cmd->type = FLB_SP_SELECT;
        flb_sp_cmd_condition_add(cmd, $6); /* no flb_free for $6 */
      }
      |
      SELECT keys FROM source WINDOW window WHERE condition GROUP_BY gb_keys ';'
      {
        cmd->type = FLB_SP_SELECT;
        flb_sp_cmd_condition_add(cmd, $8); /* no flb_free for $8 */
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
      window: TUMBLING '(' INTEGER time ')'
              {
                flb_sp_cmd_window(cmd, FLB_SP_WINDOW_TUMBLING, $3, $4);
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
                 | '(' condition ')'
                   {
                     $$ = flb_sp_cmd_operation(cmd, $2, NULL, FLB_EXP_PAR);
                   }
                 | NOT condition
                   {
                     $$ = flb_sp_cmd_operation(cmd, $2, NULL, FLB_EXP_NOT);
                   }
                 | condition AND condition
                   {
                     $$ = flb_sp_cmd_operation(cmd, $1, $3, FLB_EXP_AND);
                   }
                 | condition OR condition
                   {
                     $$ = flb_sp_cmd_operation(cmd, $1, $3, FLB_EXP_OR);
                   }
      comparison: key '=' value
                   {
                     $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_EQ);
                   }
                  |
                  key LT value
                   {
                     $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_LT);
                   }
                  |
                  key LTE value
                   {
                     $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_LTE);
                   }
                  |
                  key GT value
                   {
                     $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_GT);
                   }
                  |
                  key GTE value
                   {
                     $$ = flb_sp_cmd_comparison(cmd, $1, $3, FLB_EXP_GTE);
                   }
        key: IDENTIFIER
                   {
                     $$ = flb_sp_cmd_condition_key(cmd, $1);
                     flb_free($1);
                   }
        value: INTEGER
                   {
                     $$ = flb_sp_cmd_condition_integer(cmd, $1);
                   }
               |
               FLOAT
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
               BOOLEAN
                   {
                     $$ = flb_sp_cmd_condition_boolean(cmd, $1);
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
        gb_keys:
            IDENTIFIER
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
