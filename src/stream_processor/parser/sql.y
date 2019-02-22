%define api.pure full
%parse-param { struct flb_sp_cmd *cmd };
%lex-param   { void *scanner }
%parse-param { void *scanner }

%{
#include <stdio.h>
#include <stdlib.h>

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
%token CREATE STREAM WITH SELECT AVG SUM COUNT MAX MIN AS FROM FROM_STREAM FROM_TAG TAG WHERE IDENTIFIER INTEGER QUOTE QUOTED

/* Union and field types */
%union
{
   int integer;
   char *string;
   struct flb_sp_cmd *cmd;
}

%type <string>  IDENTIFIER
%type <string>  TAG
%type <integer> INTEGER
%type <string>  record_keys
%type <string>  record_key
%type <string>  alias
%type <string>  prop_key
%type <string>  prop_val

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
      property: prop_key '=' QUOTE prop_val QUOTE
                  {
                    flb_sp_cmd_stream_prop_add(cmd, $1, $4);
                    flb_free($1);
                    flb_free($4);
                  }
      prop_key: IDENTIFIER
      prop_val: IDENTIFIER

/* Parser for 'SELECT' statement */
select: SELECT keys FROM source ';'
      {
        cmd->type = FLB_SP_SELECT;
      }
      |
      SELECT keys FROM source WHERE condition ';'
      {
      }
      keys:
           record_keys
           |
           '*'
           {
             flb_sp_cmd_key_add(cmd, -1, NULL, NULL);
           }
      record_keys: record_key
                   |
                   record_keys ',' record_key
      record_key: IDENTIFIER
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
      alias: IDENTIFIER
      source: FROM_STREAM IDENTIFIER
                   {
                     flb_sp_cmd_source(cmd, FLB_SP_STREAM, $2);
                     flb_free($2);
                   }
              |
              FROM_TAG IDENTIFIER
                   {
                     flb_sp_cmd_source(cmd, FLB_SP_TAG, $2);
                     flb_free($2);
                   }
      condition: IDENTIFIER '=' IDENTIFIER
                 {
                   printf("key='%s' val='%s'\n", $1, $3);
                 }
                 |
                 IDENTIFIER '=' INTEGER
                 {
                   printf("key='%s' val='%d'\n", $1, $3);
                 }
                 |
                 ;
