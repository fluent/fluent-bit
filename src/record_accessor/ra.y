%define api.pure full
%parse-param { struct flb_ra_parser *rp };
%parse-param { const char *str };
%lex-param   { void *scanner }
%parse-param { void *scanner }

%{
#include <stdio.h>
#include <stdlib.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#include "ra_parser.h"
#include "ra_lex.h"

extern int yylex();

void yyerror(struct flb_ra_parser *rp, const char *query, void *scanner,
             const char *str)
{
    flb_error("[record accessor] %s at '%s'", str, query);
}

%} /* EOF C code */


/* Known Tokens (refer to sql.l) */

/* Keywords */
%token IDENTIFIER QUOTE QUOTED
%token STRING

%define parse.error verbose

/* Union and field types */
%union
{
    int integer;
    float fval;
    char *string;
    struct flb_sp_cmd *cmd;
    struct flb_exp *expression;
}

%type <string>     IDENTIFIER
%type <string>     STRING
%type <string>     record_key

%destructor { flb_free ($$); } IDENTIFIER
%destructor { flb_free ($$); } STRING

%% /* rules section */

statements: record_accessor

/* Parse record accessor string: $key, $key['x'], $key['x'][...] */
record_accessor: record_key
      record_key:
                  '$' IDENTIFIER
                  {
                    void *key;

                    rp->type = FLB_RA_PARSER_KEYMAP;
                    key = flb_ra_parser_key_add(rp, $2);
                    if (key) {
                      rp->key = key;
                    }
                    flb_free($2);
                  }
                  |
                  '$' IDENTIFIER record_subkey
                  {
                    void *key;
                    rp->type = FLB_RA_PARSER_KEYMAP;
                    key = flb_ra_parser_key_add(rp, $2);
                    if (key) {
                      rp->key = key;
                    }
                    flb_free($2);
                  }
      record_subkey: '[' STRING ']'
                  {
                    flb_ra_parser_subkey_add(rp, $2);
                    flb_free($2);
                  }
                  |
                  record_subkey record_subkey
                  ;
