%option prefix="flb_ra_"
%option caseless
%{
#include <stdio.h>
#include <stdbool.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/record_accessor/flb_ra_parser.h>

#include "ra_parser.h"

static inline char *remove_dup_quotes(const char *s, size_t n)
{
    char *str;
    int dups;
    int i, j;

    dups = 0;
    for (i = 0; i < n; i++) {
        if (s[i] == '\'') {
            dups++;
            i++;
        }
    }

    str = (char *) flb_malloc(n - dups + 1);
    if (!str) {
        return NULL;
    }

    j = 0;
    for (i = 0; i < n; i++, j++) {
        if (s[i] == '\'') {
            str[j] = '\'';
            i++;
        } else {
            str[j] = s[i];
        }
    }
    str[j] = '\0';

    return str;
}

%}

%option 8bit reentrant bison-bridge
%option warn noyywrap nodefault
%option nounput
%option noinput

%%

[1-9][0-9]*|0            { yylval->integer = atoi(yytext);  return INTEGER; }
\'([^']|'{2})*\'           { yylval->string = remove_dup_quotes(yytext + 1, yyleng - 2); return STRING; }
[_A-Za-z][A-Za-z0-9_.\-/]*	   { yylval->string = flb_strdup(yytext); return IDENTIFIER; }

"$"                     |
"["                     |
"]"                     |
"."                     |
","                     |
";"                     { return yytext[0]; }
\n
[ \t]+			/* ignore whitespace */;

.	flb_error("[record accessor] bad input character '%s' at line %d", yytext, yylineno);

%%
