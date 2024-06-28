%option caseless
%{
#include <stdio.h>
#include <fluent-bit/flb_str.h>

#include "processor-sql_parser.h"
#include "sql.h"

static inline char *remove_dup_qoutes(const char *s, size_t n)
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

SELECT                  return SELECT;
AS                      return AS;
FROM                    return FROM;
STREAM                  return FROM_STREAM;
WHERE                   return WHERE;
AND                     return AND;
OR                      return OR;
NOT                     return NOT;

IS                      return IS;
NULL                    return NUL;

"true"                     { yylval->boolean = true;  return BOOLTYPE; };
"false"                    { yylval->boolean = false;  return BOOLTYPE; };

-?[1-9][0-9]*|0            { yylval->integer = atol(yytext);  return INTEGER; }
(-?[1-9][0-9]*|0)\.[0-9]+  { yylval->fval = atof(yytext); return FLOATING; }
\'([^']|'{2})*\'           { yylval->string = remove_dup_qoutes(yytext + 1, yyleng - 2); return STRING; }
[_A-Za-z][A-Za-z0-9_.]*	   { yylval->string = flb_strdup(yytext); return IDENTIFIER; }

"*"                     |
","                     |
"="                     |
"("                     |
")"                     |
";"                     { return yytext[0]; }

"!="                    return NEQ;
"<>"                    return NEQ;
"<"                     return LT;
"<="                    return LTE;
">"                     return GT;
">="                    return GTE;

\'                      return QUOTE;
\n
[ \t]+			/* ignore whitespace */;

%%
