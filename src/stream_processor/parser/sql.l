%option caseless
%{
#include <stdio.h>
#include <fluent-bit/flb_str.h>
#include "sql_parser.h"

static inline char *remove_dup_qoutes(char *s, size_t n)
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

CREATE                  return CREATE;
STREAM                  return STREAM;
WITH                    return WITH;
SELECT                  return SELECT;
SUM                     return SUM;
AVG                     return AVG;
COUNT                   return COUNT;
MIN                     return MIN;
MAX                     return MAX;
AS                      return AS;
FROM                    return FROM;
WHERE                   return WHERE;
STREAM:                 return FROM_STREAM;
TAG:                    return FROM_TAG;
AND                     return AND;
OR                      return OR;
NOT                     return NOT;

-?[1-9][0-9]*           { yylval->integer = atoi(yytext);  return INTEGER; }
-?[1-9][0-9]*\.[0-9]+   { yylval->fval = atof(yytext); return FLOAT; }
\'([^']|'{2})*\'        { yylval->string = remove_dup_qoutes(yytext + 1, yyleng - 2); return STRING; }
[A-Za-z][A-Za-z0-9_]*	{ yylval->string = flb_strdup(yytext); return IDENTIFIER; }

"*"                     |
","                     |
"="                     |
"("                     |
")"                     |
";"                     { return yytext[0]; }

"<"                     return LT;
"<="                    return LTE;
">"                     return GT;
">="                    return GTE;

\'                      return QUOTE;
\n
[ \t]+			/* ignore whitespace */;

%%
