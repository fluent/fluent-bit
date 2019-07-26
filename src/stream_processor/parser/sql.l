%option caseless
%{
#include <stdio.h>
#include <stdbool.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include "sql_parser.h"

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

 /* SQL */
CREATE                  return CREATE;
STREAM                  return STREAM;
WITH                    return WITH;
SELECT                  return SELECT;
AS                      return AS;
FROM                    return FROM;
STREAM:                 return FROM_STREAM;
TAG:                    return FROM_TAG;
WHERE                   return WHERE;
AND                     return AND;
OR                      return OR;
NOT                     return NOT;
WINDOW                  return WINDOW;
"GROUP BY"              return GROUP_BY;

IS                      return IS;
NULL                    return NUL;

 /* Aggregation Functions */
SUM                     return SUM;
AVG                     return AVG;
COUNT                   return COUNT;
MIN                     return MIN;
MAX                     return MAX;

 /* Record Functions */
@RECORD                 return RECORD;
CONTAINS                return CONTAINS;
TIME                    return TIME;

 /* Window Types */
TUMBLING                return TUMBLING;
HOPPING                 return HOPPING;
"ADVANCE BY"            return ADVANCE_BY;

 /* Time */
HOUR                    return HOUR;
MINUTE                  return MINUTE;
SECOND                  return SECOND;

 /* Date / Time Functions */
NOW                     return NOW;
UNIX_TIMESTAMP          return UNIX_TIMESTAMP;

 /* Record information */
RECORD_TAG              return RECORD_TAG;
RECORD_TIME             return RECORD_TIME;

"true"                     { yylval->boolean = true;  return BOOLTYPE; };
"false"                    { yylval->boolean = false;  return BOOLTYPE; };

-?[1-9][0-9]*|0            { yylval->integer = atoi(yytext);  return INTEGER; }
(-?[1-9][0-9]*|0)\.[0-9]+  { yylval->fval = atof(yytext); return FLOATING; }
\'([^']|'{2})*\'           { yylval->string = remove_dup_qoutes(yytext + 1, yyleng - 2); return STRING; }

[_A-Za-z][A-Za-z0-9_.]*	   { yylval->string = flb_strdup(yytext); return IDENTIFIER; }

"*"                     |
","                     |
"="                     |
"("                     |
")"                     |
"["                     |
"]"                     |
"."                     |
";"                     { return yytext[0]; }

"<"                     return LT;
"<="                    return LTE;
">"                     return GT;
">="                    return GTE;

\'                      return QUOTE;
\n
[ \t]+			/* ignore whitespace */;

.	flb_error("[sp] bad input character '%s' at line %d", yytext, yylineno);

%%
