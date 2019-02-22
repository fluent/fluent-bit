%option caseless
%{
#include <stdio.h>
#include <fluent-bit/flb_str.h>
#include "sql_parser.h"

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

[0-9]+                  { yylval->integer = atoi(yytext);  return INTEGER;   }
[A-Za-z][A-Za-z0-9_]*	{ yylval->string = flb_strdup(yytext); return IDENTIFIER;}

"*"                     |
","                     |
"="                     |
"("                     |
")"                     |
";"                     { return yytext[0]; }

\'                      return QUOTE;
\n
[ \t]+			/* ignore whitespace */;

%%
