%option prefix="flb_sp_"
%option caseless
%option 8bit reentrant bison-bridge
%option warn noyywrap nodefault
%option nounput
%option noinput


%{
#include <stdio.h>
#include <stdbool.h>
#include <ctype.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_log.h>
#include "sql_parser.h"
#include <fluent-bit/stream_processor/flb_sp_parser.h>

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

char* to_upper(char* token, size_t len)
{
    int i;
    char* token_;

    token_ = flb_malloc(len * sizeof(char) + 1);

    for (i = 0; i < len; i++) {
        token_[i] = toupper(token[i]);
    }

    token_[len] = '\0';
    return token_;
}

int func_to_code(char* name, size_t len)
{
    int code;
    char* name_;

    name_ = to_upper(name, len);
    code = -1;

    if (!strcmp(name_, "AVG")) {
        code = FLB_SP_AVG;
    } else if (!strcmp(name_, "SUM")) {
        code = FLB_SP_SUM;
    } else if (!strcmp(name_, "COUNT")) {
        code = FLB_SP_COUNT;
    } else if (!strcmp(name_, "MIN")) {
        code = FLB_SP_MIN;
    } else if (!strcmp(name_, "MAX")) {
        code = FLB_SP_MAX;
    } else if (!strcmp(name_, "TIMESERIES_FORECAST")) {
        code = FLB_SP_FORECAST;
    } else if (!strcmp(name_, "NOW")) {
        code = FLB_SP_NOW;
    } else if (!strcmp(name_, "UNIX_TIMESTAMP")) {
        code = FLB_SP_UNIX_TIMESTAMP;
    } else if (!strcmp(name_, "RECORD_TAG")) {
        code = FLB_SP_RECORD_TAG;
    } else if (!strcmp(name_, "RECORD_TIME")) {
        code = FLB_SP_RECORD_TIME;
    }

    flb_free(name_);
    return code;
}

%}

%%

 /* SQL */
CREATE                  return CREATE;
FLUSH                   return FLUSH;
STREAM                  return STREAM;
SNAPSHOT                return SNAPSHOT;
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
LIMIT                   return LIMIT;

IS                      return IS;
NULL                    return NUL;

 /* Aggregation Functions */
SUM                     {yylval->integer = func_to_code(yytext, yyleng); return SUM;}
AVG                     {yylval->integer = func_to_code(yytext, yyleng); return AVG;}
COUNT                   {yylval->integer = func_to_code(yytext, yyleng); return COUNT;}
MIN                     {yylval->integer = func_to_code(yytext, yyleng); return MIN;}
MAX                     {yylval->integer = func_to_code(yytext, yyleng); return MAX;}
TIMESERIES_FORECAST     {yylval->integer = func_to_code(yytext, yyleng); return TIMESERIES_FORECAST;};

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
NOW                     {yylval->integer = func_to_code(yytext, yyleng); return NOW;}
UNIX_TIMESTAMP          {yylval->integer = func_to_code(yytext, yyleng); return UNIX_TIMESTAMP;}

 /* Record information */
RECORD_TAG              {yylval->integer = func_to_code(yytext, yyleng); return RECORD_TAG;}
RECORD_TIME             {yylval->integer = func_to_code(yytext, yyleng); return RECORD_TIME;}

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

"!="                    return NEQ;
"<>"                    return NEQ;
"<"                     return LT;
"<="                    return LTE;
">"                     return GT;
">="                    return GTE;

\'                      return QUOTE;
\n
[ \t]+			/* ignore whitespace */;

.	flb_error("[sp] bad input character '%s' at line %d", yytext, yylineno);

%%
