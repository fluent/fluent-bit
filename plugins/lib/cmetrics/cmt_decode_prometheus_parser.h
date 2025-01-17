/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2015, 2018-2021 Free Software Foundation,
   Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

#ifndef YY_CMT_DECODE_PROMETHEUS_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_LIB_CMETRICS_CMT_DECODE_PROMETHEUS_PARSER_H_INCLUDED
# define YY_CMT_DECODE_PROMETHEUS_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_LIB_CMETRICS_CMT_DECODE_PROMETHEUS_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int cmt_decode_prometheus_debug;
#endif

/* Token kinds.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    YYEMPTY = -2,
    YYEOF = 0,                     /* "end of file"  */
    YYerror = 256,                 /* error  */
    YYUNDEF = 257,                 /* "invalid token"  */
    IDENTIFIER = 258,              /* IDENTIFIER  */
    QUOTED = 259,                  /* QUOTED  */
    HELP = 260,                    /* HELP  */
    TYPE = 261,                    /* TYPE  */
    METRIC_DOC = 262,              /* METRIC_DOC  */
    COUNTER = 263,                 /* COUNTER  */
    GAUGE = 264,                   /* GAUGE  */
    SUMMARY = 265,                 /* SUMMARY  */
    UNTYPED = 266,                 /* UNTYPED  */
    HISTOGRAM = 267,               /* HISTOGRAM  */
    START_HEADER = 268,            /* START_HEADER  */
    START_LABELS = 269,            /* START_LABELS  */
    START_SAMPLES = 270,           /* START_SAMPLES  */
    NUMSTR = 271,                  /* NUMSTR  */
    INFNAN = 272                   /* INFNAN  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 15 "cmt_decode_prometheus.y"

    cfl_sds_t str;
    char numstr[64];
    int integer;

#line 87 "/Users/adheipsingh/parseable/fluent-bit/plugins/lib/cmetrics/cmt_decode_prometheus_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int cmt_decode_prometheus_parse (void *yyscanner, struct cmt_decode_prometheus_context *context);


#endif /* !YY_CMT_DECODE_PROMETHEUS_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_LIB_CMETRICS_CMT_DECODE_PROMETHEUS_PARSER_H_INCLUDED  */
