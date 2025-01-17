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

#ifndef YY_YY_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_PLUGINS_PROCESSOR_SQL_PARSER_PROCESSOR_SQL_PARSER_H_INCLUDED
# define YY_YY_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_PLUGINS_PROCESSOR_SQL_PARSER_PROCESSOR_SQL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
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
    SELECT = 258,                  /* SELECT  */
    AS = 259,                      /* AS  */
    FROM = 260,                    /* FROM  */
    FROM_STREAM = 261,             /* FROM_STREAM  */
    FROM_TAG = 262,                /* FROM_TAG  */
    TAG = 263,                     /* TAG  */
    WHERE = 264,                   /* WHERE  */
    IDENTIFIER = 265,              /* IDENTIFIER  */
    QUOTE = 266,                   /* QUOTE  */
    QUOTED = 267,                  /* QUOTED  */
    AVG = 268,                     /* AVG  */
    SUM = 269,                     /* SUM  */
    COUNT = 270,                   /* COUNT  */
    MAX = 271,                     /* MAX  */
    MIN = 272,                     /* MIN  */
    RECORD = 273,                  /* RECORD  */
    CONTAINS = 274,                /* CONTAINS  */
    IS = 275,                      /* IS  */
    NUL = 276,                     /* NUL  */
    AND = 277,                     /* AND  */
    OR = 278,                      /* OR  */
    NOT = 279,                     /* NOT  */
    NEQ = 280,                     /* NEQ  */
    LT = 281,                      /* LT  */
    LTE = 282,                     /* LTE  */
    GT = 283,                      /* GT  */
    GTE = 284,                     /* GTE  */
    INTEGER = 285,                 /* INTEGER  */
    FLOATING = 286,                /* FLOATING  */
    STRING = 287,                  /* STRING  */
    BOOLTYPE = 288                 /* BOOLTYPE  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 52 "sql-parser.y"

  int boolean;
  int integer;
  float fval;
  char *string;
  struct sql_expression *expression;
  struct sql_query *query;

#line 106 "/Users/adheipsingh/parseable/fluent-bit/plugins/plugins/processor_sql/parser/processor-sql_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int yyparse (struct sql_query *query, void *scanner);


#endif /* !YY_YY_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_PLUGINS_PROCESSOR_SQL_PARSER_PROCESSOR_SQL_PARSER_H_INCLUDED  */
