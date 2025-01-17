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

#ifndef YY_FLB_SP_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_SRC_STREAM_PROCESSOR_PARSER_SQL_PARSER_H_INCLUDED
# define YY_FLB_SP_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_SRC_STREAM_PROCESSOR_PARSER_SQL_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int flb_sp_debug;
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
    QUOTE = 259,                   /* QUOTE  */
    CREATE = 260,                  /* CREATE  */
    STREAM = 261,                  /* STREAM  */
    SNAPSHOT = 262,                /* SNAPSHOT  */
    FLUSH = 263,                   /* FLUSH  */
    WITH = 264,                    /* WITH  */
    SELECT = 265,                  /* SELECT  */
    AS = 266,                      /* AS  */
    FROM = 267,                    /* FROM  */
    FROM_STREAM = 268,             /* FROM_STREAM  */
    FROM_TAG = 269,                /* FROM_TAG  */
    WHERE = 270,                   /* WHERE  */
    WINDOW = 271,                  /* WINDOW  */
    GROUP_BY = 272,                /* GROUP_BY  */
    LIMIT = 273,                   /* LIMIT  */
    IS = 274,                      /* IS  */
    NUL = 275,                     /* NUL  */
    AVG = 276,                     /* AVG  */
    SUM = 277,                     /* SUM  */
    COUNT = 278,                   /* COUNT  */
    MAX = 279,                     /* MAX  */
    MIN = 280,                     /* MIN  */
    TIMESERIES_FORECAST = 281,     /* TIMESERIES_FORECAST  */
    RECORD = 282,                  /* RECORD  */
    CONTAINS = 283,                /* CONTAINS  */
    TIME = 284,                    /* TIME  */
    NOW = 285,                     /* NOW  */
    UNIX_TIMESTAMP = 286,          /* UNIX_TIMESTAMP  */
    RECORD_TAG = 287,              /* RECORD_TAG  */
    RECORD_TIME = 288,             /* RECORD_TIME  */
    INTEGER = 289,                 /* INTEGER  */
    FLOATING = 290,                /* FLOATING  */
    STRING = 291,                  /* STRING  */
    BOOLTYPE = 292,                /* BOOLTYPE  */
    AND = 293,                     /* AND  */
    OR = 294,                      /* OR  */
    NOT = 295,                     /* NOT  */
    NEQ = 296,                     /* NEQ  */
    LT = 297,                      /* LT  */
    LTE = 298,                     /* LTE  */
    GT = 299,                      /* GT  */
    GTE = 300,                     /* GTE  */
    HOUR = 301,                    /* HOUR  */
    MINUTE = 302,                  /* MINUTE  */
    SECOND = 303,                  /* SECOND  */
    TUMBLING = 304,                /* TUMBLING  */
    HOPPING = 305,                 /* HOPPING  */
    ADVANCE_BY = 306               /* ADVANCE_BY  */
  };
  typedef enum yytokentype yytoken_kind_t;
#endif

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
union YYSTYPE
{
#line 69 "sql.y"

    bool boolean;
    int integer;
    float fval;
    char *string;
    struct flb_sp_cmd *cmd;
    struct flb_exp *expression;

#line 124 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.h"

};
typedef union YYSTYPE YYSTYPE;
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif




int flb_sp_parse (struct flb_sp_cmd *cmd, const char *query, void *scanner);


#endif /* !YY_FLB_SP_USERS_ADHEIPSINGH_PARSEABLE_FLUENT_BIT_PLUGINS_SRC_STREAM_PROCESSOR_PARSER_SQL_PARSER_H_INCLUDED  */
