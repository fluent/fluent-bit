/* A Bison parser, made by GNU Bison 3.8.2.  */

/* Bison implementation for Yacc-like parsers in C

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

/* C LALR(1) parser skeleton written by Richard Stallman, by
   simplifying the original so-called "semantic" parser.  */

/* DO NOT RELY ON FEATURES THAT ARE NOT DOCUMENTED in the manual,
   especially those whose name start with YY_ or yy_.  They are
   private implementation details that can be changed or removed.  */

/* All symbols defined below should begin with yy or YY, to avoid
   infringing on user name space.  This should be done even for local
   variables, as they might otherwise be expanded by user macros.
   There are some unavoidable exceptions within include files to
   define necessary library symbols; they are noted "INFRINGES ON
   USER NAME SPACE" below.  */

/* Identify Bison output, and Bison version.  */
#define YYBISON 30802

/* Bison version string.  */
#define YYBISON_VERSION "3.8.2"

/* Skeleton name.  */
#define YYSKELETON_NAME "yacc.c"

/* Pure parsers.  */
#define YYPURE 2

/* Push parsers.  */
#define YYPUSH 0

/* Pull parsers.  */
#define YYPULL 1


/* Substitute the variable and function names.  */
#define yyparse         flb_sp_parse
#define yylex           flb_sp_lex
#define yyerror         flb_sp_error
#define yydebug         flb_sp_debug
#define yynerrs         flb_sp_nerrs

/* First part of user prologue.  */
#line 9 "sql.y"
 // definition section (prologue)
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>
#include <fluent-bit/stream_processor/flb_sp_parser.h>

#include "sql_parser.h"
#include "sql_lex.h"

extern int yylex();

void yyerror(struct flb_sp_cmd *cmd, const char *query, void *scanner, const char *str)
{
    flb_error("[sp] %s at '%s'", str, query);
}


#line 97 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"

# ifndef YY_CAST
#  ifdef __cplusplus
#   define YY_CAST(Type, Val) static_cast<Type> (Val)
#   define YY_REINTERPRET_CAST(Type, Val) reinterpret_cast<Type> (Val)
#  else
#   define YY_CAST(Type, Val) ((Type) (Val))
#   define YY_REINTERPRET_CAST(Type, Val) ((Type) (Val))
#  endif
# endif
# ifndef YY_NULLPTR
#  if defined __cplusplus
#   if 201103L <= __cplusplus
#    define YY_NULLPTR nullptr
#   else
#    define YY_NULLPTR 0
#   endif
#  else
#   define YY_NULLPTR ((void*)0)
#  endif
# endif

#include "sql_parser.h"
/* Symbol kind.  */
enum yysymbol_kind_t
{
  YYSYMBOL_YYEMPTY = -2,
  YYSYMBOL_YYEOF = 0,                      /* "end of file"  */
  YYSYMBOL_YYerror = 1,                    /* error  */
  YYSYMBOL_YYUNDEF = 2,                    /* "invalid token"  */
  YYSYMBOL_IDENTIFIER = 3,                 /* IDENTIFIER  */
  YYSYMBOL_QUOTE = 4,                      /* QUOTE  */
  YYSYMBOL_CREATE = 5,                     /* CREATE  */
  YYSYMBOL_STREAM = 6,                     /* STREAM  */
  YYSYMBOL_SNAPSHOT = 7,                   /* SNAPSHOT  */
  YYSYMBOL_FLUSH = 8,                      /* FLUSH  */
  YYSYMBOL_WITH = 9,                       /* WITH  */
  YYSYMBOL_SELECT = 10,                    /* SELECT  */
  YYSYMBOL_AS = 11,                        /* AS  */
  YYSYMBOL_FROM = 12,                      /* FROM  */
  YYSYMBOL_FROM_STREAM = 13,               /* FROM_STREAM  */
  YYSYMBOL_FROM_TAG = 14,                  /* FROM_TAG  */
  YYSYMBOL_WHERE = 15,                     /* WHERE  */
  YYSYMBOL_WINDOW = 16,                    /* WINDOW  */
  YYSYMBOL_GROUP_BY = 17,                  /* GROUP_BY  */
  YYSYMBOL_LIMIT = 18,                     /* LIMIT  */
  YYSYMBOL_IS = 19,                        /* IS  */
  YYSYMBOL_NUL = 20,                       /* NUL  */
  YYSYMBOL_AVG = 21,                       /* AVG  */
  YYSYMBOL_SUM = 22,                       /* SUM  */
  YYSYMBOL_COUNT = 23,                     /* COUNT  */
  YYSYMBOL_MAX = 24,                       /* MAX  */
  YYSYMBOL_MIN = 25,                       /* MIN  */
  YYSYMBOL_TIMESERIES_FORECAST = 26,       /* TIMESERIES_FORECAST  */
  YYSYMBOL_RECORD = 27,                    /* RECORD  */
  YYSYMBOL_CONTAINS = 28,                  /* CONTAINS  */
  YYSYMBOL_TIME = 29,                      /* TIME  */
  YYSYMBOL_NOW = 30,                       /* NOW  */
  YYSYMBOL_UNIX_TIMESTAMP = 31,            /* UNIX_TIMESTAMP  */
  YYSYMBOL_RECORD_TAG = 32,                /* RECORD_TAG  */
  YYSYMBOL_RECORD_TIME = 33,               /* RECORD_TIME  */
  YYSYMBOL_INTEGER = 34,                   /* INTEGER  */
  YYSYMBOL_FLOATING = 35,                  /* FLOATING  */
  YYSYMBOL_STRING = 36,                    /* STRING  */
  YYSYMBOL_BOOLTYPE = 37,                  /* BOOLTYPE  */
  YYSYMBOL_AND = 38,                       /* AND  */
  YYSYMBOL_OR = 39,                        /* OR  */
  YYSYMBOL_NOT = 40,                       /* NOT  */
  YYSYMBOL_NEQ = 41,                       /* NEQ  */
  YYSYMBOL_LT = 42,                        /* LT  */
  YYSYMBOL_LTE = 43,                       /* LTE  */
  YYSYMBOL_GT = 44,                        /* GT  */
  YYSYMBOL_GTE = 45,                       /* GTE  */
  YYSYMBOL_HOUR = 46,                      /* HOUR  */
  YYSYMBOL_MINUTE = 47,                    /* MINUTE  */
  YYSYMBOL_SECOND = 48,                    /* SECOND  */
  YYSYMBOL_TUMBLING = 49,                  /* TUMBLING  */
  YYSYMBOL_HOPPING = 50,                   /* HOPPING  */
  YYSYMBOL_ADVANCE_BY = 51,                /* ADVANCE_BY  */
  YYSYMBOL_52_ = 52,                       /* '('  */
  YYSYMBOL_53_ = 53,                       /* ')'  */
  YYSYMBOL_54_ = 54,                       /* '*'  */
  YYSYMBOL_55_ = 55,                       /* ';'  */
  YYSYMBOL_56_ = 56,                       /* ','  */
  YYSYMBOL_57_ = 57,                       /* '='  */
  YYSYMBOL_58_ = 58,                       /* '['  */
  YYSYMBOL_59_ = 59,                       /* ']'  */
  YYSYMBOL_60_ = 60,                       /* '.'  */
  YYSYMBOL_YYACCEPT = 61,                  /* $accept  */
  YYSYMBOL_statements = 62,                /* statements  */
  YYSYMBOL_create = 63,                    /* create  */
  YYSYMBOL_properties = 64,                /* properties  */
  YYSYMBOL_property = 65,                  /* property  */
  YYSYMBOL_prop_key = 66,                  /* prop_key  */
  YYSYMBOL_prop_val = 67,                  /* prop_val  */
  YYSYMBOL_select = 68,                    /* select  */
  YYSYMBOL_keys = 69,                      /* keys  */
  YYSYMBOL_record_keys = 70,               /* record_keys  */
  YYSYMBOL_record_key = 71,                /* record_key  */
  YYSYMBOL_aggregate_func = 72,            /* aggregate_func  */
  YYSYMBOL_time_record_func = 73,          /* time_record_func  */
  YYSYMBOL_key_alias = 74,                 /* key_alias  */
  YYSYMBOL_record_subkey = 75,             /* record_subkey  */
  YYSYMBOL_source = 76,                    /* source  */
  YYSYMBOL_window = 77,                    /* window  */
  YYSYMBOL_where = 78,                     /* where  */
  YYSYMBOL_groupby = 79,                   /* groupby  */
  YYSYMBOL_limit = 80,                     /* limit  */
  YYSYMBOL_window_spec = 81,               /* window_spec  */
  YYSYMBOL_condition = 82,                 /* condition  */
  YYSYMBOL_comparison = 83,                /* comparison  */
  YYSYMBOL_record_func = 84,               /* record_func  */
  YYSYMBOL_key = 85,                       /* key  */
  YYSYMBOL_value = 86,                     /* value  */
  YYSYMBOL_null = 87,                      /* null  */
  YYSYMBOL_time = 88,                      /* time  */
  YYSYMBOL_gb_keys = 89,                   /* gb_keys  */
  YYSYMBOL_gb_key = 90                     /* gb_key  */
};
typedef enum yysymbol_kind_t yysymbol_kind_t;




#ifdef short
# undef short
#endif

/* On compilers that do not define __PTRDIFF_MAX__ etc., make sure
   <limits.h> and (if available) <stdint.h> are included
   so that the code can choose integer types of a good width.  */

#ifndef __PTRDIFF_MAX__
# include <limits.h> /* INFRINGES ON USER NAME SPACE */
# if defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stdint.h> /* INFRINGES ON USER NAME SPACE */
#  define YY_STDINT_H
# endif
#endif

/* Narrow types that promote to a signed type and that can represent a
   signed or unsigned integer of at least N bits.  In tables they can
   save space and decrease cache pressure.  Promoting to a signed type
   helps avoid bugs in integer arithmetic.  */

#ifdef __INT_LEAST8_MAX__
typedef __INT_LEAST8_TYPE__ yytype_int8;
#elif defined YY_STDINT_H
typedef int_least8_t yytype_int8;
#else
typedef signed char yytype_int8;
#endif

#ifdef __INT_LEAST16_MAX__
typedef __INT_LEAST16_TYPE__ yytype_int16;
#elif defined YY_STDINT_H
typedef int_least16_t yytype_int16;
#else
typedef short yytype_int16;
#endif

/* Work around bug in HP-UX 11.23, which defines these macros
   incorrectly for preprocessor constants.  This workaround can likely
   be removed in 2023, as HPE has promised support for HP-UX 11.23
   (aka HP-UX 11i v2) only through the end of 2022; see Table 2 of
   <https://h20195.www2.hpe.com/V2/getpdf.aspx/4AA4-7673ENW.pdf>.  */
#ifdef __hpux
# undef UINT_LEAST8_MAX
# undef UINT_LEAST16_MAX
# define UINT_LEAST8_MAX 255
# define UINT_LEAST16_MAX 65535
#endif

#if defined __UINT_LEAST8_MAX__ && __UINT_LEAST8_MAX__ <= __INT_MAX__
typedef __UINT_LEAST8_TYPE__ yytype_uint8;
#elif (!defined __UINT_LEAST8_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST8_MAX <= INT_MAX)
typedef uint_least8_t yytype_uint8;
#elif !defined __UINT_LEAST8_MAX__ && UCHAR_MAX <= INT_MAX
typedef unsigned char yytype_uint8;
#else
typedef short yytype_uint8;
#endif

#if defined __UINT_LEAST16_MAX__ && __UINT_LEAST16_MAX__ <= __INT_MAX__
typedef __UINT_LEAST16_TYPE__ yytype_uint16;
#elif (!defined __UINT_LEAST16_MAX__ && defined YY_STDINT_H \
       && UINT_LEAST16_MAX <= INT_MAX)
typedef uint_least16_t yytype_uint16;
#elif !defined __UINT_LEAST16_MAX__ && USHRT_MAX <= INT_MAX
typedef unsigned short yytype_uint16;
#else
typedef int yytype_uint16;
#endif

#ifndef YYPTRDIFF_T
# if defined __PTRDIFF_TYPE__ && defined __PTRDIFF_MAX__
#  define YYPTRDIFF_T __PTRDIFF_TYPE__
#  define YYPTRDIFF_MAXIMUM __PTRDIFF_MAX__
# elif defined PTRDIFF_MAX
#  ifndef ptrdiff_t
#   include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  endif
#  define YYPTRDIFF_T ptrdiff_t
#  define YYPTRDIFF_MAXIMUM PTRDIFF_MAX
# else
#  define YYPTRDIFF_T long
#  define YYPTRDIFF_MAXIMUM LONG_MAX
# endif
#endif

#ifndef YYSIZE_T
# ifdef __SIZE_TYPE__
#  define YYSIZE_T __SIZE_TYPE__
# elif defined size_t
#  define YYSIZE_T size_t
# elif defined __STDC_VERSION__ && 199901 <= __STDC_VERSION__
#  include <stddef.h> /* INFRINGES ON USER NAME SPACE */
#  define YYSIZE_T size_t
# else
#  define YYSIZE_T unsigned
# endif
#endif

#define YYSIZE_MAXIMUM                                  \
  YY_CAST (YYPTRDIFF_T,                                 \
           (YYPTRDIFF_MAXIMUM < YY_CAST (YYSIZE_T, -1)  \
            ? YYPTRDIFF_MAXIMUM                         \
            : YY_CAST (YYSIZE_T, -1)))

#define YYSIZEOF(X) YY_CAST (YYPTRDIFF_T, sizeof (X))


/* Stored state numbers (used for stacks). */
typedef yytype_uint8 yy_state_t;

/* State numbers in computations.  */
typedef int yy_state_fast_t;

#ifndef YY_
# if defined YYENABLE_NLS && YYENABLE_NLS
#  if ENABLE_NLS
#   include <libintl.h> /* INFRINGES ON USER NAME SPACE */
#   define YY_(Msgid) dgettext ("bison-runtime", Msgid)
#  endif
# endif
# ifndef YY_
#  define YY_(Msgid) Msgid
# endif
#endif


#ifndef YY_ATTRIBUTE_PURE
# if defined __GNUC__ && 2 < __GNUC__ + (96 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_PURE __attribute__ ((__pure__))
# else
#  define YY_ATTRIBUTE_PURE
# endif
#endif

#ifndef YY_ATTRIBUTE_UNUSED
# if defined __GNUC__ && 2 < __GNUC__ + (7 <= __GNUC_MINOR__)
#  define YY_ATTRIBUTE_UNUSED __attribute__ ((__unused__))
# else
#  define YY_ATTRIBUTE_UNUSED
# endif
#endif

/* Suppress unused-variable warnings by "using" E.  */
#if ! defined lint || defined __GNUC__
# define YY_USE(E) ((void) (E))
#else
# define YY_USE(E) /* empty */
#endif

/* Suppress an incorrect diagnostic about yylval being uninitialized.  */
#if defined __GNUC__ && ! defined __ICC && 406 <= __GNUC__ * 100 + __GNUC_MINOR__
# if __GNUC__ * 100 + __GNUC_MINOR__ < 407
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")
# else
#  define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN                           \
    _Pragma ("GCC diagnostic push")                                     \
    _Pragma ("GCC diagnostic ignored \"-Wuninitialized\"")              \
    _Pragma ("GCC diagnostic ignored \"-Wmaybe-uninitialized\"")
# endif
# define YY_IGNORE_MAYBE_UNINITIALIZED_END      \
    _Pragma ("GCC diagnostic pop")
#else
# define YY_INITIAL_VALUE(Value) Value
#endif
#ifndef YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
# define YY_IGNORE_MAYBE_UNINITIALIZED_END
#endif
#ifndef YY_INITIAL_VALUE
# define YY_INITIAL_VALUE(Value) /* Nothing. */
#endif

#if defined __cplusplus && defined __GNUC__ && ! defined __ICC && 6 <= __GNUC__
# define YY_IGNORE_USELESS_CAST_BEGIN                          \
    _Pragma ("GCC diagnostic push")                            \
    _Pragma ("GCC diagnostic ignored \"-Wuseless-cast\"")
# define YY_IGNORE_USELESS_CAST_END            \
    _Pragma ("GCC diagnostic pop")
#endif
#ifndef YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_BEGIN
# define YY_IGNORE_USELESS_CAST_END
#endif


#define YY_ASSERT(E) ((void) (0 && (E)))

#if 1

/* The parser invokes alloca or malloc; define the necessary symbols.  */

# ifdef YYSTACK_USE_ALLOCA
#  if YYSTACK_USE_ALLOCA
#   ifdef __GNUC__
#    define YYSTACK_ALLOC __builtin_alloca
#   elif defined __BUILTIN_VA_ARG_INCR
#    include <alloca.h> /* INFRINGES ON USER NAME SPACE */
#   elif defined _AIX
#    define YYSTACK_ALLOC __alloca
#   elif defined _MSC_VER
#    include <malloc.h> /* INFRINGES ON USER NAME SPACE */
#    define alloca _alloca
#   else
#    define YYSTACK_ALLOC alloca
#    if ! defined _ALLOCA_H && ! defined EXIT_SUCCESS
#     include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
      /* Use EXIT_SUCCESS as a witness for stdlib.h.  */
#     ifndef EXIT_SUCCESS
#      define EXIT_SUCCESS 0
#     endif
#    endif
#   endif
#  endif
# endif

# ifdef YYSTACK_ALLOC
   /* Pacify GCC's 'empty if-body' warning.  */
#  define YYSTACK_FREE(Ptr) do { /* empty */; } while (0)
#  ifndef YYSTACK_ALLOC_MAXIMUM
    /* The OS might guarantee only one guard page at the bottom of the stack,
       and a page size can be as small as 4096 bytes.  So we cannot safely
       invoke alloca (N) if N exceeds 4096.  Use a slightly smaller number
       to allow for a few compiler-allocated temporary stack slots.  */
#   define YYSTACK_ALLOC_MAXIMUM 4032 /* reasonable circa 2006 */
#  endif
# else
#  define YYSTACK_ALLOC YYMALLOC
#  define YYSTACK_FREE YYFREE
#  ifndef YYSTACK_ALLOC_MAXIMUM
#   define YYSTACK_ALLOC_MAXIMUM YYSIZE_MAXIMUM
#  endif
#  if (defined __cplusplus && ! defined EXIT_SUCCESS \
       && ! ((defined YYMALLOC || defined malloc) \
             && (defined YYFREE || defined free)))
#   include <stdlib.h> /* INFRINGES ON USER NAME SPACE */
#   ifndef EXIT_SUCCESS
#    define EXIT_SUCCESS 0
#   endif
#  endif
#  ifndef YYMALLOC
#   define YYMALLOC malloc
#   if ! defined malloc && ! defined EXIT_SUCCESS
void *malloc (YYSIZE_T); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
#  ifndef YYFREE
#   define YYFREE free
#   if ! defined free && ! defined EXIT_SUCCESS
void free (void *); /* INFRINGES ON USER NAME SPACE */
#   endif
#  endif
# endif
#endif /* 1 */

#if (! defined yyoverflow \
     && (! defined __cplusplus \
         || (defined YYSTYPE_IS_TRIVIAL && YYSTYPE_IS_TRIVIAL)))

/* A type that is properly aligned for any stack member.  */
union yyalloc
{
  yy_state_t yyss_alloc;
  YYSTYPE yyvs_alloc;
};

/* The size of the maximum gap between one aligned stack and the next.  */
# define YYSTACK_GAP_MAXIMUM (YYSIZEOF (union yyalloc) - 1)

/* The size of an array large to enough to hold all stacks, each with
   N elements.  */
# define YYSTACK_BYTES(N) \
     ((N) * (YYSIZEOF (yy_state_t) + YYSIZEOF (YYSTYPE)) \
      + YYSTACK_GAP_MAXIMUM)

# define YYCOPY_NEEDED 1

/* Relocate STACK from its old location to the new one.  The
   local variables YYSIZE and YYSTACKSIZE give the old and new number of
   elements in the stack, and YYPTR gives the new location of the
   stack.  Advance YYPTR to a properly aligned location for the next
   stack.  */
# define YYSTACK_RELOCATE(Stack_alloc, Stack)                           \
    do                                                                  \
      {                                                                 \
        YYPTRDIFF_T yynewbytes;                                         \
        YYCOPY (&yyptr->Stack_alloc, Stack, yysize);                    \
        Stack = &yyptr->Stack_alloc;                                    \
        yynewbytes = yystacksize * YYSIZEOF (*Stack) + YYSTACK_GAP_MAXIMUM; \
        yyptr += yynewbytes / YYSIZEOF (*yyptr);                        \
      }                                                                 \
    while (0)

#endif

#if defined YYCOPY_NEEDED && YYCOPY_NEEDED
/* Copy COUNT objects from SRC to DST.  The source and destination do
   not overlap.  */
# ifndef YYCOPY
#  if defined __GNUC__ && 1 < __GNUC__
#   define YYCOPY(Dst, Src, Count) \
      __builtin_memcpy (Dst, Src, YY_CAST (YYSIZE_T, (Count)) * sizeof (*(Src)))
#  else
#   define YYCOPY(Dst, Src, Count)              \
      do                                        \
        {                                       \
          YYPTRDIFF_T yyi;                      \
          for (yyi = 0; yyi < (Count); yyi++)   \
            (Dst)[yyi] = (Src)[yyi];            \
        }                                       \
      while (0)
#  endif
# endif
#endif /* !YYCOPY_NEEDED */

/* YYFINAL -- State number of the termination state.  */
#define YYFINAL  27
/* YYLAST -- Last index in YYTABLE.  */
#define YYLAST   211

/* YYNTOKENS -- Number of terminals.  */
#define YYNTOKENS  61
/* YYNNTS -- Number of nonterminals.  */
#define YYNNTS  30
/* YYNRULES -- Number of rules.  */
#define YYNRULES  85
/* YYNSTATES -- Number of states.  */
#define YYNSTATES  206

/* YYMAXUTOK -- Last valid token kind.  */
#define YYMAXUTOK   306


/* YYTRANSLATE(TOKEN-NUM) -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex, with out-of-bounds checking.  */
#define YYTRANSLATE(YYX)                                \
  (0 <= (YYX) && (YYX) <= YYMAXUTOK                     \
   ? YY_CAST (yysymbol_kind_t, yytranslate[YYX])        \
   : YYSYMBOL_YYUNDEF)

/* YYTRANSLATE[TOKEN-NUM] -- Symbol number corresponding to TOKEN-NUM
   as returned by yylex.  */
static const yytype_int8 yytranslate[] =
{
       0,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
      52,    53,    54,     2,    56,     2,    60,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,    55,
       2,    57,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,    58,     2,    59,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     2,     2,     2,     2,
       2,     2,     2,     2,     2,     2,     1,     2,     3,     4,
       5,     6,     7,     8,     9,    10,    11,    12,    13,    14,
      15,    16,    17,    18,    19,    20,    21,    22,    23,    24,
      25,    26,    27,    28,    29,    30,    31,    32,    33,    34,
      35,    36,    37,    38,    39,    40,    41,    42,    43,    44,
      45,    46,    47,    48,    49,    50,    51
};

#if YYDEBUG
/* YYRLINE[YYN] -- Source line where rule number YYN was defined.  */
static const yytype_int16 yyrline[] =
{
       0,   106,   106,   106,   110,   116,   122,   128,   134,   140,
     145,   147,   148,   154,   155,   158,   162,   163,   165,   166,
     171,   177,   183,   188,   194,   200,   206,   212,   218,   223,
     223,   223,   223,   225,   225,   225,   225,   227,   229,   233,
     239,   240,   246,   251,   253,   254,   256,   260,   262,   263,
     265,   270,   275,   279,   281,   286,   291,   296,   301,   306,
     311,   316,   323,   331,   336,   344,   349,   354,   359,   363,
     365,   370,   374,   380,   385,   390,   395,   401,   405,   409,
     414,   419,   423,   425,   426,   432
};
#endif

/** Accessing symbol of state STATE.  */
#define YY_ACCESSING_SYMBOL(State) YY_CAST (yysymbol_kind_t, yystos[State])

#if 1
/* The user-facing name of the symbol whose (internal) number is
   YYSYMBOL.  No bounds checking.  */
static const char *yysymbol_name (yysymbol_kind_t yysymbol) YY_ATTRIBUTE_UNUSED;

/* YYTNAME[SYMBOL-NUM] -- String name of the symbol SYMBOL-NUM.
   First, the terminals, then, starting at YYNTOKENS, nonterminals.  */
static const char *const yytname[] =
{
  "\"end of file\"", "error", "\"invalid token\"", "IDENTIFIER", "QUOTE",
  "CREATE", "STREAM", "SNAPSHOT", "FLUSH", "WITH", "SELECT", "AS", "FROM",
  "FROM_STREAM", "FROM_TAG", "WHERE", "WINDOW", "GROUP_BY", "LIMIT", "IS",
  "NUL", "AVG", "SUM", "COUNT", "MAX", "MIN", "TIMESERIES_FORECAST",
  "RECORD", "CONTAINS", "TIME", "NOW", "UNIX_TIMESTAMP", "RECORD_TAG",
  "RECORD_TIME", "INTEGER", "FLOATING", "STRING", "BOOLTYPE", "AND", "OR",
  "NOT", "NEQ", "LT", "LTE", "GT", "GTE", "HOUR", "MINUTE", "SECOND",
  "TUMBLING", "HOPPING", "ADVANCE_BY", "'('", "')'", "'*'", "';'", "','",
  "'='", "'['", "']'", "'.'", "$accept", "statements", "create",
  "properties", "property", "prop_key", "prop_val", "select", "keys",
  "record_keys", "record_key", "aggregate_func", "time_record_func",
  "key_alias", "record_subkey", "source", "window", "where", "groupby",
  "limit", "window_spec", "condition", "comparison", "record_func", "key",
  "value", "null", "time", "gb_keys", "gb_key", YY_NULLPTR
};

static const char *
yysymbol_name (yysymbol_kind_t yysymbol)
{
  return yytname[yysymbol];
}
#endif

#define YYPACT_NINF (-129)

#define yypact_value_is_default(Yyn) \
  ((Yyn) == YYPACT_NINF)

#define YYTABLE_NINF (-70)

#define yytable_value_is_error(Yyn) \
  0

/* YYPACT[STATE-NUM] -- Index in YYTABLE of the portion describing
   STATE-NUM.  */
static const yytype_int16 yypact[] =
{
      59,   113,    16,    28,    26,  -129,  -129,    29,    33,    37,
       5,  -129,  -129,     3,  -129,  -129,    19,  -129,  -129,  -129,
    -129,  -129,    92,     9,  -129,    34,    65,  -129,    13,    35,
      74,   120,    94,  -129,     5,     8,   128,   108,    28,   129,
      80,    82,   125,    84,   127,    87,   130,  -129,    83,  -129,
      85,   -28,    91,    89,   138,   110,   131,  -129,   -15,   137,
     146,  -129,   146,    96,   146,    97,  -129,   137,   -11,   137,
     118,  -129,  -129,    75,   139,   137,    15,  -129,  -129,   -41,
    -129,    98,    23,   141,    25,   144,  -129,   137,  -129,   104,
     106,   107,  -129,    53,   143,  -129,   137,   150,   146,   126,
     152,   108,   153,   108,  -129,   137,   132,   133,    85,   105,
    -129,  -129,  -129,  -129,    53,    53,    88,  -129,   -24,    58,
    -129,   165,   151,  -129,   125,  -129,  -129,  -129,   160,   151,
     161,   139,  -129,    66,    66,    85,   100,    88,   -25,    53,
      53,    60,    60,    60,    60,    60,    60,   -13,    85,  -129,
     116,   140,   121,  -129,   119,   122,   124,   134,  -129,  -129,
    -129,   135,   123,   142,   145,  -129,    88,    88,  -129,  -129,
    -129,  -129,  -129,  -129,  -129,   155,  -129,    85,   165,  -129,
    -129,   168,  -129,   169,  -129,  -129,   136,   179,   147,  -129,
    -129,   108,   108,   149,   148,  -129,   151,   139,    66,  -129,
     154,   156,   157,  -129,  -129,  -129
};

/* YYDEFACT[STATE-NUM] -- Default reduction number in state STATE-NUM.
   Performed when YYTABLE does not specify something else to do.  Zero
   means the default is an error.  */
static const yytype_int8 yydefact[] =
{
       0,     0,     0,     0,     0,     2,     3,     0,     0,     0,
      37,    29,    30,     0,    31,    32,     0,    33,    34,    35,
      36,    19,     0,    16,    17,     0,     0,     1,     0,     0,
       0,     0,     0,    20,    37,     0,     0,     0,     0,     0,
       0,     0,     0,     0,     0,     0,     0,    38,     0,    21,
      40,     0,     0,     0,     0,     0,    43,    18,     0,    37,
       0,     4,     0,     0,     0,     0,    39,    37,     0,    37,
       0,    41,    42,     0,    45,    37,     0,    28,    13,     0,
      10,     0,     0,     0,     0,     0,    23,    37,    22,     0,
       0,     0,    44,     0,    47,    25,    37,     0,     0,     0,
       0,     0,     0,     0,    24,    37,     0,     0,    72,     0,
      74,    75,    76,    77,     0,     0,    46,    53,    62,    54,
      55,     0,    49,    26,     0,    11,    14,    12,     0,    49,
       0,    45,    27,     0,     0,    73,     0,    57,     0,     0,
       0,     0,     0,     0,     0,     0,     0,     0,    84,    48,
      82,     0,     0,     5,     0,     0,     0,     0,    81,    80,
      79,     0,     0,     0,     0,    56,    58,    59,    64,    65,
      66,    67,    68,    63,    78,     0,    60,    85,     0,    50,
      15,     0,     6,     0,     8,    51,     0,     0,     0,    61,
      83,     0,     0,     0,     0,    71,    49,    45,     0,    70,
       0,     0,     0,     7,     9,    52
};

/* YYPGOTO[NTERM-NUM].  */
static const yytype_int16 yypgoto[] =
{
    -129,  -129,  -129,    54,    86,  -129,  -129,   -40,  -129,  -129,
     158,  -129,  -129,   -30,   -10,  -100,  -129,  -123,  -129,  -124,
    -129,  -105,  -129,  -129,    -2,   -35,    11,  -128,    12,  -129
};

/* YYDEFGOTO[NTERM-NUM].  */
static const yytype_uint8 yydefgoto[] =
{
       0,     4,     5,    79,    80,    81,   127,     6,    22,    23,
      24,    25,    26,    33,    50,    56,    74,    94,   122,   152,
      92,   116,   117,   118,   119,   120,   176,   161,   149,   150
};

/* YYTABLE[YYPACT[STATE-NUM]] -- What to do in state STATE-NUM.  If
   positive, shift that token.  If negative, reduce the rule whose
   number is the opposite.  If YYTABLE_NINF, syntax error.  */
static const yytype_int16 yytable[] =
{
      34,   129,    61,   131,    49,   155,   162,   174,   157,   137,
     138,    51,    97,   139,   140,    98,    31,   141,   142,   143,
     144,   145,    41,     9,    42,    67,    27,   175,   165,    77,
      32,    10,    28,   146,   166,   167,    29,    86,    75,    88,
      30,    68,    87,    32,    43,    95,    44,    32,    76,    11,
      12,    13,    14,    15,    16,    35,   108,   104,    17,    18,
      19,    20,    52,    32,     1,    38,   123,     2,    96,     3,
     202,    36,   200,    32,   201,   132,   100,   147,   102,    98,
     109,    98,    21,    45,   153,    46,    39,   110,   111,   112,
     113,   196,   197,   114,   110,   111,   112,   113,   135,   -69,
     -69,   -69,   -69,   -69,    37,   115,   168,   169,   170,   171,
     172,   173,   158,   159,   160,   -69,    82,    40,    84,     7,
       8,    54,    55,    47,    90,    91,   139,   140,   163,   164,
      48,    53,    58,    59,    60,     3,    62,    63,   177,    64,
      65,    71,    66,    32,    69,    70,    72,    73,    31,    78,
      83,    85,    89,   101,    93,    99,   103,   105,   106,   107,
     121,   124,   126,   128,   130,   136,   133,   134,   148,   151,
     154,   156,   178,   181,   179,   174,   180,   182,   183,   186,
     191,   192,   108,   198,   125,   194,   189,   193,   185,   184,
     190,     0,     0,     0,   187,     0,    57,   188,     0,     0,
     195,   199,     0,     0,     0,     0,     0,     0,     0,   203,
     205,   204
};

static const yytype_int16 yycheck[] =
{
      10,   101,    42,   103,    34,   129,   134,    20,   131,   114,
     115,     3,    53,    38,    39,    56,    11,    41,    42,    43,
      44,    45,     9,     7,    11,    53,     0,    40,    53,    59,
      58,     3,     3,    57,   139,   140,     3,    67,    53,    69,
       3,    51,    53,    58,     9,    75,    11,    58,    58,    21,
      22,    23,    24,    25,    26,    52,     3,    87,    30,    31,
      32,    33,    54,    58,     5,    56,    96,     8,    53,    10,
     198,    52,   196,    58,   197,   105,    53,    19,    53,    56,
      27,    56,    54,     9,   124,    11,    52,    34,    35,    36,
      37,   191,   192,    40,    34,    35,    36,    37,   108,    41,
      42,    43,    44,    45,    12,    52,   141,   142,   143,   144,
     145,   146,    46,    47,    48,    57,    62,    52,    64,     6,
       7,    13,    14,     3,    49,    50,    38,    39,    28,    29,
      36,     3,     3,    53,    52,    10,    52,    10,   148,    52,
      10,     3,    59,    58,    53,    56,    36,    16,    11,     3,
      54,    54,    34,    12,    15,    57,    12,    53,    52,    52,
      17,    11,    36,    11,    11,    60,    34,    34,     3,    18,
      10,    10,    56,    54,    34,    20,    55,    55,    54,    56,
      12,    12,     3,    34,    98,   187,   175,    51,    53,    55,
     178,    -1,    -1,    -1,    52,    -1,    38,    52,    -1,    -1,
      53,    53,    -1,    -1,    -1,    -1,    -1,    -1,    -1,    55,
      53,    55
};

/* YYSTOS[STATE-NUM] -- The symbol kind of the accessing symbol of
   state STATE-NUM.  */
static const yytype_int8 yystos[] =
{
       0,     5,     8,    10,    62,    63,    68,     6,     7,     7,
       3,    21,    22,    23,    24,    25,    26,    30,    31,    32,
      33,    54,    69,    70,    71,    72,    73,     0,     3,     3,
       3,    11,    58,    74,    75,    52,    52,    12,    56,    52,
      52,     9,    11,     9,    11,     9,    11,     3,    36,    74,
      75,     3,    54,     3,    13,    14,    76,    71,     3,    53,
      52,    68,    52,    10,    52,    10,    59,    53,    75,    53,
      56,     3,    36,    16,    77,    53,    75,    74,     3,    64,
      65,    66,    64,    54,    64,    54,    74,    53,    74,    34,
      49,    50,    81,    15,    78,    74,    53,    53,    56,    57,
      53,    12,    53,    12,    74,    53,    52,    52,     3,    27,
      34,    35,    36,    37,    40,    52,    82,    83,    84,    85,
      86,    17,    79,    74,    11,    65,    36,    67,    11,    76,
      11,    76,    74,    34,    34,    75,    60,    82,    82,    38,
      39,    41,    42,    43,    44,    45,    57,    19,     3,    89,
      90,    18,    80,    68,    10,    80,    10,    78,    46,    47,
      48,    88,    88,    28,    29,    53,    82,    82,    86,    86,
      86,    86,    86,    86,    20,    40,    87,    75,    56,    34,
      55,    54,    55,    54,    55,    53,    56,    52,    52,    87,
      89,    12,    12,    51,    85,    53,    76,    76,    34,    53,
      80,    78,    88,    55,    55,    53
};

/* YYR1[RULE-NUM] -- Symbol kind of the left-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr1[] =
{
       0,    61,    62,    62,    63,    63,    63,    63,    63,    63,
      64,    64,    65,    66,    67,    68,    69,    70,    70,    71,
      71,    71,    71,    71,    71,    71,    71,    71,    71,    72,
      72,    72,    72,    73,    73,    73,    73,    74,    74,    75,
      75,    76,    76,    77,    77,    78,    78,    79,    79,    80,
      80,    81,    81,    82,    82,    82,    82,    82,    82,    82,
      83,    83,    83,    83,    83,    83,    83,    83,    83,    84,
      84,    84,    85,    85,    86,    86,    86,    86,    87,    88,
      88,    88,    89,    89,    90,    90
};

/* YYR2[RULE-NUM] -- Number of symbols on the right-hand side of rule RULE-NUM.  */
static const yytype_int8 yyr2[] =
{
       0,     2,     1,     1,     5,     9,    10,    14,    10,    14,
       1,     3,     3,     1,     1,     9,     1,     1,     3,     1,
       2,     3,     5,     5,     6,     5,     6,     7,     4,     1,
       1,     1,     1,     1,     1,     1,     1,     0,     2,     3,
       2,     2,     2,     0,     2,     0,     2,     0,     2,     0,
       2,     5,     9,     1,     1,     1,     3,     2,     3,     3,
       3,     4,     1,     3,     3,     3,     3,     3,     3,     1,
       6,     5,     1,     2,     1,     1,     1,     1,     1,     1,
       1,     1,     1,     3,     1,     2
};


enum { YYENOMEM = -2 };

#define yyerrok         (yyerrstatus = 0)
#define yyclearin       (yychar = YYEMPTY)

#define YYACCEPT        goto yyacceptlab
#define YYABORT         goto yyabortlab
#define YYERROR         goto yyerrorlab
#define YYNOMEM         goto yyexhaustedlab


#define YYRECOVERING()  (!!yyerrstatus)

#define YYBACKUP(Token, Value)                                    \
  do                                                              \
    if (yychar == YYEMPTY)                                        \
      {                                                           \
        yychar = (Token);                                         \
        yylval = (Value);                                         \
        YYPOPSTACK (yylen);                                       \
        yystate = *yyssp;                                         \
        goto yybackup;                                            \
      }                                                           \
    else                                                          \
      {                                                           \
        yyerror (cmd, query, scanner, YY_("syntax error: cannot back up")); \
        YYERROR;                                                  \
      }                                                           \
  while (0)

/* Backward compatibility with an undocumented macro.
   Use YYerror or YYUNDEF. */
#define YYERRCODE YYUNDEF


/* Enable debugging if requested.  */
#if YYDEBUG

# ifndef YYFPRINTF
#  include <stdio.h> /* INFRINGES ON USER NAME SPACE */
#  define YYFPRINTF fprintf
# endif

# define YYDPRINTF(Args)                        \
do {                                            \
  if (yydebug)                                  \
    YYFPRINTF Args;                             \
} while (0)




# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)                    \
do {                                                                      \
  if (yydebug)                                                            \
    {                                                                     \
      YYFPRINTF (stderr, "%s ", Title);                                   \
      yy_symbol_print (stderr,                                            \
                  Kind, Value, cmd, query, scanner); \
      YYFPRINTF (stderr, "\n");                                           \
    }                                                                     \
} while (0)


/*-----------------------------------.
| Print this symbol's value on YYO.  |
`-----------------------------------*/

static void
yy_symbol_value_print (FILE *yyo,
                       yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, struct flb_sp_cmd *cmd, const char *query, void *scanner)
{
  FILE *yyoutput = yyo;
  YY_USE (yyoutput);
  YY_USE (cmd);
  YY_USE (query);
  YY_USE (scanner);
  if (!yyvaluep)
    return;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  YY_USE (yykind);
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}


/*---------------------------.
| Print this symbol on YYO.  |
`---------------------------*/

static void
yy_symbol_print (FILE *yyo,
                 yysymbol_kind_t yykind, YYSTYPE const * const yyvaluep, struct flb_sp_cmd *cmd, const char *query, void *scanner)
{
  YYFPRINTF (yyo, "%s %s (",
             yykind < YYNTOKENS ? "token" : "nterm", yysymbol_name (yykind));

  yy_symbol_value_print (yyo, yykind, yyvaluep, cmd, query, scanner);
  YYFPRINTF (yyo, ")");
}

/*------------------------------------------------------------------.
| yy_stack_print -- Print the state stack from its BOTTOM up to its |
| TOP (included).                                                   |
`------------------------------------------------------------------*/

static void
yy_stack_print (yy_state_t *yybottom, yy_state_t *yytop)
{
  YYFPRINTF (stderr, "Stack now");
  for (; yybottom <= yytop; yybottom++)
    {
      int yybot = *yybottom;
      YYFPRINTF (stderr, " %d", yybot);
    }
  YYFPRINTF (stderr, "\n");
}

# define YY_STACK_PRINT(Bottom, Top)                            \
do {                                                            \
  if (yydebug)                                                  \
    yy_stack_print ((Bottom), (Top));                           \
} while (0)


/*------------------------------------------------.
| Report that the YYRULE is going to be reduced.  |
`------------------------------------------------*/

static void
yy_reduce_print (yy_state_t *yyssp, YYSTYPE *yyvsp,
                 int yyrule, struct flb_sp_cmd *cmd, const char *query, void *scanner)
{
  int yylno = yyrline[yyrule];
  int yynrhs = yyr2[yyrule];
  int yyi;
  YYFPRINTF (stderr, "Reducing stack by rule %d (line %d):\n",
             yyrule - 1, yylno);
  /* The symbols being reduced.  */
  for (yyi = 0; yyi < yynrhs; yyi++)
    {
      YYFPRINTF (stderr, "   $%d = ", yyi + 1);
      yy_symbol_print (stderr,
                       YY_ACCESSING_SYMBOL (+yyssp[yyi + 1 - yynrhs]),
                       &yyvsp[(yyi + 1) - (yynrhs)], cmd, query, scanner);
      YYFPRINTF (stderr, "\n");
    }
}

# define YY_REDUCE_PRINT(Rule)          \
do {                                    \
  if (yydebug)                          \
    yy_reduce_print (yyssp, yyvsp, Rule, cmd, query, scanner); \
} while (0)

/* Nonzero means print parse trace.  It is left uninitialized so that
   multiple parsers can coexist.  */
int yydebug;
#else /* !YYDEBUG */
# define YYDPRINTF(Args) ((void) 0)
# define YY_SYMBOL_PRINT(Title, Kind, Value, Location)
# define YY_STACK_PRINT(Bottom, Top)
# define YY_REDUCE_PRINT(Rule)
#endif /* !YYDEBUG */


/* YYINITDEPTH -- initial size of the parser's stacks.  */
#ifndef YYINITDEPTH
# define YYINITDEPTH 200
#endif

/* YYMAXDEPTH -- maximum size the stacks can grow to (effective only
   if the built-in stack extension method is used).

   Do not make this value too large; the results are undefined if
   YYSTACK_ALLOC_MAXIMUM < YYSTACK_BYTES (YYMAXDEPTH)
   evaluated with infinite-precision integer arithmetic.  */

#ifndef YYMAXDEPTH
# define YYMAXDEPTH 10000
#endif


/* Context of a parse error.  */
typedef struct
{
  yy_state_t *yyssp;
  yysymbol_kind_t yytoken;
} yypcontext_t;

/* Put in YYARG at most YYARGN of the expected tokens given the
   current YYCTX, and return the number of tokens stored in YYARG.  If
   YYARG is null, return the number of expected tokens (guaranteed to
   be less than YYNTOKENS).  Return YYENOMEM on memory exhaustion.
   Return 0 if there are more than YYARGN expected tokens, yet fill
   YYARG up to YYARGN. */
static int
yypcontext_expected_tokens (const yypcontext_t *yyctx,
                            yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  int yyn = yypact[+*yyctx->yyssp];
  if (!yypact_value_is_default (yyn))
    {
      /* Start YYX at -YYN if negative to avoid negative indexes in
         YYCHECK.  In other words, skip the first -YYN actions for
         this state because they are default actions.  */
      int yyxbegin = yyn < 0 ? -yyn : 0;
      /* Stay within bounds of both yycheck and yytname.  */
      int yychecklim = YYLAST - yyn + 1;
      int yyxend = yychecklim < YYNTOKENS ? yychecklim : YYNTOKENS;
      int yyx;
      for (yyx = yyxbegin; yyx < yyxend; ++yyx)
        if (yycheck[yyx + yyn] == yyx && yyx != YYSYMBOL_YYerror
            && !yytable_value_is_error (yytable[yyx + yyn]))
          {
            if (!yyarg)
              ++yycount;
            else if (yycount == yyargn)
              return 0;
            else
              yyarg[yycount++] = YY_CAST (yysymbol_kind_t, yyx);
          }
    }
  if (yyarg && yycount == 0 && 0 < yyargn)
    yyarg[0] = YYSYMBOL_YYEMPTY;
  return yycount;
}




#ifndef yystrlen
# if defined __GLIBC__ && defined _STRING_H
#  define yystrlen(S) (YY_CAST (YYPTRDIFF_T, strlen (S)))
# else
/* Return the length of YYSTR.  */
static YYPTRDIFF_T
yystrlen (const char *yystr)
{
  YYPTRDIFF_T yylen;
  for (yylen = 0; yystr[yylen]; yylen++)
    continue;
  return yylen;
}
# endif
#endif

#ifndef yystpcpy
# if defined __GLIBC__ && defined _STRING_H && defined _GNU_SOURCE
#  define yystpcpy stpcpy
# else
/* Copy YYSRC to YYDEST, returning the address of the terminating '\0' in
   YYDEST.  */
static char *
yystpcpy (char *yydest, const char *yysrc)
{
  char *yyd = yydest;
  const char *yys = yysrc;

  while ((*yyd++ = *yys++) != '\0')
    continue;

  return yyd - 1;
}
# endif
#endif

#ifndef yytnamerr
/* Copy to YYRES the contents of YYSTR after stripping away unnecessary
   quotes and backslashes, so that it's suitable for yyerror.  The
   heuristic is that double-quoting is unnecessary unless the string
   contains an apostrophe, a comma, or backslash (other than
   backslash-backslash).  YYSTR is taken from yytname.  If YYRES is
   null, do not copy; instead, return the length of what the result
   would have been.  */
static YYPTRDIFF_T
yytnamerr (char *yyres, const char *yystr)
{
  if (*yystr == '"')
    {
      YYPTRDIFF_T yyn = 0;
      char const *yyp = yystr;
      for (;;)
        switch (*++yyp)
          {
          case '\'':
          case ',':
            goto do_not_strip_quotes;

          case '\\':
            if (*++yyp != '\\')
              goto do_not_strip_quotes;
            else
              goto append;

          append:
          default:
            if (yyres)
              yyres[yyn] = *yyp;
            yyn++;
            break;

          case '"':
            if (yyres)
              yyres[yyn] = '\0';
            return yyn;
          }
    do_not_strip_quotes: ;
    }

  if (yyres)
    return yystpcpy (yyres, yystr) - yyres;
  else
    return yystrlen (yystr);
}
#endif


static int
yy_syntax_error_arguments (const yypcontext_t *yyctx,
                           yysymbol_kind_t yyarg[], int yyargn)
{
  /* Actual size of YYARG. */
  int yycount = 0;
  /* There are many possibilities here to consider:
     - If this state is a consistent state with a default action, then
       the only way this function was invoked is if the default action
       is an error action.  In that case, don't check for expected
       tokens because there are none.
     - The only way there can be no lookahead present (in yychar) is if
       this state is a consistent state with a default action.  Thus,
       detecting the absence of a lookahead is sufficient to determine
       that there is no unexpected or expected token to report.  In that
       case, just report a simple "syntax error".
     - Don't assume there isn't a lookahead just because this state is a
       consistent state with a default action.  There might have been a
       previous inconsistent state, consistent state with a non-default
       action, or user semantic action that manipulated yychar.
     - Of course, the expected token list depends on states to have
       correct lookahead information, and it depends on the parser not
       to perform extra reductions after fetching a lookahead from the
       scanner and before detecting a syntax error.  Thus, state merging
       (from LALR or IELR) and default reductions corrupt the expected
       token list.  However, the list is correct for canonical LR with
       one exception: it will still contain any token that will not be
       accepted due to an error action in a later state.
  */
  if (yyctx->yytoken != YYSYMBOL_YYEMPTY)
    {
      int yyn;
      if (yyarg)
        yyarg[yycount] = yyctx->yytoken;
      ++yycount;
      yyn = yypcontext_expected_tokens (yyctx,
                                        yyarg ? yyarg + 1 : yyarg, yyargn - 1);
      if (yyn == YYENOMEM)
        return YYENOMEM;
      else
        yycount += yyn;
    }
  return yycount;
}

/* Copy into *YYMSG, which is of size *YYMSG_ALLOC, an error message
   about the unexpected token YYTOKEN for the state stack whose top is
   YYSSP.

   Return 0 if *YYMSG was successfully written.  Return -1 if *YYMSG is
   not large enough to hold the message.  In that case, also set
   *YYMSG_ALLOC to the required number of bytes.  Return YYENOMEM if the
   required number of bytes is too large to store.  */
static int
yysyntax_error (YYPTRDIFF_T *yymsg_alloc, char **yymsg,
                const yypcontext_t *yyctx)
{
  enum { YYARGS_MAX = 5 };
  /* Internationalized format string. */
  const char *yyformat = YY_NULLPTR;
  /* Arguments of yyformat: reported tokens (one for the "unexpected",
     one per "expected"). */
  yysymbol_kind_t yyarg[YYARGS_MAX];
  /* Cumulated lengths of YYARG.  */
  YYPTRDIFF_T yysize = 0;

  /* Actual size of YYARG. */
  int yycount = yy_syntax_error_arguments (yyctx, yyarg, YYARGS_MAX);
  if (yycount == YYENOMEM)
    return YYENOMEM;

  switch (yycount)
    {
#define YYCASE_(N, S)                       \
      case N:                               \
        yyformat = S;                       \
        break
    default: /* Avoid compiler warnings. */
      YYCASE_(0, YY_("syntax error"));
      YYCASE_(1, YY_("syntax error, unexpected %s"));
      YYCASE_(2, YY_("syntax error, unexpected %s, expecting %s"));
      YYCASE_(3, YY_("syntax error, unexpected %s, expecting %s or %s"));
      YYCASE_(4, YY_("syntax error, unexpected %s, expecting %s or %s or %s"));
      YYCASE_(5, YY_("syntax error, unexpected %s, expecting %s or %s or %s or %s"));
#undef YYCASE_
    }

  /* Compute error message size.  Don't count the "%s"s, but reserve
     room for the terminator.  */
  yysize = yystrlen (yyformat) - 2 * yycount + 1;
  {
    int yyi;
    for (yyi = 0; yyi < yycount; ++yyi)
      {
        YYPTRDIFF_T yysize1
          = yysize + yytnamerr (YY_NULLPTR, yytname[yyarg[yyi]]);
        if (yysize <= yysize1 && yysize1 <= YYSTACK_ALLOC_MAXIMUM)
          yysize = yysize1;
        else
          return YYENOMEM;
      }
  }

  if (*yymsg_alloc < yysize)
    {
      *yymsg_alloc = 2 * yysize;
      if (! (yysize <= *yymsg_alloc
             && *yymsg_alloc <= YYSTACK_ALLOC_MAXIMUM))
        *yymsg_alloc = YYSTACK_ALLOC_MAXIMUM;
      return -1;
    }

  /* Avoid sprintf, as that infringes on the user's name space.
     Don't have undefined behavior even if the translation
     produced a string with the wrong number of "%s"s.  */
  {
    char *yyp = *yymsg;
    int yyi = 0;
    while ((*yyp = *yyformat) != '\0')
      if (*yyp == '%' && yyformat[1] == 's' && yyi < yycount)
        {
          yyp += yytnamerr (yyp, yytname[yyarg[yyi++]]);
          yyformat += 2;
        }
      else
        {
          ++yyp;
          ++yyformat;
        }
  }
  return 0;
}


/*-----------------------------------------------.
| Release the memory associated to this symbol.  |
`-----------------------------------------------*/

static void
yydestruct (const char *yymsg,
            yysymbol_kind_t yykind, YYSTYPE *yyvaluep, struct flb_sp_cmd *cmd, const char *query, void *scanner)
{
  YY_USE (yyvaluep);
  YY_USE (cmd);
  YY_USE (query);
  YY_USE (scanner);
  if (!yymsg)
    yymsg = "Deleting";
  YY_SYMBOL_PRINT (yymsg, yykind, yyvaluep, yylocationp);

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  switch (yykind)
    {
    case YYSYMBOL_IDENTIFIER: /* IDENTIFIER  */
#line 102 "sql.y"
            { flb_free (((*yyvaluep).string)); }
#line 1320 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
        break;

      default:
        break;
    }
  YY_IGNORE_MAYBE_UNINITIALIZED_END
}






/*----------.
| yyparse.  |
`----------*/

int
yyparse (struct flb_sp_cmd *cmd, const char *query, void *scanner)
{
/* Lookahead token kind.  */
int yychar;


/* The semantic value of the lookahead symbol.  */
/* Default value used for initialization, for pacifying older GCCs
   or non-GCC compilers.  */
YY_INITIAL_VALUE (static YYSTYPE yyval_default;)
YYSTYPE yylval YY_INITIAL_VALUE (= yyval_default);

    /* Number of syntax errors so far.  */
    int yynerrs = 0;

    yy_state_fast_t yystate = 0;
    /* Number of tokens to shift before error messages enabled.  */
    int yyerrstatus = 0;

    /* Refer to the stacks through separate pointers, to allow yyoverflow
       to reallocate them elsewhere.  */

    /* Their size.  */
    YYPTRDIFF_T yystacksize = YYINITDEPTH;

    /* The state stack: array, bottom, top.  */
    yy_state_t yyssa[YYINITDEPTH];
    yy_state_t *yyss = yyssa;
    yy_state_t *yyssp = yyss;

    /* The semantic value stack: array, bottom, top.  */
    YYSTYPE yyvsa[YYINITDEPTH];
    YYSTYPE *yyvs = yyvsa;
    YYSTYPE *yyvsp = yyvs;

  int yyn;
  /* The return value of yyparse.  */
  int yyresult;
  /* Lookahead symbol kind.  */
  yysymbol_kind_t yytoken = YYSYMBOL_YYEMPTY;
  /* The variables used to return semantic value and location from the
     action routines.  */
  YYSTYPE yyval;

  /* Buffer for error messages, and its allocated size.  */
  char yymsgbuf[128];
  char *yymsg = yymsgbuf;
  YYPTRDIFF_T yymsg_alloc = sizeof yymsgbuf;

#define YYPOPSTACK(N)   (yyvsp -= (N), yyssp -= (N))

  /* The number of symbols on the RHS of the reduced rule.
     Keep to zero when no symbol should be popped.  */
  int yylen = 0;

  YYDPRINTF ((stderr, "Starting parse\n"));

  yychar = YYEMPTY; /* Cause a token to be read.  */

  goto yysetstate;


/*------------------------------------------------------------.
| yynewstate -- push a new state, which is found in yystate.  |
`------------------------------------------------------------*/
yynewstate:
  /* In all cases, when you get here, the value and location stacks
     have just been pushed.  So pushing a state here evens the stacks.  */
  yyssp++;


/*--------------------------------------------------------------------.
| yysetstate -- set current state (the top of the stack) to yystate.  |
`--------------------------------------------------------------------*/
yysetstate:
  YYDPRINTF ((stderr, "Entering state %d\n", yystate));
  YY_ASSERT (0 <= yystate && yystate < YYNSTATES);
  YY_IGNORE_USELESS_CAST_BEGIN
  *yyssp = YY_CAST (yy_state_t, yystate);
  YY_IGNORE_USELESS_CAST_END
  YY_STACK_PRINT (yyss, yyssp);

  if (yyss + yystacksize - 1 <= yyssp)
#if !defined yyoverflow && !defined YYSTACK_RELOCATE
    YYNOMEM;
#else
    {
      /* Get the current used size of the three stacks, in elements.  */
      YYPTRDIFF_T yysize = yyssp - yyss + 1;

# if defined yyoverflow
      {
        /* Give user a chance to reallocate the stack.  Use copies of
           these so that the &'s don't force the real ones into
           memory.  */
        yy_state_t *yyss1 = yyss;
        YYSTYPE *yyvs1 = yyvs;

        /* Each stack pointer address is followed by the size of the
           data in use in that stack, in bytes.  This used to be a
           conditional around just the two extra args, but that might
           be undefined if yyoverflow is a macro.  */
        yyoverflow (YY_("memory exhausted"),
                    &yyss1, yysize * YYSIZEOF (*yyssp),
                    &yyvs1, yysize * YYSIZEOF (*yyvsp),
                    &yystacksize);
        yyss = yyss1;
        yyvs = yyvs1;
      }
# else /* defined YYSTACK_RELOCATE */
      /* Extend the stack our own way.  */
      if (YYMAXDEPTH <= yystacksize)
        YYNOMEM;
      yystacksize *= 2;
      if (YYMAXDEPTH < yystacksize)
        yystacksize = YYMAXDEPTH;

      {
        yy_state_t *yyss1 = yyss;
        union yyalloc *yyptr =
          YY_CAST (union yyalloc *,
                   YYSTACK_ALLOC (YY_CAST (YYSIZE_T, YYSTACK_BYTES (yystacksize))));
        if (! yyptr)
          YYNOMEM;
        YYSTACK_RELOCATE (yyss_alloc, yyss);
        YYSTACK_RELOCATE (yyvs_alloc, yyvs);
#  undef YYSTACK_RELOCATE
        if (yyss1 != yyssa)
          YYSTACK_FREE (yyss1);
      }
# endif

      yyssp = yyss + yysize - 1;
      yyvsp = yyvs + yysize - 1;

      YY_IGNORE_USELESS_CAST_BEGIN
      YYDPRINTF ((stderr, "Stack size increased to %ld\n",
                  YY_CAST (long, yystacksize)));
      YY_IGNORE_USELESS_CAST_END

      if (yyss + yystacksize - 1 <= yyssp)
        YYABORT;
    }
#endif /* !defined yyoverflow && !defined YYSTACK_RELOCATE */


  if (yystate == YYFINAL)
    YYACCEPT;

  goto yybackup;


/*-----------.
| yybackup.  |
`-----------*/
yybackup:
  /* Do appropriate processing given the current state.  Read a
     lookahead token if we need one and don't already have one.  */

  /* First try to decide what to do without reference to lookahead token.  */
  yyn = yypact[yystate];
  if (yypact_value_is_default (yyn))
    goto yydefault;

  /* Not known => get a lookahead token if don't already have one.  */

  /* YYCHAR is either empty, or end-of-input, or a valid lookahead.  */
  if (yychar == YYEMPTY)
    {
      YYDPRINTF ((stderr, "Reading a token\n"));
      yychar = yylex (&yylval, scanner);
    }

  if (yychar <= YYEOF)
    {
      yychar = YYEOF;
      yytoken = YYSYMBOL_YYEOF;
      YYDPRINTF ((stderr, "Now at end of input.\n"));
    }
  else if (yychar == YYerror)
    {
      /* The scanner already issued an error message, process directly
         to error recovery.  But do not keep the error token as
         lookahead, it is too special and may lead us to an endless
         loop in error recovery. */
      yychar = YYUNDEF;
      yytoken = YYSYMBOL_YYerror;
      goto yyerrlab1;
    }
  else
    {
      yytoken = YYTRANSLATE (yychar);
      YY_SYMBOL_PRINT ("Next token is", yytoken, &yylval, &yylloc);
    }

  /* If the proper action on seeing token YYTOKEN is to reduce or to
     detect an error, take that action.  */
  yyn += yytoken;
  if (yyn < 0 || YYLAST < yyn || yycheck[yyn] != yytoken)
    goto yydefault;
  yyn = yytable[yyn];
  if (yyn <= 0)
    {
      if (yytable_value_is_error (yyn))
        goto yyerrlab;
      yyn = -yyn;
      goto yyreduce;
    }

  /* Count tokens shifted since error; after three, turn off error
     status.  */
  if (yyerrstatus)
    yyerrstatus--;

  /* Shift the lookahead token.  */
  YY_SYMBOL_PRINT ("Shifting", yytoken, &yylval, &yylloc);
  yystate = yyn;
  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END

  /* Discard the shifted token.  */
  yychar = YYEMPTY;
  goto yynewstate;


/*-----------------------------------------------------------.
| yydefault -- do the default action for the current state.  |
`-----------------------------------------------------------*/
yydefault:
  yyn = yydefact[yystate];
  if (yyn == 0)
    goto yyerrlab;
  goto yyreduce;


/*-----------------------------.
| yyreduce -- do a reduction.  |
`-----------------------------*/
yyreduce:
  /* yyn is the number of a rule to reduce with.  */
  yylen = yyr2[yyn];

  /* If YYLEN is nonzero, implement the default value of the action:
     '$$ = $1'.

     Otherwise, the following line sets YYVAL to garbage.
     This behavior is undocumented and Bison
     users should not rely upon it.  Assigning to YYVAL
     unconditionally makes the parser a bit smaller, and it avoids a
     GCC warning that YYVAL may be used uninitialized.  */
  yyval = yyvsp[1-yylen];


  YY_REDUCE_PRINT (yyn);
  switch (yyn)
    {
  case 4: /* create: CREATE STREAM IDENTIFIER AS select  */
#line 111 "sql.y"
      {
        flb_sp_cmd_stream_new(cmd, (yyvsp[-2].string));
        flb_free((yyvsp[-2].string));
      }
#line 1602 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 5: /* create: CREATE STREAM IDENTIFIER WITH '(' properties ')' AS select  */
#line 117 "sql.y"
      {
        flb_sp_cmd_stream_new(cmd, (yyvsp[-6].string));
        flb_free((yyvsp[-6].string));
      }
#line 1611 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 6: /* create: CREATE SNAPSHOT IDENTIFIER AS SELECT '*' FROM source limit ';'  */
#line 123 "sql.y"
      {
        flb_sp_cmd_snapshot_new(cmd, (yyvsp[-7].string));
        flb_free((yyvsp[-7].string));
      }
#line 1620 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 7: /* create: CREATE SNAPSHOT IDENTIFIER WITH '(' properties ')' AS SELECT '*' FROM source limit ';'  */
#line 129 "sql.y"
      {
        flb_sp_cmd_snapshot_new(cmd, (yyvsp[-11].string));
        flb_free((yyvsp[-11].string));
      }
#line 1629 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 8: /* create: FLUSH SNAPSHOT IDENTIFIER AS SELECT '*' FROM source where ';'  */
#line 135 "sql.y"
      {
        flb_sp_cmd_snapshot_flush_new(cmd, (yyvsp[-7].string));
        flb_free((yyvsp[-7].string));
      }
#line 1638 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 9: /* create: FLUSH SNAPSHOT IDENTIFIER WITH '(' properties ')' AS SELECT '*' FROM source where ';'  */
#line 141 "sql.y"
      {
        flb_sp_cmd_snapshot_flush_new(cmd, (yyvsp[-11].string));
        flb_free((yyvsp[-11].string));
      }
#line 1647 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 12: /* property: prop_key '=' prop_val  */
#line 149 "sql.y"
                  {
                    flb_sp_cmd_stream_prop_add(cmd, (yyvsp[-2].string), (yyvsp[0].string));
                    flb_free((yyvsp[-2].string));
                    flb_free((yyvsp[0].string));
                  }
#line 1657 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 15: /* select: SELECT keys FROM source window where groupby limit ';'  */
#line 159 "sql.y"
      {
        cmd->type = FLB_SP_SELECT;
      }
#line 1665 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 19: /* record_key: '*'  */
#line 167 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, -1, NULL);
                  }
#line 1673 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 20: /* record_key: IDENTIFIER key_alias  */
#line 172 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, -1, (yyvsp[-1].string));
                    flb_free((yyvsp[-1].string));
                  }
#line 1682 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 21: /* record_key: IDENTIFIER record_subkey key_alias  */
#line 178 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, -1, (yyvsp[-2].string));
                    flb_free((yyvsp[-2].string));
                  }
#line 1691 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 22: /* record_key: COUNT '(' '*' ')' key_alias  */
#line 184 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-4].integer), NULL);
                  }
#line 1699 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 23: /* record_key: COUNT '(' IDENTIFIER ')' key_alias  */
#line 189 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-4].integer), (yyvsp[-2].string));
                    flb_free((yyvsp[-2].string));
                  }
#line 1708 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 24: /* record_key: COUNT '(' IDENTIFIER record_subkey ')' key_alias  */
#line 195 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-5].integer), (yyvsp[-3].string));
                    flb_free((yyvsp[-3].string));
                  }
#line 1717 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 25: /* record_key: aggregate_func '(' IDENTIFIER ')' key_alias  */
#line 201 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-4].integer), (yyvsp[-2].string));
                    flb_free((yyvsp[-2].string));
                  }
#line 1726 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 26: /* record_key: aggregate_func '(' IDENTIFIER record_subkey ')' key_alias  */
#line 207 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-5].integer), (yyvsp[-3].string));
                    flb_free((yyvsp[-3].string));
                  }
#line 1735 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 27: /* record_key: TIMESERIES_FORECAST '(' IDENTIFIER ',' INTEGER ')' key_alias  */
#line 213 "sql.y"
                  {
                    flb_sp_cmd_timeseries_forecast(cmd, (yyvsp[-6].integer), (yyvsp[-4].string), (yyvsp[-2].integer));
                    flb_free((yyvsp[-4].string));
                  }
#line 1744 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 28: /* record_key: time_record_func '(' ')' key_alias  */
#line 219 "sql.y"
                  {
                    flb_sp_cmd_key_add(cmd, (yyvsp[-3].integer), NULL);
                  }
#line 1752 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 38: /* key_alias: AS IDENTIFIER  */
#line 230 "sql.y"
             {
                 flb_sp_cmd_alias_add(cmd, (yyvsp[0].string));
             }
#line 1760 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 39: /* record_subkey: '[' STRING ']'  */
#line 234 "sql.y"
             {
               flb_slist_add(cmd->tmp_subkeys, (yyvsp[-1].string));
               flb_free((yyvsp[-1].string));
             }
#line 1769 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 41: /* source: FROM_STREAM IDENTIFIER  */
#line 241 "sql.y"
              {
                flb_sp_cmd_source(cmd, FLB_SP_STREAM, (yyvsp[0].string));
                flb_free((yyvsp[0].string));
              }
#line 1778 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 42: /* source: FROM_TAG STRING  */
#line 247 "sql.y"
              {
                flb_sp_cmd_source(cmd, FLB_SP_TAG, (yyvsp[0].string));
                flb_free((yyvsp[0].string));
              }
#line 1787 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 46: /* where: WHERE condition  */
#line 257 "sql.y"
             {
               flb_sp_cmd_condition_add(cmd, (yyvsp[0].expression));
             }
#line 1795 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 50: /* limit: LIMIT INTEGER  */
#line 266 "sql.y"
             {
                 flb_sp_cmd_limit_add(cmd, (yyvsp[0].integer));
             }
#line 1803 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 51: /* window_spec: TUMBLING '(' INTEGER time ')'  */
#line 271 "sql.y"
              {
                flb_sp_cmd_window(cmd, FLB_SP_WINDOW_TUMBLING, (yyvsp[-2].integer), (yyvsp[-1].integer), 0, 0);
              }
#line 1811 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 52: /* window_spec: HOPPING '(' INTEGER time ',' ADVANCE_BY INTEGER time ')'  */
#line 276 "sql.y"
              {
                flb_sp_cmd_window(cmd, FLB_SP_WINDOW_HOPPING, (yyvsp[-6].integer), (yyvsp[-5].integer), (yyvsp[-2].integer), (yyvsp[-1].integer));
              }
#line 1819 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 54: /* condition: key  */
#line 282 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, (yyvsp[0].expression), NULL, FLB_EXP_OR);
                 }
#line 1827 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 55: /* condition: value  */
#line 287 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, NULL, (yyvsp[0].expression), FLB_EXP_OR);
                 }
#line 1835 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 56: /* condition: '(' condition ')'  */
#line 292 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, (yyvsp[-1].expression), NULL, FLB_EXP_PAR);
                 }
#line 1843 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 57: /* condition: NOT condition  */
#line 297 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, (yyvsp[0].expression), NULL, FLB_EXP_NOT);
                 }
#line 1851 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 58: /* condition: condition AND condition  */
#line 302 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_AND);
                 }
#line 1859 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 59: /* condition: condition OR condition  */
#line 307 "sql.y"
                 {
                   (yyval.expression) = flb_sp_cmd_operation(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_OR);
                 }
#line 1867 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 60: /* comparison: key IS null  */
#line 312 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_EQ);
                  }
#line 1875 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 61: /* comparison: key IS NOT null  */
#line 317 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_operation(cmd,
                             flb_sp_cmd_comparison(cmd, (yyvsp[-3].expression), (yyvsp[0].expression), FLB_EXP_EQ),
                             NULL, FLB_EXP_NOT);
                  }
#line 1885 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 62: /* comparison: record_func  */
#line 324 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd,
                             (yyvsp[0].expression),
                             flb_sp_cmd_condition_boolean(cmd, true),
                             FLB_EXP_EQ);
                  }
#line 1896 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 63: /* comparison: record_func '=' value  */
#line 332 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_EQ);
                  }
#line 1904 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 64: /* comparison: record_func NEQ value  */
#line 337 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_operation(cmd,
                             flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_EQ),
                                 NULL, FLB_EXP_NOT)
                    ;
                  }
#line 1915 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 65: /* comparison: record_func LT value  */
#line 345 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_LT);
                  }
#line 1923 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 66: /* comparison: record_func LTE value  */
#line 350 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_LTE);
                  }
#line 1931 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 67: /* comparison: record_func GT value  */
#line 355 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_GT);
                  }
#line 1939 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 68: /* comparison: record_func GTE value  */
#line 360 "sql.y"
                  {
                    (yyval.expression) = flb_sp_cmd_comparison(cmd, (yyvsp[-2].expression), (yyvsp[0].expression), FLB_EXP_GTE);
                  }
#line 1947 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 70: /* record_func: RECORD '.' CONTAINS '(' key ')'  */
#line 366 "sql.y"
                     {
                       (yyval.expression) = flb_sp_record_function_add(cmd, "contains", (yyvsp[-1].expression));
                     }
#line 1955 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 71: /* record_func: RECORD '.' TIME '(' ')'  */
#line 371 "sql.y"
                     {
                       (yyval.expression) = flb_sp_record_function_add(cmd, "time", NULL);
                     }
#line 1963 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 72: /* key: IDENTIFIER  */
#line 375 "sql.y"
                   {
                     (yyval.expression) = flb_sp_cmd_condition_key(cmd, (yyvsp[0].string));
                     flb_free((yyvsp[0].string));
                   }
#line 1972 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 73: /* key: IDENTIFIER record_subkey  */
#line 381 "sql.y"
                   {
                     (yyval.expression) = flb_sp_cmd_condition_key(cmd, (yyvsp[-1].string));
                     flb_free((yyvsp[-1].string));
                   }
#line 1981 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 74: /* value: INTEGER  */
#line 386 "sql.y"
               {
                 (yyval.expression) = flb_sp_cmd_condition_integer(cmd, (yyvsp[0].integer));
               }
#line 1989 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 75: /* value: FLOATING  */
#line 391 "sql.y"
               {
                 (yyval.expression) = flb_sp_cmd_condition_float(cmd, (yyvsp[0].fval));
               }
#line 1997 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 76: /* value: STRING  */
#line 396 "sql.y"
               {
                 (yyval.expression) = flb_sp_cmd_condition_string(cmd, (yyvsp[0].string));
                 flb_free((yyvsp[0].string));
               }
#line 2006 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 77: /* value: BOOLTYPE  */
#line 402 "sql.y"
               {
                 (yyval.expression) = flb_sp_cmd_condition_boolean(cmd, (yyvsp[0].boolean));
               }
#line 2014 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 78: /* null: NUL  */
#line 406 "sql.y"
              {
                 (yyval.expression) = flb_sp_cmd_condition_null(cmd);
              }
#line 2022 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 79: /* time: SECOND  */
#line 410 "sql.y"
              {
                (yyval.integer) = FLB_SP_TIME_SECOND;
              }
#line 2030 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 80: /* time: MINUTE  */
#line 415 "sql.y"
              {
                (yyval.integer) = FLB_SP_TIME_MINUTE;
              }
#line 2038 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 81: /* time: HOUR  */
#line 420 "sql.y"
              {
                (yyval.integer) = FLB_SP_TIME_HOUR;
              }
#line 2046 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 84: /* gb_key: IDENTIFIER  */
#line 427 "sql.y"
                {
                  flb_sp_cmd_gb_key_add(cmd, (yyvsp[0].string));
                  flb_free((yyvsp[0].string));
                }
#line 2055 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;

  case 85: /* gb_key: IDENTIFIER record_subkey  */
#line 433 "sql.y"
                {
                  flb_sp_cmd_gb_key_add(cmd, (yyvsp[-1].string));
                  flb_free((yyvsp[-1].string));
                }
#line 2064 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"
    break;


#line 2068 "/Users/adheipsingh/parseable/fluent-bit/plugins/src/stream_processor/parser/sql_parser.c"

      default: break;
    }
  /* User semantic actions sometimes alter yychar, and that requires
     that yytoken be updated with the new translation.  We take the
     approach of translating immediately before every use of yytoken.
     One alternative is translating here after every semantic action,
     but that translation would be missed if the semantic action invokes
     YYABORT, YYACCEPT, or YYERROR immediately after altering yychar or
     if it invokes YYBACKUP.  In the case of YYABORT or YYACCEPT, an
     incorrect destructor might then be invoked immediately.  In the
     case of YYERROR or YYBACKUP, subsequent parser actions might lead
     to an incorrect destructor call or verbose syntax error message
     before the lookahead is translated.  */
  YY_SYMBOL_PRINT ("-> $$ =", YY_CAST (yysymbol_kind_t, yyr1[yyn]), &yyval, &yyloc);

  YYPOPSTACK (yylen);
  yylen = 0;

  *++yyvsp = yyval;

  /* Now 'shift' the result of the reduction.  Determine what state
     that goes to, based on the state we popped back to and the rule
     number reduced by.  */
  {
    const int yylhs = yyr1[yyn] - YYNTOKENS;
    const int yyi = yypgoto[yylhs] + *yyssp;
    yystate = (0 <= yyi && yyi <= YYLAST && yycheck[yyi] == *yyssp
               ? yytable[yyi]
               : yydefgoto[yylhs]);
  }

  goto yynewstate;


/*--------------------------------------.
| yyerrlab -- here on detecting error.  |
`--------------------------------------*/
yyerrlab:
  /* Make sure we have latest lookahead translation.  See comments at
     user semantic actions for why this is necessary.  */
  yytoken = yychar == YYEMPTY ? YYSYMBOL_YYEMPTY : YYTRANSLATE (yychar);
  /* If not already recovering from an error, report this error.  */
  if (!yyerrstatus)
    {
      ++yynerrs;
      {
        yypcontext_t yyctx
          = {yyssp, yytoken};
        char const *yymsgp = YY_("syntax error");
        int yysyntax_error_status;
        yysyntax_error_status = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
        if (yysyntax_error_status == 0)
          yymsgp = yymsg;
        else if (yysyntax_error_status == -1)
          {
            if (yymsg != yymsgbuf)
              YYSTACK_FREE (yymsg);
            yymsg = YY_CAST (char *,
                             YYSTACK_ALLOC (YY_CAST (YYSIZE_T, yymsg_alloc)));
            if (yymsg)
              {
                yysyntax_error_status
                  = yysyntax_error (&yymsg_alloc, &yymsg, &yyctx);
                yymsgp = yymsg;
              }
            else
              {
                yymsg = yymsgbuf;
                yymsg_alloc = sizeof yymsgbuf;
                yysyntax_error_status = YYENOMEM;
              }
          }
        yyerror (cmd, query, scanner, yymsgp);
        if (yysyntax_error_status == YYENOMEM)
          YYNOMEM;
      }
    }

  if (yyerrstatus == 3)
    {
      /* If just tried and failed to reuse lookahead token after an
         error, discard it.  */

      if (yychar <= YYEOF)
        {
          /* Return failure if at end of input.  */
          if (yychar == YYEOF)
            YYABORT;
        }
      else
        {
          yydestruct ("Error: discarding",
                      yytoken, &yylval, cmd, query, scanner);
          yychar = YYEMPTY;
        }
    }

  /* Else will try to reuse lookahead token after shifting the error
     token.  */
  goto yyerrlab1;


/*---------------------------------------------------.
| yyerrorlab -- error raised explicitly by YYERROR.  |
`---------------------------------------------------*/
yyerrorlab:
  /* Pacify compilers when the user code never invokes YYERROR and the
     label yyerrorlab therefore never appears in user code.  */
  if (0)
    YYERROR;
  ++yynerrs;

  /* Do not reclaim the symbols of the rule whose action triggered
     this YYERROR.  */
  YYPOPSTACK (yylen);
  yylen = 0;
  YY_STACK_PRINT (yyss, yyssp);
  yystate = *yyssp;
  goto yyerrlab1;


/*-------------------------------------------------------------.
| yyerrlab1 -- common code for both syntax error and YYERROR.  |
`-------------------------------------------------------------*/
yyerrlab1:
  yyerrstatus = 3;      /* Each real token shifted decrements this.  */

  /* Pop stack until we find a state that shifts the error token.  */
  for (;;)
    {
      yyn = yypact[yystate];
      if (!yypact_value_is_default (yyn))
        {
          yyn += YYSYMBOL_YYerror;
          if (0 <= yyn && yyn <= YYLAST && yycheck[yyn] == YYSYMBOL_YYerror)
            {
              yyn = yytable[yyn];
              if (0 < yyn)
                break;
            }
        }

      /* Pop the current state because it cannot handle the error token.  */
      if (yyssp == yyss)
        YYABORT;


      yydestruct ("Error: popping",
                  YY_ACCESSING_SYMBOL (yystate), yyvsp, cmd, query, scanner);
      YYPOPSTACK (1);
      yystate = *yyssp;
      YY_STACK_PRINT (yyss, yyssp);
    }

  YY_IGNORE_MAYBE_UNINITIALIZED_BEGIN
  *++yyvsp = yylval;
  YY_IGNORE_MAYBE_UNINITIALIZED_END


  /* Shift the error token.  */
  YY_SYMBOL_PRINT ("Shifting", YY_ACCESSING_SYMBOL (yyn), yyvsp, yylsp);

  yystate = yyn;
  goto yynewstate;


/*-------------------------------------.
| yyacceptlab -- YYACCEPT comes here.  |
`-------------------------------------*/
yyacceptlab:
  yyresult = 0;
  goto yyreturnlab;


/*-----------------------------------.
| yyabortlab -- YYABORT comes here.  |
`-----------------------------------*/
yyabortlab:
  yyresult = 1;
  goto yyreturnlab;


/*-----------------------------------------------------------.
| yyexhaustedlab -- YYNOMEM (memory exhaustion) comes here.  |
`-----------------------------------------------------------*/
yyexhaustedlab:
  yyerror (cmd, query, scanner, YY_("memory exhausted"));
  yyresult = 2;
  goto yyreturnlab;


/*----------------------------------------------------------.
| yyreturnlab -- parsing is finished, clean up and return.  |
`----------------------------------------------------------*/
yyreturnlab:
  if (yychar != YYEMPTY)
    {
      /* Make sure we have latest lookahead translation.  See comments at
         user semantic actions for why this is necessary.  */
      yytoken = YYTRANSLATE (yychar);
      yydestruct ("Cleanup: discarding lookahead",
                  yytoken, &yylval, cmd, query, scanner);
    }
  /* Do not reclaim the symbols of the rule whose action triggered
     this YYABORT or YYACCEPT.  */
  YYPOPSTACK (yylen);
  YY_STACK_PRINT (yyss, yyssp);
  while (yyssp != yyss)
    {
      yydestruct ("Cleanup: popping",
                  YY_ACCESSING_SYMBOL (+*yyssp), yyvsp, cmd, query, scanner);
      YYPOPSTACK (1);
    }
#ifndef yyoverflow
  if (yyss != yyssa)
    YYSTACK_FREE (yyss);
#endif
  if (yymsg != yymsgbuf)
    YYSTACK_FREE (yymsg);
  return yyresult;
}

