/*
 *
 * Mini regex-module inspired by Rob Pike's regex code described in:
 *
 * http://www.cs.princeton.edu/courses/archive/spr09/cos333/beautiful.html
 *
 *
 *
 * Supports:
 * ---------
 *   '.'        Dot, matches any character
 *   '^'        Start anchor, matches beginning of string
 *   '$'        End anchor, matches end of string
 *   '*'        Asterisk, match zero or more (greedy)
 *   '+'        Plus, match one or more (greedy)
 *   '?'        Question, match zero or one (non-greedy)
 *   '[abc]'    Character class, match if one of {'a', 'b', 'c'}
 *   '[^abc]'   Inverted class, match if NOT one of {'a', 'b', 'c'} -- NOTE: feature is currently broken!
 *   '[a-zA-Z]' Character ranges, the character set of the ranges { a-z | A-Z }
 *   '\s'       Whitespace, \t \f \r \n \v and spaces
 *   '\S'       Non-whitespace
 *   '\w'       Alphanumeric, [a-zA-Z0-9_]
 *   '\W'       Non-alphanumeric
 *   '\d'       Digits, [0-9]
 *   '\D'       Non-digits
 *
 *
 */

#ifndef _TINY_REGEX_C
#define _TINY_REGEX_C


#ifndef RE_DOT_MATCHES_NEWLINE
/* Define to 0 if you DON'T want '.' to match '\r' + '\n' */
#define RE_DOT_MATCHES_NEWLINE 1
#endif

#ifdef __cplusplus
extern "C"{
#endif


/* Definitions: */

/* This was incremented because everything counts as a symbol, even literals and because
 * of that the longer regular expressions matched wrong input text because they were only
 * partially compiled
 */
#define MAX_REGEXP_OBJECTS      512    /* Max number of regex symbols in expression. */
#define MAX_CHAR_CLASS_LEN      40     /* Max length of character-class buffer in.   */


enum { UNUSED, DOT, BEGIN, END, QUESTIONMARK, STAR, PLUS, RE_CHAR, CHAR_CLASS, INV_CHAR_CLASS, DIGIT, NOT_DIGIT, ALPHA, NOT_ALPHA, WHITESPACE, NOT_WHITESPACE, /* BRANCH */ };

typedef struct regex_t
{
  unsigned char  type;   /* CHAR, STAR, etc.                      */
  union
  {
    unsigned char  ch;   /*      the character itself             */
    unsigned char* ccl;  /*  OR  a pointer to characters in class */
  } u;
} regex_t;

/* Typedef'd pointer to get abstract datatype. */
typedef struct regex_t* re_t;

#define REGEXP_SIZE (MAX_REGEXP_OBJECTS * sizeof(struct regex_t))

/* Compile regex string pattern to a regex_t-array. */
re_t re_compile(const char* pattern);


/* Find matches of the compiled pattern inside text. */
int re_matchp(re_t pattern, const char* text, int* matchlength);


/* Find matches of the txt pattern inside text (will compile automatically first). */
int re_match(const char* pattern, const char* text, int* matchlength);


#ifdef __cplusplus
}
#endif

#endif /* ifndef _TINY_REGEX_C */
