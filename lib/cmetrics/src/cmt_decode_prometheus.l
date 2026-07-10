%option prefix="cmt_decode_prometheus_"

%option reentrant bison-bridge
%option noyywrap nounput noinput
%option nodefault

%{

#include <cmetrics/cmt_decode_prometheus.h>
#include <stdio.h>

#define STRBUF_RET \
    yylval->str = context->strbuf; \
    context->strbuf = NULL

static void set_allocation_error(struct cmt_decode_prometheus_context *context)
{
    context->errcode = CMT_DECODE_PROMETHEUS_ALLOCATION_ERROR;

    if (context->opts.errbuf != NULL && context->opts.errbuf_size > 0) {
        snprintf(context->opts.errbuf,
                 context->opts.errbuf_size,
                 "memory allocation failed");
    }
}

static int reset_strbuf(struct cmt_decode_prometheus_context *context)
{
    if (context->strbuf != NULL) {
        cfl_sds_destroy(context->strbuf);
    }

    context->strbuf = cfl_sds_create_size(256);
    if (context->strbuf == NULL) {
        set_allocation_error(context);

        return -1;
    }

    return 0;
}

static int append_strbuf(struct cmt_decode_prometheus_context *context,
                         const char *text, int length)
{
    cfl_sds_t result;

    result = cfl_sds_cat(context->strbuf, text, length);
    if (result == NULL) {
        set_allocation_error(context);

        return -1;
    }

    context->strbuf = result;

    return 0;
}

#define STRBUF_CREATE() \
    do { \
        if (reset_strbuf(context) != 0) { \
            return 0; \
        } \
    } while (0)

#define STRBUF_APPEND(text, length) \
    do { \
        if (append_strbuf(context, (text), (length)) != 0) { \
            return 0; \
        } \
    } while (0)

#define SET_STR_TOKEN() \
    do { \
        yylval->str = cfl_sds_create(yytext); \
        if (yylval->str == NULL) { \
            set_allocation_error(context); \
            return 0; \
        } \
    } while (0)

%}

/* here we define some states that allow us to create rules only
   matched in certain situations */

%x INQUOTE HELPTAG INHELPTAG TYPETAG INTYPETAG COMMENT COMMENT_START

%%

%{
    if (context->opts.start_token) {
        int t = context->opts.start_token;
        context->opts.start_token = 0;
        return t;
    }
%}

<*>\r\n|\n {
    int top_state = YYSTATE;
    // We always return to the INITIAL state on a linefeed, no matter which
    // state we are on (the "<*>" means this rule is applied on every state)
    BEGIN(INITIAL);
    if (top_state == INHELPTAG) {
        // But if we were on the INHELPTAG state, we return everything collected
        // in strbuf
        STRBUF_RET;
        return METRIC_DOC;
    }
}

^[ ]*#[ ]* {
    // Lines with "#" as the first non-whitespace character begin a comment
    // unless the first token is either HELP or TYPE. To handle this ambiguity,
    // we enter the COMMENT_START state, which contains rules for selecting
    // if this is a HELP/TYPE tag or just a normal comment
    BEGIN(COMMENT_START);
}

<COMMENT_START>HELP[ \t]+ {
    // Begin a help tag
    BEGIN(HELPTAG);
}

<COMMENT_START>TYPE[ \t]+ {
    // Begin a type tag
    BEGIN(TYPETAG);
}

<COMMENT_START>[^\n] {
    // Any character that is not a newline begins the COMMENT state where
    // everything is ignored until the next linefeed. This works because flex
    // will prioritize the two rules above this one since they have longer
    // matches.
    BEGIN(COMMENT);
}

<COMMENT>[^\n]+ {
    // ignore
}

<HELPTAG,TYPETAG>[^ \t]+ {
    // The next token will be the metric name
    SET_STR_TOKEN();
    return YYSTATE == HELPTAG ? HELP : TYPE;
}

<HELPTAG,TYPETAG>[ \t]* {
    // Every whitespace after the metric name is ignored
    if (YYSTATE == HELPTAG) {
        // For HELPTAG we enter the INHELPTAG start condition which we will use to
        // read everything until the end of line into context->strbuf. We enter a
        // separate start condition for this to handle "\\" and "\n" escapes
        // more easily.
        BEGIN(INHELPTAG);
        STRBUF_CREATE();
    }
    else {
        // For TYPETAG we enter INTYPETAG start condition to check only valid
        // metric types are accepted. This prevents us from having to do
        // manual validation later.
        BEGIN(INTYPETAG);
    }
}

<INHELPTAG><<EOF>> {
    // Handle EOF when in the INHELPTAG state by returning the buffered docstring.
    // While this is not strictly necessary, it makes easier unit testing the
    // lexer
    BEGIN(INITIAL);
    STRBUF_RET;
    return METRIC_DOC;
}

<INHELPTAG>\\n {
    // Process linefeed escape sequence
    STRBUF_APPEND("\n", 1);
}

<INHELPTAG>\\\\ {
    // Process backslack escape sequence
    STRBUF_APPEND("\\", 1);
}

<INHELPTAG>[^\r\n\\]+ {
    // Put everything that is not a backslash or a line feed into strbuf
    STRBUF_APPEND(yytext, yyleng);
}

<INTYPETAG>counter {
    return COUNTER;
}

<INTYPETAG>gauge {
    return GAUGE;
}

<INTYPETAG>summary {
    return SUMMARY;
}

<INTYPETAG>untyped {
    return UNTYPED;
}

<INTYPETAG>histogram {
    return HISTOGRAM;
}

<INTYPETAG,INITIAL>[ \t]+ {
    /* ignore whitespace */
}

["] {
    BEGIN(INQUOTE);
    STRBUF_CREATE();
}

<INQUOTE>[\\]["] {
    STRBUF_APPEND("\"", 1);
}

<INQUOTE>\\n {
    STRBUF_APPEND("\n", 1);
}

<INQUOTE>\\\\ {
    STRBUF_APPEND("\\", 1);
}

<INQUOTE>[^\r\n\\"]+ {
    STRBUF_APPEND(yytext, yyleng);
}

<INQUOTE>["] {
    BEGIN(INITIAL);
    STRBUF_RET;
    return QUOTED;
}

[+-]?(?i:(INF|NAN)) {
    strncpy(yylval->numstr, yytext, sizeof(yylval->numstr) - 1);
    return INFNAN;
}

[a-zA-Z_][a-zA-Z_0-9]*  {
    SET_STR_TOKEN();
    return IDENTIFIER;
}

[0-9.eE+-]+ {
    strncpy(yylval->numstr, yytext, sizeof(yylval->numstr) - 1);
    return NUMSTR;
}

. {
    // Catch all workaround to avoid having to define token types for every
    // possible delimiter. We simply return the character to the parser.
    return *yytext;
}

%%
