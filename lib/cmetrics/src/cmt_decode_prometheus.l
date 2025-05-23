%option prefix="cmt_decode_prometheus_"

%option reentrant bison-bridge
%option noyywrap nounput noinput
%option nodefault

%{

#include <cmetrics/cmt_decode_prometheus.h>

#define STRBUF_RET \
    yylval->str = context->strbuf; \
    context->strbuf = NULL

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
    yylval->str = cfl_sds_create(yytext);
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
        context->strbuf = cfl_sds_create_size(256);
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
    context->strbuf = cfl_sds_cat(context->strbuf, "\n", 1);
}

<INHELPTAG>\\\\ {
    // Process backslack escape sequence
    context->strbuf = cfl_sds_cat(context->strbuf, "\\", 1);
}

<INHELPTAG>[^\r\n\\]+ {
    // Put everything that is not a backslash or a line feed into strbuf
    context->strbuf = cfl_sds_cat(context->strbuf, yytext, yyleng);
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
    if (context->strbuf != NULL) {
        cfl_sds_destroy(context->strbuf);
    }
    context->strbuf = cfl_sds_create_size(256);
}

<INQUOTE>[\\]["] {
    context->strbuf = cfl_sds_cat(context->strbuf, "\"", 1);
}

<INQUOTE>\\n {
    context->strbuf = cfl_sds_cat(context->strbuf, "\n", 1);
}

<INQUOTE>\\\\ {
    context->strbuf = cfl_sds_cat(context->strbuf, "\\", 1);
}

<INQUOTE>[^\r\n\\"]+ {
    context->strbuf = cfl_sds_cat(context->strbuf, yytext, yyleng);
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
    yylval->str = cfl_sds_create(yytext);
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
