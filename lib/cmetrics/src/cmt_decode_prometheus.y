%define api.pure true
%name-prefix "cmt_decode_prometheus_"
%define parse.error verbose

%param {void *yyscanner}
%param {struct cmt_decode_prometheus_context *context}

%{
// we inline cmt_decode_prometheus.c which contains all the actions to avoid
// having to export a bunch of symbols that are only used by the generated
// parser code
#include "cmt_decode_prometheus.c"
%}

%union {
    cfl_sds_t str;
    char numstr[64];
    int integer;
}

%token '=' '{' '}' ','
%token <str> IDENTIFIER QUOTED HELP TYPE METRIC_DOC
%token COUNTER GAUGE SUMMARY UNTYPED HISTOGRAM
%token START_HEADER START_LABELS START_SAMPLES
%token <numstr> NUMSTR INFNAN

%type <integer> metric_type
%type <numstr> value

%destructor {
    cfl_sds_destroy($$);
} <str>

%start start;

%%

start:
    START_HEADER header
  | START_LABELS labels
  | START_SAMPLES samples
  | metrics {
    if (finish_metric(context, true, NULL)) {
        YYABORT;
    }
  }
;

metrics:
    metrics metric
  | metric
;

metric:
    header samples
  | samples
  | header
;

header:
    help type
  | help
  | type help
  | type
;

help:
    HELP METRIC_DOC {
        if (parse_metric_name(context, $1)) {
            YYABORT;
        }
        context->metric.docstring = $2;
    }
;

type:
    TYPE metric_type {
        if (parse_metric_name(context, $1)) {
            YYABORT;
        }
        context->metric.type = $2;
    }
;

metric_type:
    COUNTER { $$ = COUNTER; }
  | GAUGE { $$ = GAUGE; }
  | SUMMARY { $$ = SUMMARY; }
  | UNTYPED { $$ = UNTYPED; }
  | HISTOGRAM { $$ = HISTOGRAM; }
;

samples:
    samples sample
  | sample
;

sample:
    IDENTIFIER { 
        if (parse_metric_name(context, $1)) {
            YYABORT;
        }
        $1 = NULL;
        if (sample_start(context)) {
            YYABORT;
        }
    } sample_data
;

sample_data:
    '{' '}' values
  | '{' labels '}' values
  | values
;

labels:
    labellist ','
  | labellist
;

labellist:
    labellist ',' label
  | label
;

label:
    IDENTIFIER '=' QUOTED {
        if (parse_label(context, $1, $3)) {
            YYABORT;
        }
    }
;

values:
    value value {
        if (parse_sample(context, $1, $2)) {
            YYABORT;
        }
    }
  | value {
        if (parse_sample(context, $1, "")) {
            YYABORT;
        }
    }
;

value:
    NUMSTR | INFNAN
;

%%
