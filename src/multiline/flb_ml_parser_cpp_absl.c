#include <fluent-bit/flb_info.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>
#include <fluent-bit/multiline/flb_ml_rule.h>

#define rule flb_ml_rule_create

static void rule_error(struct flb_ml_parser *ml_parser) {
    int id;

    id = mk_list_size(&ml_parser->regex_rules);
    flb_error("[multiline: cpp_absl] rule #%i could not be created", id);
    flb_ml_parser_destroy(ml_parser);
}

/* cpp_absl mode */
struct flb_ml_parser *flb_ml_parser_cpp_absl(struct flb_config *config, char *key) {
    int ret;
    struct flb_ml_parser *mlp;

    mlp = flb_ml_parser_create(config,               /* Fluent Bit context */
                               "cpp_absl",           /* name      */
                               FLB_ML_REGEX,         /* type      */
                               NULL,                 /* match_str */
                               FLB_FALSE,            /* negate    */
                               FLB_ML_FLUSH_TIMEOUT, /* flush_ms  */
                               key,                  /* key_content */
                               NULL,                 /* key_group   */
                               NULL,                 /* key_pattern */
                               NULL,                 /* parser ctx  */
                               NULL);                /* parser name */

    if (!mlp) {
        flb_error("[multiline] could not create 'cpp_absl mode'");
        return NULL;
    }

    ret = rule(mlp,
               "start_state, cpp_absl_start",
               "/^(?:I|W|E|F)(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])\\s+\\d{2}:\\d{2}:\\d{2}\\.\\d{6}\\s+\\d+\\s+\\S+:\\d+\\]\\s+.+/",
               "cpp_absl_stack", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    ret = rule(mlp,
               "cpp_absl_stack",
               "/^(?!(?:I|W|E|F)(0[1-9]|1[012])(0[1-9]|[12][0-9]|3[01])\\s+\\d{2}:\\d{2}:\\d{2}\\.\\d{6}\\s+\\d+\\s+\\S+:\\d+\\]).+/",
               "cpp_absl_stack", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    ret = rule(mlp,
               "cpp_absl_stack",
               "/^[\\r\\n]*$/",
               "cpp_absl_stack", NULL);
    if (ret != 0) {
        rule_error(mlp);
        return NULL;
    }

    /* Map the rules (mandatory for regex rules) */
    ret = flb_ml_parser_init(mlp);
    if (ret != 0) {
        flb_error("[multiline: cpp_absl] error on mapping rules");
        flb_ml_parser_destroy(mlp);
        return NULL;
    }

    return mlp;
}
