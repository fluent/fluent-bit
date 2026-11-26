/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2026 The Fluent Bit Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_unescape.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/multiline/flb_ml.h>
#include <fluent-bit/multiline/flb_ml_parser.h>

#include <limits.h>

#include "tail_config.h"
#include "tail_dockermode.h"
#include "tail_file_internal.h"

int flb_tail_dmode_create(struct flb_tail_config *ctx,
                          struct flb_input_instance *ins,
                          struct flb_config *config)
{
    const char *tmp;

    if (ctx->multiline == FLB_TRUE) {
        flb_plg_error(ctx->ins, "Docker mode cannot be enabled when multiline "
                      "is enabled");
        return -1;
    }

#ifdef FLB_HAVE_REGEX
    /* First line Parser */
    tmp = flb_input_get_property("docker_mode_parser", ins);
    if (tmp) {
        ctx->docker_mode_parser = flb_parser_get(tmp, config);
        if (!ctx->docker_mode_parser) {
            flb_plg_error(ctx->ins, "parser '%s' is not registered", tmp);
        }
    }
    else {
        ctx->docker_mode_parser = NULL;
    }
#endif

    tmp = flb_input_get_property("docker_mode_flush", ins);
    if (!tmp) {
        ctx->docker_mode_flush = FLB_TAIL_DMODE_FLUSH;
    }
    else {
        ctx->docker_mode_flush = atoi(tmp);
        if (ctx->docker_mode_flush <= 0) {
            ctx->docker_mode_flush = 1;
        }
    }

    return 0;
}

#ifdef FLB_HAVE_PARSER
/*
 * The legacy Docker mode joins the split lines on the raw JSON text, before
 * any parser runs. The multiline core joins the value of the 'log' key once
 * the parser has decoded every line. Both generate the same record only when
 * the configured parser is a plain JSON one: return the reason that prevents
 * the usage of the multiline core, or NULL if there is none.
 */
static const char *dmode_ml_blocker(struct flb_tail_config *ctx)
{
    if (ctx->docker_mode_parser) {
        return "'docker_mode_parser' matches the raw JSON line, use a "
               "'multiline' filter on the 'log' key instead";
    }

    if (!ctx->parser) {
        return "no 'parser' is set, so the raw JSON line is kept as the record";
    }

    if (ctx->parser->type != FLB_PARSER_JSON) {
        return "'parser' is not a JSON parser";
    }

    if (ctx->parser->decoders && mk_list_size(ctx->parser->decoders) > 0) {
        return "'parser' uses decoders, which must run on the joined line";
    }

    if (ctx->ignore_older > 0) {
        return "'ignore_older' also discards the records by their timestamp";
    }

    return NULL;
}

/*
 * Docker mode is deprecated in favor of the multiline core. When the
 * configuration allows it, replace the legacy implementation with a private
 * multiline parser that behaves as the built-in 'docker' one, but honors the
 * 'parser' set by the user.
 *
 * The flush timer of the multiline core is not used: it flushes every stream
 * on a global schedule, no matter when the last fragment arrived. Docker mode
 * waits 'docker_mode_flush' seconds since the last line of each file, so the
 * plugin keeps that deadline (flb_tail_dmode_ml_pending_flush).
 *
 * On return 'ctx->docker_mode' is only enabled if the legacy implementation
 * is the one in charge of the files content, 'ctx->docker_mode_ml' is set
 * when the multiline core took over.
 */
int flb_tail_dmode_ml_create(struct flb_tail_config *ctx)
{
    int flush_ms;
    char name[128];
    const char *blocker;
    struct flb_ml_parser *ml_parser;
    struct flb_ml_parser_ins *parser_i;

    if (ctx->ml_ctx) {
        /* 'multiline.parser' always had priority in the files processing */
        flb_plg_warn(ctx->ins, "'docker_mode' is deprecated and it is ignored "
                     "when 'multiline.parser' is set, remove 'docker_mode' "
                     "from the configuration");
        ctx->docker_mode = FLB_FALSE;
        return 0;
    }

    blocker = dmode_ml_blocker(ctx);
    if (blocker) {
        flb_plg_warn(ctx->ins, "'docker_mode' is deprecated and will be removed "
                     "in a future release, migrate to 'multiline.parser docker'. "
                     "Using the legacy implementation: %s", blocker);
        return 0;
    }

    if (ctx->docker_mode_flush > INT_MAX / 1000) {
        flush_ms = INT_MAX;
    }
    else {
        flush_ms = ctx->docker_mode_flush * 1000;
    }

    /* The instance name is unique, so it is the multiline parser name */
    snprintf(name, sizeof(name), "_tail_docker_mode.%s", ctx->ins->name);

    ml_parser = flb_ml_parser_create(ctx->config, name,
                                     FLB_ML_ENDSWITH, "\n", FLB_FALSE,
                                     flush_ms,
                                     "log", "stream", NULL,
                                     ctx->parser, NULL);
    if (!ml_parser) {
        flb_plg_error(ctx->ins, "could not create docker mode multiline parser");
        return -1;
    }

    ctx->ml_ctx = flb_ml_create(ctx->config, ctx->ins->name);
    if (!ctx->ml_ctx) {
        flb_ml_parser_destroy(ml_parser);
        return -1;
    }

    parser_i = flb_ml_parser_instance_create(ctx->ml_ctx, name);
    if (!parser_i) {
        flb_ml_destroy(ctx->ml_ctx);
        ctx->ml_ctx = NULL;
        flb_ml_parser_destroy(ml_parser);
        return -1;
    }

    ctx->docker_mode_ml = FLB_TRUE;
    ctx->docker_mode_ml_parser = parser_i;
    ctx->docker_mode = FLB_FALSE;
    flb_plg_warn(ctx->ins, "'docker_mode' is deprecated and will be removed in "
                 "a future release: split lines are now joined by the multiline "
                 "core, replace 'docker_mode' with 'multiline.parser docker'");

    return 0;
}

static void file_ml_pending_flush(struct flb_tail_config *ctx,
                                  struct flb_tail_file *file, time_t now)
{
    if (file->dmode_flush_timeout == 0 || file->dmode_flush_timeout > now) {
        return;
    }
    file->dmode_flush_timeout = 0;

    /* A forced flush makes the callback ingest the record right away */
    flb_ml_flush_parser_instance(ctx->ml_ctx, ctx->docker_mode_ml_parser,
                                 file->ml_stream_id, FLB_TRUE);
}

/*
 * Docker mode on top of the multiline core: flush the unfinished lines of the
 * files that did not get new content before their deadline.
 */
int flb_tail_dmode_ml_pending_flush(struct flb_input_instance *ins,
                                    struct flb_config *config, void *context)
{
    time_t now;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;

    now = time(NULL);

    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_ml_pending_flush(ctx, file, now);
    }

    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_ml_pending_flush(ctx, file, now);
    }

    return 0;
}
#endif

static int modify_json_cond(char *js, size_t js_len,
                            char **val, size_t *val_len,
                            char **out, size_t *out_len,
                            int cond(char*, size_t),
                            int mod(char*, size_t, char**, size_t*, void*), void *data)
{
    int ret;
    struct flb_pack_state state;
    jsmntok_t *t;
    jsmntok_t *t_val = NULL;
    int i;
    int i_root = -1;
    int i_key = -1;
    char *old_val;
    size_t old_val_len;
    char *new_val = NULL;
    size_t new_val_len = 0;
    size_t mod_len;

    ret = flb_pack_state_init(&state);
    if (ret != 0) {
        ret = -1;
        goto modify_json_cond_end;
    }

    ret = flb_json_tokenise(js, js_len, &state);
    if (ret != 0 || state.tokens_count == 0) {
        ret = -1;
        goto modify_json_cond_end;
    }

    for (i = 0; i < state.tokens_count; i++) {
        t = &state.tokens[i];

        if (i_key >= 0) {
            if (t->parent == i_key) {
                if (t->type == JSMN_STRING) {
                   t_val = t;
                }
                break;
            }
            continue;
        }

        if (t->start == 0 && t->parent == -1 && t->type == JSMN_OBJECT) {
            i_root = i;
            continue;
        }
        if (i_root == -1) {
            continue;
        }

        if (t->parent == i_root && t->type == JSMN_STRING && t->end - t->start == 3 && strncmp(js + t->start, "log", 3) == 0) {
            i_key = i;
        }
    }

    if (!t_val) {
        ret = -1;
        goto modify_json_cond_end;
    }

    *out = js;
    *out_len = js_len;

    if (val) {
        *val = js + t_val->start;
    }
    if (val_len) {
        *val_len = t_val->end - t_val->start;
    }

    if (!cond || cond(js + t_val->start, t_val->end - t_val->start)) {
        old_val = js + t_val->start;
        old_val_len = t_val->end - t_val->start;
        ret = mod(old_val, old_val_len, &new_val, &new_val_len, data);
        if (ret != 0) {
            ret = -1;
            goto modify_json_cond_end;
        }

        ret = 1;

        if (new_val == old_val) {
            goto modify_json_cond_end;
        }

        mod_len = js_len + new_val_len - old_val_len;
        *out = flb_malloc(mod_len);
        if (!*out) {
            flb_errno();
            flb_free(new_val);
            ret = -1;
            goto modify_json_cond_end;
        }
        *out_len = mod_len;

        memcpy(*out, js, t_val->start);
        memcpy(*out + t_val->start, new_val, new_val_len);
        memcpy(*out + t_val->start + new_val_len, js + t_val->end, js_len - t_val->end);

        flb_free(new_val);
    }

 modify_json_cond_end:
    flb_pack_state_reset(&state);
    if (ret < 0) {
        *out = NULL;
    }
    return ret;
}

static int unesc_ends_with_nl(char *str, size_t len)
{
    char* unesc;
    int unesc_len;
    int nl;

    unesc = flb_malloc(len + 1);
    if (!unesc) {
        flb_errno();
        return FLB_FALSE;
    }
    unesc_len = flb_unescape_string(str, len, &unesc);
    nl = unesc_len > 0 && unesc[unesc_len - 1] == '\n';
    flb_free(unesc);
    return nl;
}

static int prepend_sds_to_str(char *str, size_t len, char **out, size_t *out_len, void *data)
{
    flb_sds_t sds = data;

    if (flb_sds_len(sds) == 0) {
        *out = str;
        *out_len = len;
        return 0;
    }

    size_t mod_len = flb_sds_len(sds) + len;
    *out = flb_malloc(mod_len);
    if (!*out) {
        flb_errno();
        return -1;
    }
    *out_len = mod_len;

    memcpy(*out, sds, flb_sds_len(sds));
    memcpy(*out + flb_sds_len(sds), str, len);
    return 0;
}

static int use_sds(char *str, size_t len, char **out, size_t *out_len, void *data)
{
    flb_sds_t sds = data;
    size_t mod_len = flb_sds_len(sds);
    *out = flb_malloc(mod_len);
    if (!*out) {
        flb_errno();
        return -1;
    }
    *out_len = mod_len;

    memcpy(*out, sds, flb_sds_len(sds));
    return 0;
}

int flb_tail_dmode_process_content(time_t now,
                                   char* line, size_t line_len,
                                   char **repl_line, size_t *repl_line_len,
                                   struct flb_tail_file *file,
                                   struct flb_tail_config *ctx)
{
    char* val = NULL;
    size_t val_len;
    int ret;
    void *out_buf = NULL;
    size_t out_size;
    struct flb_time out_time = {0};
    *repl_line = NULL;
    *repl_line_len = 0;
    flb_sds_t tmp;
    flb_sds_t tmp_copy;

#ifdef FLB_HAVE_REGEX
    if (ctx->docker_mode_parser) {
        ret = flb_parser_do(ctx->docker_mode_parser, line, line_len,
                            &out_buf, &out_size, &out_time);
        flb_free(out_buf);

        /*
        * Set dmode_firstline if the line meets the first-line requirement
        */
        if(ret >= 0) {
            file->dmode_firstline = true;
        }

        /*
        * Process if buffer contains full log line
        */
        if (flb_sds_len(file->dmode_lastline) > 0 && file->dmode_complete) {
            /*
            * Buffered log should be flushed out
            * as current line meets first-line requirement
            */
            if(ret >= 0) {
                flb_tail_dmode_flush(file, ctx);
            }

            /*
            * Flush the buffer if multiline has not been detected yet
            */
            if (!file->dmode_firstline) {
                flb_tail_dmode_flush(file, ctx);
            }
        }
    }
#endif

    ret = modify_json_cond(line, line_len,
                           &val, &val_len,
                           repl_line, repl_line_len,
                           unesc_ends_with_nl,
                           prepend_sds_to_str, file->dmode_buf);
    if (ret >= 0) {
        /* line is a valid json */
        flb_sds_len_set(file->dmode_lastline, 0);

        /* concatenate current log line with buffered one */
        tmp = flb_sds_cat(file->dmode_buf, val, val_len);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        file->dmode_buf = tmp;

        tmp_copy = flb_sds_copy(file->dmode_lastline, line, line_len);
        if (!tmp_copy) {
            flb_errno();
            return -1;
        }

        file->dmode_lastline = tmp_copy;
        file->dmode_flush_timeout = now + (ctx->docker_mode_flush - 1);

        if (ret == 0) {
            /* Line not ended with newline */
            file->dmode_complete = false;
        }
        else {
            /* Line ended with newline */
            file->dmode_complete = true;
#ifdef FLB_HAVE_REGEX
            if (!ctx->docker_mode_parser) {
                flb_tail_dmode_flush(file, ctx);
            }
#else
            flb_tail_dmode_flush(file, ctx);
#endif
        }
    }
    return ret;
}

void flb_tail_dmode_flush(struct flb_tail_file *file, struct flb_tail_config *ctx)
{
    int ret;
    char *repl_line = NULL;
    size_t repl_line_len = 0;
    void *out_buf = NULL;
    size_t out_size;
    struct flb_time out_time = {0};
    time_t now = time(NULL);

    if (flb_sds_len(file->dmode_lastline) == 0) {
        return;
    }

    flb_time_zero(&out_time);

    ret = modify_json_cond(file->dmode_lastline,
                           flb_sds_len(file->dmode_lastline),
                           NULL, NULL,
                           &repl_line, &repl_line_len,
                           NULL,
                           use_sds, file->dmode_buf);
    if (ret < 0) {
        return;
    }

    flb_sds_len_set(file->dmode_buf, 0);
    flb_sds_len_set(file->dmode_lastline, 0);
    file->dmode_flush_timeout = 0;

#ifdef FLB_HAVE_REGEX
    if (ctx->parser) {
        ret = flb_parser_do(ctx->parser, repl_line, repl_line_len,
                            &out_buf, &out_size, &out_time);
        if (ret >= 0) {
            if (flb_time_to_double(&out_time) == 0) {
                flb_time_get(&out_time);
            }
            if (ctx->ignore_older > 0 && (now - ctx->ignore_older) > out_time.tm.tv_sec) {
                goto dmode_flush_end;
            }

            flb_tail_pack_line_map(&out_time, (char**) &out_buf, &out_size, file, 0);

            goto dmode_flush_end;
        }
    }
#endif

    flb_tail_file_pack_line(NULL, repl_line, repl_line_len, file, 0);

 dmode_flush_end:
    flb_free(repl_line);
    flb_free(out_buf);
}

static void file_pending_flush(struct flb_tail_config *ctx,
                               struct flb_tail_file *file, time_t now)
{
    if (file->dmode_flush_timeout > now) {
        return;
    }

    if (flb_sds_len(file->dmode_lastline) == 0) {
        return;
    }

    flb_tail_dmode_flush(file, ctx);

    if (file->sl_log_event_encoder->output_length > 0) {
        flb_input_log_append(ctx->ins,
                             file->tag_buf,
                             file->tag_len,
                             file->sl_log_event_encoder->output_buffer,
                             file->sl_log_event_encoder->output_length);

        flb_log_event_encoder_reset(file->sl_log_event_encoder);
    }
}

int flb_tail_dmode_pending_flush_all(struct flb_tail_config *ctx)
{
    time_t expired;
    struct mk_list *head;
    struct flb_tail_file *file;

    expired = time(NULL) + 3600;

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, expired);
    }

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, expired);
    }

    return 0;
}

int flb_tail_dmode_pending_flush(struct flb_input_instance *ins,
                                 struct flb_config *config, void *context)
{
    time_t now;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;

    now = time(NULL);

    /* Iterate static event files with pending bytes */
    mk_list_foreach(head, &ctx->files_static) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, now);
    }

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);
        file_pending_flush(ctx, file, now);
    }

    return 0;
}
