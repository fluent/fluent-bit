/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2020 The Fluent Bit Authors
 *  Copyright (C) 2015-2018 Treasure Data Inc.
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
    nl = unesc[unesc_len - 1] == '\n';
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
                                   struct flb_tail_config *ctx,
                                   msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck
                                   )
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
    if (flb_sds_len(file->dmode_lastline) > 0 && file->dmode_complete) {
        if (ctx->docker_mode_parser) {
            ret = flb_parser_do(ctx->docker_mode_parser, line, line_len,
                                &out_buf, &out_size, &out_time);
            flb_free(out_buf);

            /*
            * Buffered log should be flushed out
            * as current line meets first-line requirement
            */
            if(ret >= 0) {
                flb_tail_dmode_flush(mp_sbuf, mp_pck, file, ctx);
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

        tmp_copy = flb_sds_copy(file->dmode_lastline, line, line_len);
        if (!tmp_copy) {
            flb_errno();
            return -1;
        }

        file->dmode_buf = tmp;
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
                flb_tail_dmode_flush(mp_sbuf, mp_pck, file, ctx);
            }
#else
            flb_tail_dmode_flush(mp_sbuf, mp_pck, file, ctx);
#endif
        }
    }
    return ret;
}

void flb_tail_dmode_flush(msgpack_sbuffer *mp_sbuf, msgpack_packer *mp_pck,
                          struct flb_tail_file *file, struct flb_tail_config *ctx)
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

    ret = modify_json_cond(file->dmode_lastline, flb_sds_len(file->dmode_lastline),
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
            flb_tail_pack_line_map(mp_sbuf, mp_pck, &out_time,
                                   (char**) &out_buf, &out_size, file);
            goto dmode_flush_end;        }
    }
#endif
    flb_time_get(&out_time);
    flb_tail_file_pack_line(mp_sbuf, mp_pck, &out_time,
                            repl_line, repl_line_len, file);

 dmode_flush_end:
    flb_free(repl_line);
    flb_free(out_buf);
}

int flb_tail_dmode_pending_flush(struct flb_input_instance *ins,
                                 struct flb_config *config, void *context)
{
    time_t now;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    struct mk_list *head;
    struct flb_tail_file *file;
    struct flb_tail_config *ctx = context;

    now = time(NULL);

    /* Iterate promoted event files with pending bytes */
    mk_list_foreach(head, &ctx->files_event) {
        file = mk_list_entry(head, struct flb_tail_file, _head);

        if (file->dmode_flush_timeout > now) {
            continue;
        }

        if (flb_sds_len(file->dmode_lastline) == 0) {
            continue;
        }

        msgpack_sbuffer_init(&mp_sbuf);
        msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

        flb_tail_dmode_flush(&mp_sbuf, &mp_pck, file, ctx);

        flb_input_chunk_append_raw(ins,
                                   file->tag_buf,
                                   file->tag_len,
                                   mp_sbuf.data,
                                   mp_sbuf.size);
        msgpack_sbuffer_destroy(&mp_sbuf);
    }

    return 0;
}
