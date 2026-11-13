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

/*
 * What a record is mined by
 * =========================
 * A record offers the miner one of two things:
 *
 *  - text: the string under one of the 'key' names, in the record or inside a
 *    map or JSON object that sits under one of those names;
 *  - fields: when there is no such string, a line built from the fields,
 *    one 'name=value' token each. Short words stay as they are and take part
 *    in the identity of the pattern, anything else is masked by the miner.
 *
 * JSON text is scanned in place, nothing is allocated per record.
 */

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_slist.h>

#include <stdio.h>
#include <string.h>
#include <inttypes.h>

#include "adaptive.h"

#define FIELD_DEPTH      2
#define FIELD_NAME_MAX   48
#define FIELD_VALUE_MAX  48

struct line_state {
    struct adaptive_ctx *ctx;
    struct adaptive_source *source;
    int tokens;
    int find_text;              /* a 'key' name at the top level is the message */
    int find_level;
};

static inline int is_space(char c)
{
    return c == ' ' || c == '\t' || c == '\n' || c == '\r';
}

static int name_is_key(struct adaptive_ctx *ctx, const char *name, size_t len)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, ctx->keys) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        if (flb_sds_len(entry->str) == len && memcmp(entry->str, name, len) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

/* Copy replacing what would split or confuse a token */
static void line_cat_clean(cfl_sds_t *line, const char *str, size_t len)
{
    size_t i;
    size_t start = 0;

    for (i = 0; i < len; i++) {
        if ((unsigned char) str[i] <= ' ') {
            if (i > start) {
                cfl_sds_cat_safe(line, str + start, i - start);
            }
            cfl_sds_cat_safe(line, "_", 1);
            start = i + 1;
        }
    }
    if (len > start) {
        cfl_sds_cat_safe(line, str + start, len - start);
    }
}

/* Start a token: ' prefix.name=' */
static int line_name(struct line_state *state, const char *prefix, size_t prefix_len,
                     const char *name, size_t name_len)
{
    cfl_sds_t *line = &state->ctx->line;

    /* one more than the miner reads, so it knows the line was cut */
    if (state->tokens > state->ctx->max_tokens) {
        return -1;
    }
    state->tokens++;

    if (cfl_sds_len(*line) > 0) {
        cfl_sds_cat_safe(line, " ", 1);
    }
    if (prefix_len > 0) {
        line_cat_clean(line, prefix, prefix_len);
        cfl_sds_cat_safe(line, ".", 1);
    }
    line_cat_clean(line, name, name_len > FIELD_NAME_MAX ? FIELD_NAME_MAX : name_len);
    cfl_sds_cat_safe(line, "=", 1);

    return 0;
}

static void line_string(struct line_state *state, const char *str, size_t len)
{
    cfl_sds_t *line = &state->ctx->line;

    if (len == 0) {
        cfl_sds_cat_safe(line, "\"\"", 2);
    }
    else if (len > FIELD_VALUE_MAX) {
        /* free text, an identifier or a payload: never part of the identity */
        cfl_sds_cat_safe(line, ADAPTIVE_WILDCARD, sizeof(ADAPTIVE_WILDCARD) - 1);
    }
    else {
        line_cat_clean(line, str, len);
    }
}

static void variant_bytes(struct cfl_variant *variant, const char **str, size_t *len)
{
    *str = variant->data.as_string;
    *len = cfl_variant_size_get(variant);
    if (*len == 0 && !variant->referenced) {
        *len = cfl_sds_len(variant->data.as_string);
    }
}

static void kvlist_fields(struct line_state *state, struct cfl_kvlist *kvlist,
                          const char *prefix, size_t prefix_len, int depth)
{
    int len;
    size_t size;
    size_t name_len;
    char tmp[48];
    char path[FIELD_NAME_MAX * FIELD_DEPTH + 4];
    const char *str;
    struct cfl_list *head;
    struct cfl_kvpair *pair;
    struct cfl_variant *value;
    struct adaptive_ctx *ctx = state->ctx;
    cfl_sds_t *line = &ctx->line;

    cfl_list_foreach(head, &kvlist->list) {
        pair = cfl_list_entry(head, struct cfl_kvpair, _head);
        value = pair->val;
        name_len = cfl_sds_len(pair->key);

        /* what an earlier adaptive processor wrote says nothing about the record */
        if (depth == 0 && name_len == cfl_sds_len(ctx->annotate_key) &&
            memcmp(pair->key, ctx->annotate_key, name_len) == 0) {
            continue;
        }

        if (value->type == CFL_VARIANT_KVLIST && depth + 1 < FIELD_DEPTH) {
            len = snprintf(path, sizeof(path), "%.*s%s%.*s",
                           (int) prefix_len, prefix, prefix_len > 0 ? "." : "",
                           (int) (name_len > FIELD_NAME_MAX ? FIELD_NAME_MAX : name_len),
                           pair->key);
            kvlist_fields(state, value->data.as_kvlist, path, len, depth + 1);
            continue;
        }

        if (line_name(state, prefix, prefix_len, pair->key, name_len) != 0) {
            return;
        }

        switch (value->type) {
        case CFL_VARIANT_STRING:
            variant_bytes(value, &str, &size);
            line_string(state, str, size);
            break;
        case CFL_VARIANT_INT:
            len = snprintf(tmp, sizeof(tmp), "%" PRId64, value->data.as_int64);
            cfl_sds_cat_safe(line, tmp, len);
            break;
        case CFL_VARIANT_UINT:
            len = snprintf(tmp, sizeof(tmp), "%" PRIu64, value->data.as_uint64);
            cfl_sds_cat_safe(line, tmp, len);
            break;
        case CFL_VARIANT_DOUBLE:
            len = snprintf(tmp, sizeof(tmp), "%.6f", value->data.as_double);
            cfl_sds_cat_safe(line, tmp, len);
            break;
        case CFL_VARIANT_BOOL:
            if (value->data.as_bool) {
                cfl_sds_cat_safe(line, "true", 4);
            }
            else {
                cfl_sds_cat_safe(line, "false", 5);
            }
            break;
        case CFL_VARIANT_NULL:
            cfl_sds_cat_safe(line, "null", 4);
            break;
        case CFL_VARIANT_KVLIST:
            cfl_sds_cat_safe(line, "{}", 2);
            break;
        case CFL_VARIANT_ARRAY:
            cfl_sds_cat_safe(line, "[]", 2);
            break;
        default:
            cfl_sds_cat_safe(line, ADAPTIVE_WILDCARD, sizeof(ADAPTIVE_WILDCARD) - 1);
            break;
        }
    }
}

/* Advance past a JSON string, 'p' is at the opening quote */
static const char *json_string_end(const char *p, const char *end)
{
    p++;
    while (p < end) {
        if (*p == '\\') {
            p += 2;
            continue;
        }
        if (*p == '"') {
            return p;
        }
        p++;
    }

    return NULL;
}

/* Advance past a nested object or array without looking inside */
static const char *json_skip(const char *p, const char *end)
{
    int depth = 0;

    while (p < end) {
        if (*p == '"') {
            p = json_string_end(p, end);
            if (!p) {
                return NULL;
            }
        }
        else if (*p == '{' || *p == '[') {
            depth++;
        }
        else if (*p == '}' || *p == ']') {
            depth--;
            if (depth == 0) {
                return p + 1;
            }
        }
        p++;
    }

    return NULL;
}

/* Walk one object, 'p' is past its opening brace. Returns past the closing one */
static const char *json_fields(struct line_state *state, const char *p, const char *end,
                               const char *prefix, size_t prefix_len, int depth)
{
    int len;
    int skip;
    size_t name_len;
    char path[FIELD_NAME_MAX * FIELD_DEPTH + 4];
    const char *name;
    const char *value;
    struct adaptive_ctx *ctx = state->ctx;
    struct adaptive_source *source = state->source;
    cfl_sds_t *line = &ctx->line;

    while (p < end) {
        while (p < end && (is_space(*p) || *p == ',')) {
            p++;
        }
        if (p >= end) {
            return NULL;
        }
        if (*p == '}') {
            return p + 1;
        }
        if (*p != '"') {
            return NULL;
        }

        name = p + 1;
        p = json_string_end(p, end);
        if (!p) {
            return NULL;
        }
        name_len = p - name;
        p++;

        while (p < end && is_space(*p)) {
            p++;
        }
        if (p >= end || *p != ':') {
            return NULL;
        }
        p++;
        while (p < end && is_space(*p)) {
            p++;
        }
        if (p >= end) {
            return NULL;
        }

        if (*p == '{' && depth + 1 < FIELD_DEPTH) {
            len = snprintf(path, sizeof(path), "%.*s%s%.*s",
                           (int) prefix_len, prefix, prefix_len > 0 ? "." : "",
                           (int) (name_len > FIELD_NAME_MAX ? FIELD_NAME_MAX : name_len),
                           name);
            p = json_fields(state, p + 1, end, path, len, depth + 1);
            if (!p) {
                return NULL;
            }
            continue;
        }

        skip = line_name(state, prefix, prefix_len, name, name_len) != 0;

        if (*p == '"') {
            value = p + 1;
            p = json_string_end(p, end);
            if (!p) {
                return NULL;
            }

            if (depth == 0 && state->find_text && source->type == ADAPTIVE_SOURCE_NONE &&
                name_is_key(ctx, name, name_len)) {
                source->type = ADAPTIVE_SOURCE_TEXT;
                source->str = value;
                source->len = p - value;
            }
            else if (depth == 0 && state->find_level && !source->level && ctx->level_key &&
                     name_len == cfl_sds_len(ctx->level_key) &&
                     memcmp(name, ctx->level_key, name_len) == 0) {
                source->level = value;
                source->level_len = p - value;
            }

            if (!skip) {
                line_string(state, value, p - value);
            }
            p++;
        }
        else if (*p == '{' || *p == '[') {
            if (!skip) {
                cfl_sds_cat_safe(line, *p == '{' ? "{}" : "[]", 2);
            }
            p = json_skip(p, end);
            if (!p) {
                return NULL;
            }
        }
        else {
            value = p;
            while (p < end && *p != ',' && *p != '}' && !is_space(*p)) {
                p++;
            }
            if (p == value) {
                return NULL;
            }
            if (!skip) {
                cfl_sds_cat_safe(line, value, p - value);
            }
        }
    }

    return NULL;
}

static void state_init(struct line_state *state, struct adaptive_ctx *ctx,
                       struct adaptive_source *source)
{
    state->ctx = ctx;
    state->source = source;
    state->tokens = 0;
    state->find_text = FLB_TRUE;
    state->find_level = FLB_TRUE;
    cfl_sds_len_set(ctx->line, 0);
}

static void source_fields(struct adaptive_ctx *ctx, struct adaptive_source *source)
{
    source->type = ADAPTIVE_SOURCE_FIELDS;
    source->str = ctx->line;
    source->len = cfl_sds_len(ctx->line);
}

/* A string that holds a JSON object. Returns -1 when it is not one */
static int source_from_json(struct adaptive_ctx *ctx, const char *str, size_t len,
                            struct adaptive_source *source)
{
    const char *p = str;
    const char *end = str + len;
    struct line_state state;

    while (p < end && is_space(*p)) {
        p++;
    }
    while (end > p && is_space(end[-1])) {
        end--;
    }
    if (end - p < 2 || *p != '{' || end[-1] != '}') {
        return -1;
    }

    state_init(&state, ctx, source);
    p = json_fields(&state, p + 1, end, NULL, 0, 0);
    if (p != end) {
        source->type = ADAPTIVE_SOURCE_NONE;
        source->level = NULL;
        return -1;
    }

    if (source->type == ADAPTIVE_SOURCE_NONE) {
        source_fields(ctx, source);
    }

    return 0;
}

static void source_from_kvlist(struct adaptive_ctx *ctx, struct cfl_kvlist *kvlist,
                               int nested, struct adaptive_source *source)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct cfl_variant *variant;
    struct line_state state;

    if (nested) {
        mk_list_foreach(head, ctx->keys) {
            entry = mk_list_entry(head, struct flb_slist_entry, _head);
            variant = cfl_kvlist_fetch_s(kvlist, entry->str, flb_sds_len(entry->str));
            if (variant && variant->type == CFL_VARIANT_STRING && variant->data.as_string) {
                source->type = ADAPTIVE_SOURCE_TEXT;
                variant_bytes(variant, &source->str, &source->len);
                break;
            }
        }

        if (ctx->level_key) {
            variant = cfl_kvlist_fetch_s(kvlist, ctx->level_key, cfl_sds_len(ctx->level_key));
            if (variant && variant->type == CFL_VARIANT_STRING && variant->data.as_string) {
                variant_bytes(variant, &source->level, &source->level_len);
            }
        }

        if (source->type == ADAPTIVE_SOURCE_TEXT) {
            return;
        }
    }

    state_init(&state, ctx, source);
    kvlist_fields(&state, kvlist, NULL, 0, 0);
    source_fields(ctx, source);
}

/* The message string of a record: JSON objects are looked into */
int adaptive_source_from_text(struct adaptive_ctx *ctx, const char *str, size_t len,
                              struct adaptive_source *source)
{
    if (ctx->structured && len > 1 && source_from_json(ctx, str, len, source) == 0) {
        return source->type;
    }

    source->str = str;
    source->len = len;
    source->type = ADAPTIVE_SOURCE_TEXT;

    return source->type;
}

int adaptive_source_resolve(struct adaptive_ctx *ctx, struct cfl_kvlist *body,
                            struct adaptive_source *source)
{
    size_t len;
    const char *str;
    struct mk_list *head;
    struct flb_slist_entry *entry;
    struct cfl_variant *variant;

    source->type = ADAPTIVE_SOURCE_NONE;
    source->str = NULL;
    source->len = 0;
    source->level = NULL;
    source->level_len = 0;

    mk_list_foreach(head, ctx->keys) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);
        variant = cfl_kvlist_fetch_s(body, entry->str, flb_sds_len(entry->str));
        if (!variant) {
            continue;
        }

        if (variant->type == CFL_VARIANT_STRING && variant->data.as_string) {
            variant_bytes(variant, &str, &len);
            return adaptive_source_from_text(ctx, str, len, source);
        }

        if (variant->type == CFL_VARIANT_KVLIST && ctx->structured) {
            source_from_kvlist(ctx, variant->data.as_kvlist, FLB_TRUE, source);
            return source->type;
        }
    }

    if (ctx->structured && !cfl_list_is_empty(&body->list)) {
        source_from_kvlist(ctx, body, FLB_FALSE, source);
    }

    return source->type;
}
