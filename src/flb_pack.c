/*-*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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

#include <stdlib.h>
#include <string.h>

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_unescape.h>

#include <fluent-bit/flb_log_event_encoder.h>
#include <fluent-bit/flb_log_event_decoder.h>

/* cmetrics */
#include <cmetrics/cmetrics.h>
#include <cmetrics/cmt_decode_msgpack.h>
#include <cmetrics/cmt_encode_text.h>

#include <msgpack.h>
#include <math.h>
#include <jsmn/jsmn.h>

#define try_to_write_str  flb_utils_write_str

static int convert_nan_to_null = FLB_FALSE;

static int flb_pack_set_null_as_nan(int b) {
    if (b == FLB_TRUE || b == FLB_FALSE) {
        convert_nan_to_null = b;
    }
    return convert_nan_to_null;
}

int flb_json_tokenise(const char *js, size_t len,
                      struct flb_pack_state *state)
{
    int ret;
    int new_tokens = 256;
    size_t old_size;
    size_t new_size;
    void *tmp;

    ret = jsmn_parse(&state->parser, js, len,
                     state->tokens, state->tokens_size);
    while (ret == JSMN_ERROR_NOMEM) {
        /* Get current size of the array in bytes */
        old_size = state->tokens_size * sizeof(jsmntok_t);

        /* New size: add capacity for new 256 entries */
        new_size = old_size + (sizeof(jsmntok_t) * new_tokens);

        tmp = flb_realloc(state->tokens, new_size);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        state->tokens = tmp;
        state->tokens_size += new_tokens;

        /* Reset parser to reprocess the JSON data from the beginning */
        jsmn_init(&state->parser);

        ret = jsmn_parse(&state->parser, js, len,
                         state->tokens, state->tokens_size);
    }

    if (ret == JSMN_ERROR_INVAL) {
        return FLB_ERR_JSON_INVAL;
    }

    if (ret == JSMN_ERROR_PART) {
        /* This is a partial JSON message, just stop */
        flb_trace("[json tokenise] incomplete");
        return FLB_ERR_JSON_PART;
    }

    state->tokens_count += ret;
    return 0;
}

static inline int is_float(const char *buf, int len)
{
    const char *end = buf + len;
    const char *p = buf;

    while (p <= end) {
        if ((*p == 'e' || *p == 'E') && p < end && (*(p + 1) == '-' || *(p + 1) == '+')) {
            return 1;
        }
        else if (*p == '.') {
            return 1;
        }
        p++;
    }

    return 0;
}

static inline void pack_numeric_token(msgpack_packer *pck, const char *p, int flen)
{
    long long val;
    unsigned long long u_val;

    if (is_float(p, flen)) {
        msgpack_pack_double(pck, strtod(p, NULL));
        return;
    }

    errno = 0;

    if (*p == '-') {
        val = strtoll(p, NULL, 10);

        if (errno == ERANGE) {
            msgpack_pack_double(pck, strtod(p, NULL));
        }
        else {
            msgpack_pack_int64(pck, val);
        }
    }
    else {
        u_val = strtoull(p, NULL, 10);

        if (errno == ERANGE) {
            msgpack_pack_double(pck, strtod(p, NULL));
        }
        else if (u_val <= LLONG_MAX) {
            msgpack_pack_int64(pck, (long long)u_val);
        }
        else {
            msgpack_pack_uint64(pck, u_val);
        }
    }
}

/* Sanitize incoming JSON string */
static inline int pack_string_token(struct flb_pack_state *state,
                                    const char *str, int len,
                                    msgpack_packer *pck)
{
    int s;
    int out_len;
    char *tmp;
    char *out_buf;

    if (state->buf_size < len + 1) {
        s = len + 1;
        tmp = flb_realloc(state->buf_data, s);
        if (!tmp) {
            flb_errno();
            return -1;
        }
        else {
            state->buf_data = tmp;
            state->buf_size = s;
        }
    }
    out_buf = state->buf_data;

    /* Always decode any UTF-8 or special characters */
    out_len = flb_unescape_string_utf8(str, len, out_buf);

    /* Pack decoded text */
    msgpack_pack_str(pck, out_len);
    msgpack_pack_str_body(pck, out_buf, out_len);

    return out_len;
}

/* Receive a tokenized JSON message and convert it to MsgPack */
static char *tokens_to_msgpack(struct flb_pack_state *state,
                               const char *js,
                               int *out_size, int *last_byte,
                               int *out_records)
{
    int i;
    int flen;
    int arr_size;
    int records = 0;
    const char *p;
    char *buf = NULL;
    const jsmntok_t *t;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;
    jsmntok_t *tokens;

    tokens = state->tokens;
    arr_size = state->tokens_count;

    if (arr_size == 0) {
        return NULL;
    }

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < arr_size ; i++) {
        t = &tokens[i];

        if (t->start < 0 || t->end <= 0) {
            msgpack_sbuffer_destroy(&sbuf);
            return NULL;
        }

        if (t->parent == -1) {
            *last_byte = t->end;
            records++;
        }

        flen = (t->end - t->start);
        switch (t->type) {
        case JSMN_OBJECT:
            msgpack_pack_map(&pck, t->size);
            break;
        case JSMN_ARRAY:
            msgpack_pack_array(&pck, t->size);
            break;
        case JSMN_STRING:
            if (pack_string_token(state, js + t->start, flen, &pck) < 0) {
                msgpack_sbuffer_destroy(&sbuf);
                return NULL;
            }
            break;
        case JSMN_PRIMITIVE:
            p = js + t->start;
            if (*p == 'f') {
                msgpack_pack_false(&pck);
            }
            else if (*p == 't') {
                msgpack_pack_true(&pck);
            }
            else if (*p == 'n') {
                msgpack_pack_nil(&pck);
            }
            else {
                pack_numeric_token(&pck, p, flen);
            }
            break;
        case JSMN_UNDEFINED:
            msgpack_sbuffer_destroy(&sbuf);
            return NULL;
        }
    }

    *out_size = sbuf.size;
    *out_records = records;
    buf = sbuf.data;

    return buf;
}

/*
 * It parse a JSON string and convert it to MessagePack format, this packer is
 * useful when a complete JSON message exists, otherwise it will fail until
 * the message is complete.
 *
 * This routine do not keep a state in the parser, do not use it for big
 * JSON messages.
 */
static int pack_json_to_msgpack(const char *js, size_t len, char **buffer,
                                size_t *size, int *root_type, int *records,
                                size_t *consumed)
{
    int ret = -1;
    int n_records;
    int out;
    int last;
    char *buf = NULL;
    struct flb_pack_state state;

    ret = flb_pack_state_init(&state);
    if (ret != 0) {
        return -1;
    }
    ret = flb_json_tokenise(js, len, &state);
    if (ret != 0) {
        ret = -1;
        goto flb_pack_json_end;
    }

    if (state.tokens_count == 0) {
        ret = -1;
        goto flb_pack_json_end;
    }

    buf = tokens_to_msgpack(&state, js, &out, &last, &n_records);
    if (!buf) {
        ret = -1;
        goto flb_pack_json_end;
    }

    *root_type = state.tokens[0].type;
    *size = out;
    *buffer = buf;
    *records = n_records;

    if (consumed != NULL) {
        *consumed = last;
    }

    ret = 0;

 flb_pack_json_end:
    if (ret != 0 && buf) {
        flb_free(buf);
    }
    flb_pack_state_reset(&state);
    return ret;
}

/* Pack unlimited serialized JSON messages into msgpack */
int flb_pack_json(const char *js, size_t len, char **buffer, size_t *size,
                  int *root_type, size_t *consumed)
{
    int records;

    return pack_json_to_msgpack(js, len, buffer, size, root_type, &records, consumed);
}

/*
 * Pack unlimited serialized JSON messages into msgpack, finally it writes on
 * 'out_records' the number of messages.
 */
int flb_pack_json_recs(const char *js, size_t len, char **buffer, size_t *size,
                       int *root_type, int *out_records, size_t *consumed)
{
    return pack_json_to_msgpack(js, len, buffer, size, root_type, out_records, consumed);
}

/* Initialize a JSON packer state */
int flb_pack_state_init(struct flb_pack_state *s)
{
    int tokens = 256;
    size_t size = 256;

    jsmn_init(&s->parser);

    size = sizeof(jsmntok_t) * tokens;
    s->tokens = flb_malloc(size);
    if (!s->tokens) {
        flb_errno();
        return -1;
    }
    s->tokens_size   = tokens;
    s->tokens_count  = 0;
    s->last_byte     = 0;
    s->multiple      = FLB_FALSE;

    s->buf_data = flb_malloc(size);
    if (!s->buf_data) {
        flb_errno();
        flb_free(s->tokens);
        s->tokens = NULL;
        return -1;
    }
    s->buf_size = size;
    s->buf_len = 0;

    return 0;
}

void flb_pack_state_reset(struct flb_pack_state *s)
{
    flb_free(s->tokens);
    s->tokens = NULL;
    s->tokens_size  = 0;
    s->tokens_count = 0;
    s->last_byte    = 0;
    s->buf_size     = 0;
    flb_free(s->buf_data);
    s->buf_data = NULL;
}


/*
 * It parse a JSON string and convert it to MessagePack format. The main
 * difference of this function and the previous flb_pack_json() is that it
 * keeps a parser and tokens state, allowing to process big messages and
 * resume the parsing process instead of start from zero.
 */
int flb_pack_json_state(const char *js, size_t len,
                        char **buffer, int *size,
                        struct flb_pack_state *state)
{
    int ret;
    int out;
    int delim = 0;
    int last =  0;
    int records;
    char *buf;
    jsmntok_t *t;

    ret = flb_json_tokenise(js, len, state);
    state->multiple = FLB_TRUE;
    if (ret == FLB_ERR_JSON_PART && state->multiple == FLB_TRUE) {
        /*
         * If the caller enabled 'multiple' flag, it means that the incoming
         * JSON message may have multiple messages concatenated and likely
         * the last one is only incomplete.
         *
         * The following routine aims to determinate how many JSON messages
         * are OK in the array of tokens, if any, process them and adjust
         * the JSMN context/buffers.
         */

        /*
         * jsmn_parse updates jsmn_parser members. (state->parser)
         * A member 'toknext' points next incomplete object token.
         * We use toknext - 1 as an index of last member of complete JSON.
         */
        int i;
        int found = 0;

        if (state->parser.toknext == 0) {
            return ret;
        }

        for (i = (int)state->parser.toknext - 1; i >= 1; i--) {
            t = &state->tokens[i];

            if (t->parent == -1 && (t->end != 0)) {
                found++;
                delim = i;
                break;
            }
        }

        if (found == 0) {
            return ret; /* FLB_ERR_JSON_PART */
        }
        state->tokens_count += delim;
    }
    else if (ret != 0) {
        return ret;
    }

    if (state->tokens_count == 0 || state->tokens == NULL) {
        state->last_byte = last;
        return FLB_ERR_JSON_INVAL;
    }

    buf = tokens_to_msgpack(state, js, &out, &last, &records);
    if (!buf) {
        return -1;
    }

    *size = out;
    *buffer = buf;
    state->last_byte = last;

    return 0;
}

int flb_metadata_pop_from_msgpack(msgpack_object **metadata, msgpack_unpacked *upk,
                                  msgpack_object **map)
{
    if (metadata == NULL || upk == NULL) {
        return -1;
    }

    if (upk->data.type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    *metadata = &upk->data.via.array.ptr[0].via.array.ptr[1];
    *map = &upk->data.via.array.ptr[1];

    return 0;
}

static int pack_print_fluent_record(size_t cnt, msgpack_unpacked result)
{
    msgpack_object  *metadata;
    msgpack_object   root;
    msgpack_object  *obj;
    struct flb_time  tms;
    msgpack_object   o;

    root = result.data;
    if (root.type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    o = root.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_ARRAY) {
        return -1;
    }

    /* decode expected timestamp only (integer, float or ext) */
    o = o.via.array.ptr[0];
    if (o.type != MSGPACK_OBJECT_POSITIVE_INTEGER &&
        o.type != MSGPACK_OBJECT_FLOAT &&
        o.type != MSGPACK_OBJECT_EXT) {
        return -1;
    }

    /* This is a Fluent Bit record, just do the proper unpacking/printing */
    flb_time_pop_from_msgpack(&tms, &result, &obj);
    flb_metadata_pop_from_msgpack(&metadata, &result, &obj);

    fprintf(stdout, "[%zd] [[%"PRId32".%09lu, ", cnt, (int32_t) tms.tm.tv_sec, tms.tm.tv_nsec);

    msgpack_object_print(stdout, *metadata);

    fprintf(stdout, "], ");

    msgpack_object_print(stdout, *obj);

    fprintf(stdout, "]\n");

    return 0;
}

void flb_pack_print(const char *data, size_t bytes)
{
    int ret;
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        /* Check if we are processing an internal Fluent Bit record */
        ret = pack_print_fluent_record(cnt, result);
        if (ret == 0) {
            continue;
        }

        printf("[%zd] ", cnt++);
        msgpack_object_print(stdout, result.data);
        printf("\n");
    }
    msgpack_unpacked_destroy(&result);
}

void flb_pack_print_metrics(const char *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        flb_error("could not process metrics payload");
        return;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);

    /* destroy cmt context */
    cmt_destroy(cmt);

    printf("%s", text);
    fflush(stdout);

    cmt_encode_text_destroy(text);
}

static inline int try_to_write(char *buf, int *off, size_t left,
                               const char *str, size_t str_len)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        return FLB_FALSE;
    }
    memcpy(buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}


/*
 * Check if a key exists in the map using the 'offset' as an index to define
 * which element needs to start looking from
 */
static inline int key_exists_in_map(msgpack_object key, msgpack_object map, int offset)
{
    int i;
    msgpack_object p;

    if (key.type != MSGPACK_OBJECT_STR) {
        return FLB_FALSE;
    }

    for (i = offset; i < map.via.map.size; i++) {
        p = map.via.map.ptr[i].key;
        if (p.type != MSGPACK_OBJECT_STR) {
            continue;
        }

        if (key.via.str.size != p.via.str.size) {
            continue;
        }

        if (memcmp(key.via.str.ptr, p.via.str.ptr, p.via.str.size) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int msgpack2json(char *buf, int *off, size_t left,
                        const msgpack_object *o)
{
    int i;
    int dup;
    int ret = FLB_FALSE;
    int loop;
    int packed;

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        ret = try_to_write(buf, off, left, "null", 4);
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        ret = try_to_write(buf, off, left,
                           (o->via.boolean ? "true":"false"),0);

        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            char temp[32] = {0};
            i = snprintf(temp, sizeof(temp)-1, "%"PRIu64, o->via.u64);
            ret = try_to_write(buf, off, left, temp, i);
        }
        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            char temp[32] = {0};
            i = snprintf(temp, sizeof(temp)-1, "%"PRId64, o->via.i64);
            ret = try_to_write(buf, off, left, temp, i);
        }
        break;
    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        {
            char temp[512] = {0};
            if (o->via.f64 == (double)(long long int)o->via.f64) {
                i = snprintf(temp, sizeof(temp)-1, "%.1f", o->via.f64);
            }
            else if (convert_nan_to_null && isnan(o->via.f64) ) {
                i = snprintf(temp, sizeof(temp)-1, "null");
            }
            else {
                i = snprintf(temp, sizeof(temp)-1, "%.16g", o->via.f64);
            }
            ret = try_to_write(buf, off, left, temp, i);
        }
        break;

    case MSGPACK_OBJECT_STR:
        if (try_to_write(buf, off, left, "\"", 1) &&
            (o->via.str.size > 0 ?
             try_to_write_str(buf, off, left, o->via.str.ptr, o->via.str.size)
             : 1/* nothing to do */) &&
            try_to_write(buf, off, left, "\"", 1)) {
            ret = FLB_TRUE;
        }
        break;

    case MSGPACK_OBJECT_BIN:
        if (try_to_write(buf, off, left, "\"", 1) &&
            (o->via.bin.size > 0 ?
             try_to_write_str(buf, off, left, o->via.bin.ptr, o->via.bin.size)
              : 1 /* nothing to do */) &&
            try_to_write(buf, off, left, "\"", 1)) {
            ret = FLB_TRUE;
        }
        break;

    case MSGPACK_OBJECT_EXT:
        if (!try_to_write(buf, off, left, "\"", 1)) {
            goto msg2json_end;
        }
        /* ext body. fortmat is similar to printf(1) */
        {
            char temp[32] = {0};
            int  len;
            loop = o->via.ext.size;
            for(i=0; i<loop; i++) {
                len = snprintf(temp, sizeof(temp)-1, "\\x%02x", (char)o->via.ext.ptr[i]);
                if (!try_to_write(buf, off, left, temp, len)) {
                    goto msg2json_end;
                }
            }
        }
        if (!try_to_write(buf, off, left, "\"", 1)) {
            goto msg2json_end;
        }
        ret = FLB_TRUE;
        break;

    case MSGPACK_OBJECT_ARRAY:
        loop = o->via.array.size;

        if (!try_to_write(buf, off, left, "[", 1)) {
            goto msg2json_end;
        }
        if (loop != 0) {
            msgpack_object* p = o->via.array.ptr;
            if (!msgpack2json(buf, off, left, p)) {
                goto msg2json_end;
            }
            for (i=1; i<loop; i++) {
                if (!try_to_write(buf, off, left, ",", 1) ||
                    !msgpack2json(buf, off, left, p+i)) {
                    goto msg2json_end;
                }
            }
        }

        ret = try_to_write(buf, off, left, "]", 1);
        break;

    case MSGPACK_OBJECT_MAP:
        loop = o->via.map.size;
        if (!try_to_write(buf, off, left, "{", 1)) {
            goto msg2json_end;
        }
        if (loop != 0) {
            msgpack_object k;
            msgpack_object_kv *p = o->via.map.ptr;

            packed = 0;
            dup = FLB_FALSE;

            k = o->via.map.ptr[0].key;
            for (i = 0; i < loop; i++) {
                k = o->via.map.ptr[i].key;
                dup = key_exists_in_map(k, *o, i + 1);
                if (dup == FLB_TRUE) {
                    continue;
                }

                if (packed > 0) {
                    if (!try_to_write(buf, off, left, ",", 1)) {
                        goto msg2json_end;
                    }
                }

                if (
                    !msgpack2json(buf, off, left, &(p+i)->key) ||
                    !try_to_write(buf, off, left, ":", 1)  ||
                    !msgpack2json(buf, off, left, &(p+i)->val) ) {
                    goto msg2json_end;
                }
                packed++;
            }
        }

        ret = try_to_write(buf, off, left, "}", 1);
        break;

    default:
        flb_warn("[%s] unknown msgpack type %i", __FUNCTION__, o->type);
    }

 msg2json_end:
    return ret;
}

/**
 *  convert msgpack to JSON string.
 *  This API is similar to snprintf.
 *
 *  @param  json_str  The buffer to fill JSON string.
 *  @param  json_size The size of json_str.
 *  @param  data      The msgpack_unpacked data.
 *  @return success   ? a number characters filled : negative value
 */
int flb_msgpack_to_json(char *json_str, size_t json_size,
                        const msgpack_object *obj)
{
    int ret = -1;
    int off = 0;

    if (json_str == NULL || obj == NULL) {
        return -1;
    }

    ret = msgpack2json(json_str, &off, json_size - 1, obj);
    json_str[off] = '\0';
    return ret ? off: ret;
}

flb_sds_t flb_msgpack_raw_to_json_sds(const void *in_buf, size_t in_size)
{
    int ret;
    size_t off = 0;
    size_t out_size;
    size_t realloc_size;

    msgpack_unpacked result;
    msgpack_object *root;
    flb_sds_t out_buf;
    flb_sds_t tmp_buf;

    /* buffer size strategy */
    out_size = in_size * FLB_MSGPACK_TO_JSON_INIT_BUFFER_SIZE;
    realloc_size = in_size * FLB_MSGPACK_TO_JSON_REALLOC_BUFFER_SIZE;
    if (realloc_size < 256) {
        realloc_size = 256;
    }

    out_buf = flb_sds_create_size(out_size);
    if (!out_buf) {
        flb_errno();
        return NULL;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, in_buf, in_size, &off);
    if (ret != MSGPACK_UNPACK_SUCCESS) {
        flb_sds_destroy(out_buf);
        msgpack_unpacked_destroy(&result);
        return NULL;
    }

    root = &result.data;
    while (1) {
        ret = flb_msgpack_to_json(out_buf, out_size, root);
        if (ret <= 0) {
            realloc_size *= 2;
            tmp_buf = flb_sds_increase(out_buf, realloc_size);
            if (tmp_buf) {
                out_buf = tmp_buf;
                out_size = flb_sds_alloc(out_buf);
            }
            else {
                flb_errno();
                flb_sds_destroy(out_buf);
                msgpack_unpacked_destroy(&result);
                return NULL;
            }
        }
        else {
            break;
        }
    }

    msgpack_unpacked_destroy(&result);
    flb_sds_len_set(out_buf, ret);

    return out_buf;
}

/*
 * Given a 'format' string type, return it integer representation. This
 * is used by output plugins that uses pack functions to convert
 * msgpack records to JSON.
 */
int flb_pack_to_json_format_type(const char *str)
{
    if (strcasecmp(str, "msgpack") == 0) {
        return FLB_PACK_JSON_FORMAT_NONE;
    }
    else if (strcasecmp(str, "json") == 0) {
        return FLB_PACK_JSON_FORMAT_JSON;
    }
    else if (strcasecmp(str, "json_stream") == 0) {
        return FLB_PACK_JSON_FORMAT_STREAM;
    }
    else if (strcasecmp(str, "json_lines") == 0) {
        return FLB_PACK_JSON_FORMAT_LINES;
    }

    return -1;
}

/* Given a 'date string type', return it integer representation */
int flb_pack_to_json_date_type(const char *str)
{
    if (strcasecmp(str, "double") == 0) {
        return FLB_PACK_JSON_DATE_DOUBLE;
    }
    else if (strcasecmp(str, "java_sql_timestamp") == 0) {
        return FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP;
    }
    else if (strcasecmp(str, "iso8601") == 0) {
        return FLB_PACK_JSON_DATE_ISO8601;
    }
    else if (strcasecmp(str, "epoch") == 0) {
        return FLB_PACK_JSON_DATE_EPOCH;
    }
    else if (strcasecmp(str, "epoch_ms") == 0 ||
             strcasecmp(str, "epoch_millis") == 0 ||
             strcasecmp(str, "epoch_milliseconds") == 0) {
        return FLB_PACK_JSON_DATE_EPOCH_MS;
    }

    return -1;
}


static int msgpack_pack_formatted_datetime(flb_sds_t out_buf, char time_formatted[], int max_len,
                                           msgpack_packer* tmp_pck, struct flb_time* tms,
                                           const char *date_format,
                                           const char *time_format)
{
    int len;
    size_t s;
    struct tm tm;

    gmtime_r(&tms->tm.tv_sec, &tm);

    s = strftime(time_formatted, max_len,
                 date_format, &tm);
    if (!s) {
        flb_debug("strftime failed in flb_pack_msgpack_to_json_format");
        return 1;
    }

    /* Format the time, use microsecond precision not nanoseconds */
    max_len -= s;
    len = snprintf(&time_formatted[s],
                    max_len,
                    time_format,
                    (uint64_t) tms->tm.tv_nsec / 1000);
    if (len >= max_len) {
        flb_debug("snprintf: %d >= %d in flb_pack_msgpack_to_json_format", len, max_len);
        return 2;
    }
    s += len;
    msgpack_pack_str(tmp_pck, s);
    msgpack_pack_str_body(tmp_pck, time_formatted, s);
    return 0;
}

flb_sds_t flb_pack_msgpack_to_json_format(const char *data, uint64_t bytes,
                                          int json_format, int date_format,
                                          flb_sds_t date_key)
{
    int i;
    int ret;
    char time_formatted[38];
    flb_sds_t out_tmp;
    flb_sds_t out_js;
    flb_sds_t out_buf = NULL;
    msgpack_sbuffer tmp_sbuf;
    msgpack_packer tmp_pck;
    msgpack_object *k;
    msgpack_object *v;
    struct flb_time tms;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct flb_mp_map_header mh_array;
    struct flb_mp_map_header mh_map;
    struct flb_mp_map_header mh_internal;

    /* For json lines and streams mode we need a pre-allocated buffer */
    if (json_format == FLB_PACK_JSON_FORMAT_LINES ||
        json_format == FLB_PACK_JSON_FORMAT_STREAM) {
        out_buf = flb_sds_create_size(bytes + bytes / 4);
        if (!out_buf) {
            flb_errno();
            return NULL;
        }
    }

    /* Create temporary msgpack buffer */
    msgpack_sbuffer_init(&tmp_sbuf);
    msgpack_packer_init(&tmp_pck, &tmp_sbuf, msgpack_sbuffer_write);

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("Log event decoder initialization error : %d", ret);
        if (out_buf) {
            flb_sds_destroy(out_buf);
        }
        return NULL;
    }

    /*
     * If the format is the original msgpack style of one big array,
     * registrate the array, otherwise is not necessary. FYI, original format:
     *
     * [
     *   [timestamp, map],
     *   [timestamp, map],
     *   [T, M]...
     * ]
     */
    if (json_format == FLB_PACK_JSON_FORMAT_JSON) {
        /* register the array. Note must be finalized with flb_mp_map_header_end() */
        flb_mp_array_header_init(&mh_array, &tmp_pck);
    }

    /* Iterate log records */
    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        if (json_format == FLB_PACK_JSON_FORMAT_JSON) {
            /* register a new entry for the array entry */
            flb_mp_array_header_append(&mh_array);
        }
        tms = log_event.timestamp;

        /* initialize the map for the record key/values */
        flb_mp_map_header_init(&mh_map, &tmp_pck);

        /* date key */
        if (date_key != NULL) {
            flb_mp_array_header_append(&mh_map);

            /* Append date key */
            msgpack_pack_str(&tmp_pck, flb_sds_len(date_key));
            msgpack_pack_str_body(&tmp_pck, date_key, flb_sds_len(date_key));

            /* Append date value */
            switch (date_format) {
            case FLB_PACK_JSON_DATE_DOUBLE:
                msgpack_pack_double(&tmp_pck, flb_time_to_double(&tms));
                break;
            case FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP:
                if (msgpack_pack_formatted_datetime(out_buf, time_formatted, sizeof(time_formatted), &tmp_pck, &tms,
                                                    FLB_PACK_JSON_DATE_JAVA_SQL_TIMESTAMP_FMT, ".%06" PRIu64)) {
                    flb_sds_destroy(out_buf);
                    msgpack_sbuffer_destroy(&tmp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return NULL;
                }
                break;
            case FLB_PACK_JSON_DATE_ISO8601:
                if (msgpack_pack_formatted_datetime(out_buf, time_formatted, sizeof(time_formatted), &tmp_pck, &tms,
                                                    FLB_PACK_JSON_DATE_ISO8601_FMT, ".%06" PRIu64 "Z")) {
                    flb_sds_destroy(out_buf);
                    msgpack_sbuffer_destroy(&tmp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return NULL;
                }
                break;
            case FLB_PACK_JSON_DATE_EPOCH:
                msgpack_pack_uint64(&tmp_pck, (long long unsigned)(tms.tm.tv_sec));
                break;
            case FLB_PACK_JSON_DATE_EPOCH_MS:
                msgpack_pack_uint64(&tmp_pck, flb_time_to_millisec(&tms));
                break;
            }
        }

        /* register __internal__ data that comes from the group information */
        if ((log_event.group_attributes && log_event.group_attributes->type == MSGPACK_OBJECT_MAP && log_event.group_attributes->via.map.size > 0) ||
            (log_event.metadata && log_event.metadata->type == MSGPACK_OBJECT_MAP && log_event.metadata->via.map.size > 0)) {

            flb_mp_map_header_append(&mh_map);
            msgpack_pack_str(&tmp_pck, 12);
            msgpack_pack_str_body(&tmp_pck, "__internal__", 12);

            flb_mp_map_header_init(&mh_internal, &tmp_pck);

            /*
             * group metadata: the JSON export of this record do not aim to be re-assembled into a Fluent pipeline,
             * actually it is a generic JSON representation of the log record. For this reason, we need to add the group
             * metadata to the JSON output.
             *
             * Just leaving this code commented as a reference...
             */

            /*
             * if (log_event.group_metadata != NULL) {
             *    flb_mp_map_header_append(&mh_internal);
             *    msgpack_pack_str(&tmp_pck, 14);
             *    msgpack_pack_str_body(&tmp_pck, "group_metadata", 14);
             *    msgpack_pack_object(&tmp_pck, *log_event.group_metadata);
             * }
             */

            /* Append group attributes */
            if (log_event.group_attributes != NULL) {
                flb_mp_map_header_append(&mh_internal);
                msgpack_pack_str(&tmp_pck, 16);
                msgpack_pack_str_body(&tmp_pck, "group_attributes", 16);
                msgpack_pack_object(&tmp_pck, *log_event.group_attributes);
            }

            /* log/record metadata if exists */
            if (log_event.metadata != NULL) {
                flb_mp_map_header_append(&mh_internal);
                msgpack_pack_str(&tmp_pck, 12);
                msgpack_pack_str_body(&tmp_pck, "log_metadata", 12);
                msgpack_pack_object(&tmp_pck, *log_event.metadata);
            }

            /* finalize the internal map */
            flb_mp_map_header_end(&mh_internal);
        }

        /* Append keys/values from the log body */
        if (log_event.body != NULL) {
            if (log_event.body->type == MSGPACK_OBJECT_MAP) {
                for (i = 0; i < log_event.body->via.map.size; i++) {
                    flb_mp_map_header_append(&mh_map);
                    k = &log_event.body->via.map.ptr[i].key;
                    v = &log_event.body->via.map.ptr[i].val;

                    /* Append key/value */
                    msgpack_pack_object(&tmp_pck, *k);
                    msgpack_pack_object(&tmp_pck, *v);
                }

                flb_mp_map_header_end(&mh_map);
            }
            else {
                /* for any other data type, nest the content inside log */
                flb_mp_map_header_append(&mh_map);
                msgpack_pack_str(&tmp_pck, 4);
                msgpack_pack_str_body(&tmp_pck, "log", 3);
                msgpack_pack_object(&tmp_pck, *log_event.body);

                flb_mp_map_header_end(&mh_map);
            }
        }

        /*
         * If the format is the original msgpack style, just continue since
         * we don't care about separator or JSON convertion at this point.
         */
        if (json_format == FLB_PACK_JSON_FORMAT_JSON) {
            continue;
        }

        /*
         * Here we handle two types of records concatenation:
         *
         * FLB_PACK_JSON_FORMAT_LINES: add  breakline (\n) after each record
         *
         *
         *     {'ts':abc,'k1':1}
         *     {'ts':abc,'k1':2}
         *     {N}
         *
         * FLB_PACK_JSON_FORMAT_STREAM: no separators, e.g:
         *
         *     {'ts':abc,'k1':1}{'ts':abc,'k1':2}{N}
         */
        if (json_format == FLB_PACK_JSON_FORMAT_LINES ||
            json_format == FLB_PACK_JSON_FORMAT_STREAM) {

            /* Encode current record into JSON in a temporary variable */
            out_js = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size);
            if (!out_js) {
                flb_sds_destroy(out_buf);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                flb_log_event_decoder_destroy(&log_decoder);
                return NULL;
            }

            /*
             * One map record has been converted, now append it to the
             * outgoing out_buf sds variable.
             */
            out_tmp = flb_sds_cat(out_buf, out_js, flb_sds_len(out_js));
            if (!out_tmp) {
                flb_sds_destroy(out_js);
                flb_sds_destroy(out_buf);
                msgpack_sbuffer_destroy(&tmp_sbuf);
                flb_log_event_decoder_destroy(&log_decoder);
                return NULL;
            }

            /* Release temporary json sds buffer */
            flb_sds_destroy(out_js);

            /* If a realloc happened, check the returned address */
            if (out_tmp != out_buf) {
                out_buf = out_tmp;
            }

            /* Append the breakline only for json lines mode */
            if (json_format == FLB_PACK_JSON_FORMAT_LINES) {
                out_tmp = flb_sds_cat(out_buf, "\n", 1);
                if (!out_tmp) {
                    flb_sds_destroy(out_buf);
                    msgpack_sbuffer_destroy(&tmp_sbuf);
                    flb_log_event_decoder_destroy(&log_decoder);
                    return NULL;
                }
                if (out_tmp != out_buf) {
                    out_buf = out_tmp;
                }
            }
            msgpack_sbuffer_clear(&tmp_sbuf);
        }
    }

    /* destroy the decoder */
    flb_log_event_decoder_destroy(&log_decoder);

    /* finalize the main array */
    if (json_format == FLB_PACK_JSON_FORMAT_JSON) {
        flb_mp_array_header_end(&mh_array);
    }

    /* Format to JSON */
    if (json_format == FLB_PACK_JSON_FORMAT_JSON) {
        out_buf = flb_msgpack_raw_to_json_sds(tmp_sbuf.data, tmp_sbuf.size);
        msgpack_sbuffer_destroy(&tmp_sbuf);
        if (!out_buf) {
            return NULL;
        }
    }
    else {
        msgpack_sbuffer_destroy(&tmp_sbuf);
    }

    if (out_buf && flb_sds_len(out_buf) == 0) {
        flb_sds_destroy(out_buf);
        return NULL;
    }

    return out_buf;
}

/**
 *  convert msgpack to JSON string.
 *  This API is similar to snprintf.
 *  @param  size     Estimated length of json str.
 *  @param  data     The msgpack_unpacked data.
 *  @return success  ? allocated json str ptr : NULL
 */
char *flb_msgpack_to_json_str(size_t size, const msgpack_object *obj)
{
    int ret;
    char *buf = NULL;
    char *tmp;

    if (obj == NULL) {
        return NULL;
    }

    if (size <= 0) {
        size = 128;
    }

    buf = flb_malloc(size);
    if (!buf) {
        flb_errno();
        return NULL;
    }

    while (1) {
        ret = flb_msgpack_to_json(buf, size, obj);
        if (ret <= 0) {
            /* buffer is small. retry.*/
            size *= 2;
            tmp = flb_realloc(buf, size);
            if (tmp) {
                buf = tmp;
            }
            else {
                flb_free(buf);
                flb_errno();
                return NULL;
            }
        }
        else {
            break;
        }
    }

    return buf;
}

int flb_pack_time_now(msgpack_packer *pck)
{
    int ret;
    struct flb_time t;

    flb_time_get(&t);
    ret = flb_time_append_to_msgpack(&t, pck, 0);

    return ret;
}

int flb_msgpack_expand_map(char *map_data, size_t map_size,
                           msgpack_object_kv **kv_arr, int kv_arr_len,
                           char** out_buf, int* out_size)
{
    msgpack_sbuffer sbuf;
    msgpack_packer  pck;
    msgpack_unpacked result;
    size_t off = 0;
    char *ret_buf;
    int map_num;
    int i;
    int len;

    if (map_data == NULL){
        return -1;
    }

    msgpack_unpacked_init(&result);
    if ((i=msgpack_unpack_next(&result, map_data, map_size, &off)) !=
        MSGPACK_UNPACK_SUCCESS ) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }
    if (result.data.type != MSGPACK_OBJECT_MAP) {
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    len = result.data.via.map.size;
    map_num = kv_arr_len + len;

    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);
    msgpack_pack_map(&pck, map_num);

    for (i=0; i<len; i++) {
        msgpack_pack_object(&pck, result.data.via.map.ptr[i].key);
        msgpack_pack_object(&pck, result.data.via.map.ptr[i].val);
    }
    for (i=0; i<kv_arr_len; i++){
        msgpack_pack_object(&pck, kv_arr[i]->key);
        msgpack_pack_object(&pck, kv_arr[i]->val);
    }
    msgpack_unpacked_destroy(&result);

    *out_size = sbuf.size;
    ret_buf  = flb_malloc(sbuf.size);
    *out_buf = ret_buf;
    if (*out_buf == NULL) {
        flb_errno();
        msgpack_sbuffer_destroy(&sbuf);
        return -1;
    }
    memcpy(*out_buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

    return 0;
}

int flb_pack_init(struct flb_config *config)
{
    int ret;

    if (config == NULL) {
        return -1;
    }
    ret = flb_pack_set_null_as_nan(config->convert_nan_to_null);

    return ret;
}
