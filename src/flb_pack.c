/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_info.h>

#include <msgpack.h>
#include <jsmn/jsmn.h>

static int json_tokenise(char *js, size_t len,
                         struct flb_pack_state *state)
{
    int ret;
    int n;
    void *tmp;

    ret = jsmn_parse(&state->parser, js, len,
                     state->tokens, state->tokens_size);

    while (ret == JSMN_ERROR_NOMEM) {
        n = state->tokens_size += 256;
        tmp = flb_realloc(state->tokens, sizeof(jsmntok_t) * n);
        if (!tmp) {
            perror("realloc");
            return -1;
        }
        state->tokens = tmp;
        state->tokens_size = n;
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

static inline int is_float(char *buf, int len)
{
    char *end = buf + len;
    char *p = buf;

    while (p <= end) {
        if (*p == '.') {
            return 1;
        }
        p++;
    }
    return 0;
}

/* Receive a tokenized JSON message and convert it to MsgPack */
static char *tokens_to_msgpack(char *js,
                               jsmntok_t *tokens, int arr_size, int *out_size)
{
    int i;
    int flen;
    char *p;
    char *buf;
    jsmntok_t *t;
    msgpack_packer pck;
    msgpack_sbuffer sbuf;

    /* initialize buffers */
    msgpack_sbuffer_init(&sbuf);
    msgpack_packer_init(&pck, &sbuf, msgpack_sbuffer_write);

    for (i = 0; i < arr_size ; i++) {
        t = &tokens[i];

        if (t->start == -1 || t->end == -1 || (t->start == 0 && t->end == 0)) {
            break;
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
            msgpack_pack_str(&pck, flen);
            msgpack_pack_str_body(&pck, js + t->start, flen);
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
                if (is_float(p, flen)) {
                    msgpack_pack_double(&pck, atof(p));
                }
                else {
                    msgpack_pack_int64(&pck, atol(p));
                }
            }
            break;
        case JSMN_UNDEFINED:
            msgpack_sbuffer_destroy(&sbuf);
            return NULL;
        }
    }

    /* dump data back to a new buffer */
    *out_size = sbuf.size;
    buf = flb_malloc(sbuf.size);
    memcpy(buf, sbuf.data, sbuf.size);
    msgpack_sbuffer_destroy(&sbuf);

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
int flb_pack_json(char *js, size_t len, char **buffer, int *size)
{
    int ret;
    int out;
    char *buf;
    struct flb_pack_state state;

    ret = flb_pack_state_init(&state);
    if (ret != 0) {
        return -1;
    }
    ret = json_tokenise(js, len, &state);
    if (ret != 0) {
        goto flb_pack_json_end;
    }

    buf = tokens_to_msgpack(js, state.tokens, state.tokens_count, &out);
    if (!buf) {
        ret = -1;
        goto flb_pack_json_end;
    }

    *size = out;
    *buffer = buf;

    ret = 0;
 flb_pack_json_end:
    flb_pack_state_reset(&state);
    return ret;
}

/* Initialize a JSON packer state */
int flb_pack_state_init(struct flb_pack_state *s)
{
    int size = 256;

    jsmn_init(&s->parser);
    s->tokens = flb_calloc(1, sizeof(jsmntok_t) * size);
    if (!s->tokens) {
        perror("calloc");
        return -1;
    }
    s->tokens_size  = size;
    s->tokens_count = 0;

    return 0;
}

void flb_pack_state_reset(struct flb_pack_state *s)
{
    flb_free(s->tokens);
    s->tokens_size  = 0;
    s->tokens_count = 0;
}


/*
 * It parse a JSON string and convert it to MessagePack format. The main
 * difference of this function and the previous flb_pack_json() is that it
 * keeps a parser and tokens state, allowing to process big messages and
 * resume the parsing process instead of start from zero.
 */
int flb_pack_json_state(char *js, size_t len,
                        char **buffer, int *size,
                        struct flb_pack_state *state)
{
    int ret;
    int out;
    int delim = 0;
    char *buf;
    jsmntok_t *t;

    ret = json_tokenise(js, len, state);
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
        int i;
        int found = 0;

        for (i = 1; i < state->tokens_size; i++) {
            t = &state->tokens[i];
            if (t->start < (state->tokens[i - 1]).start) {
                break;
            }

            if (t->parent == -1 && (t->end != 0)) {
                found++;
                delim = i;
            }
        }

        if (found > 0) {
            state->tokens_count += delim;
        }
        else {
            return ret;
        }
    }
    else if (ret != 0) {
        return ret;
    }

    buf = tokens_to_msgpack(js, state->tokens, state->tokens_count, &out);
    if (!buf) {
        return -1;
    }

    *size = out;
    *buffer = buf;

    return 0;
}

void flb_pack_print(char *data, size_t bytes)
{
    msgpack_unpacked result;
    size_t off = 0, cnt = 0;

    msgpack_unpacked_init(&result);
    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        printf("[%zd] ", cnt++);
        msgpack_object_print(stdout, result.data);
        printf("\n");
    }
    msgpack_unpacked_destroy(&result);
}

#define MSGPACK2JSON_LIST_UNIT 4096

static int try_to_write(char **buf, int *off, size_t left,
                               char *str, size_t str_len,
                               struct mk_list *list)
{
    if (str_len <= 0){
        str_len = strlen(str);
    }
    if (left <= *off+str_len) {
        if (list == NULL) {
            return FLB_FALSE;
        }
        else {
            char *tmp = (char*)flb_malloc(MSGPACK2JSON_LIST_UNIT);
            char *buf_ptr = *buf;
            struct flb_pack_json_str *jstr =(struct flb_pack_json_str*)
                flb_malloc(sizeof(struct flb_pack_json_str));
            if (tmp == NULL || jstr == NULL) {
                flb_free(tmp);
                flb_free(jstr);
                return FLB_FALSE;
            }
            jstr->buf = tmp;
            mk_list_add(&jstr->_head, list);

            buf_ptr[*off] = '\0';
            *buf = tmp;
            *off = 0;
        }
    }
    memcpy(*buf+*off, str, str_len);
    *off += str_len;
    return FLB_TRUE;
}

static int msgpack2json(char **buf, int *off, size_t left, msgpack_object *o,
                        struct mk_list *str_list)
{
    int ret = FLB_FALSE;
    int i;
    int loop;

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        ret = try_to_write(buf, off, left, "null", 4, str_list);
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        ret = try_to_write(buf, off, left,
                           (o->via.boolean ? "true ":"false"),5,
                           str_list);

        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        {
            char temp[32] = {0};
            i = snprintf(temp, sizeof(temp)-1, "%lu", (unsigned long)o->via.u64);
            ret = try_to_write(buf, off, left, temp, i, str_list);
        }
        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        {
            char temp[32] = {0};
            i = snprintf(temp, sizeof(temp)-1, "%ld", (signed long)o->via.i64);
            ret = try_to_write(buf, off, left, temp, i, str_list);
        }
        break;

    case MSGPACK_OBJECT_FLOAT:
        {
            char temp[32] = {0};
            i = snprintf(temp, sizeof(temp)-1, "%f", o->via.f64);
            ret = try_to_write(buf, off, left, temp, i, str_list);
        }
        break;

    case MSGPACK_OBJECT_STR:
        if (try_to_write(buf, off, left, "\"", 1, str_list) &&
            try_to_write(buf, off, left, (char*)o->via.str.ptr, o->via.str.size,
                         str_list) &&
            try_to_write(buf, off, left, "\"", 1, str_list)) {
            ret = FLB_TRUE;
        }
        break;

    case MSGPACK_OBJECT_BIN:
        if (try_to_write(buf, off, left, "\"", 1, str_list) &&
            try_to_write(buf, off, left, (char*)o->via.bin.ptr, o->via.bin.size,
                         str_list) &&
            try_to_write(buf, off, left, "\"", 1, str_list)) {
            ret = FLB_TRUE;
        }
        break;

    case MSGPACK_OBJECT_ARRAY:
        loop = o->via.array.size;

        if (!try_to_write(buf, off, left, "[", 1, str_list)) {
            goto msg2json_end;
        }
        if (loop != 0) {
            msgpack_object* p = o->via.array.ptr;
            if (!msgpack2json(buf, off, left, p, str_list)) {
                goto msg2json_end;
            }
            for (i=1; i<loop; i++) {
                if (!try_to_write(buf, off, left, ", ", 2, str_list) ||
                    !msgpack2json(buf, off, left, p+i, str_list)) {
                    goto msg2json_end;
                }
            }
        }

        ret = try_to_write(buf, off, left, "]", 1, str_list);
        break;

    case MSGPACK_OBJECT_MAP:
        loop = o->via.map.size;
        if (!try_to_write(buf, off, left, "{", 1, str_list)) {
            goto msg2json_end;
        }
        if (loop != 0) {
            msgpack_object_kv *p = o->via.map.ptr;
            if (!msgpack2json(buf, off, left, &p->key, str_list) ||
                !try_to_write(buf, off, left, ":", 1, str_list)  ||
                !msgpack2json(buf, off, left, &p->val, str_list)) {
                goto msg2json_end;
            }
            for (i = 1; i < loop; i++) {
                if (
                    !try_to_write(buf, off, left, ", ", 2, str_list) ||
                    !msgpack2json(buf, off, left, &(p+i)->key, str_list) ||
                    !try_to_write(buf, off, left, ":", 1, str_list)  ||
                    !msgpack2json(buf, off, left, &(p+i)->val, str_list) ) {
                    goto msg2json_end;

                }
            }
        }

        ret = try_to_write(buf, off, left, "}", 1, str_list);
        break;

    default:
        flb_warn("[%s] unknown type",__FUNCTION__);
    }

 msg2json_end:
    return ret;
}

/**
 *  convert msgpack to JSON string.
 *  This API is similar to snprintf.
 *
 *  @param  json_str The buffer to fill JSON string.
 *  @param  json_len The size of json_str.
 *  @param  data     The msgpack_unpacked data.
 *  @return success  ? a number characters filled : negative value
 */
int flb_msgpack_to_json(char *json_str, size_t str_len,
                        msgpack_unpacked *data)
{
    int ret = -1;
    int off = 0;

    if (json_str == NULL || data == NULL) {
        return -1;
    }

    ret = msgpack2json(&json_str, &off, str_len, &data->data, NULL);
    json_str[str_len-1] = '\0';
    return ret ? off: ret;
}


/**
 *  convert msgpack to JSON string.
 *  This API is similar to snprintf.
 *  @param  size     Estimated length of json str.
 *  @param  data     The msgpack_unpacked data.
 *  @return success  ? allocated json str ptr : NULL
 */
char *flb_msgpack_to_json_str(size_t size, msgpack_unpacked *data)
{
    char *buf = NULL;

    if (data == NULL) {
        return NULL;
    }
    if (size <= 0) {
        size = 128;
    }
    while(1) {
        buf = (char *)flb_malloc(size);
        if (buf == NULL) {
            flb_warn("[%s] can't allocate buffer");
            return NULL;
        }

        if (flb_msgpack_to_json(buf, size, data) < 0){
            /* buffer is small. retry.*/
            size += 128;
            flb_free(buf);
        }
        else {
            break;
        }
    }
    return buf;
}

int flb_msgpack_raw_to_json_str(char *buf, size_t buf_size,
                                char **out_buf, size_t *out_size)
{
    int ret;
    size_t off = 0;
    size_t json_size;
    char *json_buf;
    char *tmp;
    msgpack_unpacked result;

    if (!buf || buf_size <= 0) {
        return -1;
    }

    msgpack_unpacked_init(&result);
    ret = msgpack_unpack_next(&result, buf, buf_size, &off);
    if (ret == -1) {
        return -1;
    }

    json_size = (buf_size * 1.2);
    json_buf = flb_calloc(1, json_size);
    if (!json_buf) {
        flb_errno();
        msgpack_unpacked_destroy(&result);
        return -1;
    }

    while (1) {
        ret = flb_msgpack_to_json(json_buf, json_size, &result);
        if (ret <= 0) {
            json_size += 128;
            tmp = flb_realloc(json_buf, json_size);
            if (!tmp) {
                flb_errno();
                flb_free(json_buf);
                msgpack_unpacked_destroy(&result);
                return -1;
            }
            json_buf = tmp;
            continue;
        }
        break;
    }

    *out_buf = json_buf;
    *out_size = ret;

    msgpack_unpacked_destroy(&result);
    return 0;
}

/* 
   To generate large JSON string.
   This function returns a pointer of string list.
 */
struct mk_list* flb_msgpack_to_json_str_list(msgpack_unpacked *data)
{
    struct mk_list *list = NULL;
    struct flb_pack_json_str *jstr = NULL;
    char *buf = NULL;
    int off = 0;

    if (data == NULL) {
        return NULL;
    }
    
    list = (struct mk_list*)flb_malloc(sizeof(struct mk_list));
    jstr = (struct flb_pack_json_str*)
        flb_malloc(sizeof(struct flb_pack_json_str));
    buf = (char*)flb_malloc(MSGPACK2JSON_LIST_UNIT);

    if (list == NULL || jstr == NULL || buf == NULL) {
        flb_free(list);
        flb_free(jstr);
        flb_free(buf);
        return NULL;
    }

    mk_list_init(list);
    jstr->buf = buf;
    mk_list_add(&jstr->_head, list);

    msgpack2json(&buf, &off,MSGPACK2JSON_LIST_UNIT, &data->data, list);
    
    buf[off] = '\0';

    return list;
}
