/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2022 The Fluent Bit Authors
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
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_filter_plugin.h>
#include <fluent-bit/flb_csv.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_file.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <avro.h>
#include <jansson.h>
#include <sys/param.h>

#include "avro/basics.h"
#include "avro/errors.h"
#include "avro/io.h"
#include "avro/schema.h"
#include "avro/src/avro/errors.h"
#include "avro/src/avro/generic.h"
#include "avro/src/avro/io.h"
#include "avro/src/avro/value.h"
#include "avro/src/schema.h"
#include "avro/src/st.h"
#include "avro/value.h"
#include "filter_avro.h"
#include "fluent-bit/flb_config.h"
#include "fluent-bit/flb_mem.h"
#include "fluent-bit/flb_str.h"
#include "fluent-bit/flb_time.h"
#include "mpack/mpack.h"

struct avro_union_data {
    const char *field;
    size_t field_len;
    int discriminant;
    int type;
};

static void write_avro_field(void *data, const char *field, size_t field_len);

static int create_outer_avro_schema(struct filter_avro *ctx)
{
    avro_schema_t schema;
    avro_schema_t field, item;

    schema = avro_schema_record("LogEvent", NULL);

    field = avro_schema_bytes();
    if (avro_schema_record_field_append(schema, "metadata", field)) {
        return -1;
    }
    avro_schema_decref(field);

    field = avro_schema_string();
    if (avro_schema_record_field_append(schema, "avro_schema", field)) {
        return -1;
    }
    avro_schema_decref(field);

    field = avro_schema_int();
    if (avro_schema_record_field_append(schema, "max_size", field)) {
        return -1;
    }
    avro_schema_decref(field);

    item = avro_schema_bytes();
    field = avro_schema_array(item);
    if (avro_schema_record_field_append(schema, "payload", field)) {
        return -1;
    }

    avro_schema_decref(field);
    avro_schema_decref(item);

    ctx->outer_schema = schema;

    ctx->outer_class = avro_generic_class_from_schema(ctx->outer_schema);
    if (!ctx->outer_class) {
        return -1;
    }

    return 0;
}

static int cb_avro_init(struct flb_filter_instance *f_ins,
                       struct flb_config *config,
                       void *data)
{
    (void) data;
    struct filter_avro *ctx;

    /* Create context */
    ctx = flb_malloc(sizeof *ctx);
    if (!ctx) {
        flb_error("[filter_avro] filter cannot be loaded");
        return -1;
    }

    memset(ctx, 0, sizeof(*ctx));

    if (flb_filter_config_map_set(f_ins, (void*)ctx)) {
        flb_errno();
        flb_plg_error(f_ins, "configuration error");
        flb_free(ctx);
        return -1;
    }

    /* Set context */
    flb_filter_set_context(f_ins, ctx);
    ctx->ins = f_ins;

    ctx->packbuf = flb_sds_create_size(1024);
    if (!ctx->packbuf) {
        flb_error("[filter_avro] failed to allocate packbuf");
        return -1;
    }

    if (create_outer_avro_schema(ctx)) {
        flb_plg_error(ctx->ins, "failed to allocate avro outer schema");
        return -1;
    }

    ctx->avro_write_buffer_size = 1024;
    ctx->avro_write_buffer = flb_malloc(ctx->avro_write_buffer_size);
    if (!ctx->avro_write_buffer) {
        flb_plg_error(ctx->ins, "Unable to allocate avro write buffer");
        return -1;
    }

    ctx->awriter = avro_writer_memory(ctx->avro_write_buffer,
            ctx->avro_write_buffer_size);
    if (!ctx->awriter) {
        flb_plg_error(ctx->ins, "failed to allocate avro writer");
        return -1;
    }

    return 0;
}

static flb_sds_t read_schema(const char *csv_file)
{
    char fname[4096];
    char *ext;

    strncpy(fname, csv_file, sizeof(fname));

    ext = strrchr(fname, '.');
    if (!ext) {
        return NULL;
    }

    strncpy(ext, ".json", sizeof(fname) - (ext - fname));

    return flb_file_read(fname);
}

static struct filter_avro_tag_state *get_tag_state(
        struct filter_avro *ctx,
        const char *tag) {
    char *avro_schema_json;
    flb_sds_t json_root_str;
    json_t *json_root;
    json_t *schema_root;
    json_error_t json_error;
    int i;

    for (i = 0; i < FILTER_AVRO_MAX_TAG_COUNT; i++) {
        struct filter_avro_tag_state *state = ctx->states + i;
        if (state->used && !strcmp(state->tag, tag)) {
            return state;
        }
    }
    /* not found, initialize for first use */
    for (i = 0; i < FILTER_AVRO_MAX_TAG_COUNT; i++) {
        struct filter_avro_tag_state *state = ctx->states + i;
        if (!state->used) {
            state->ctx = ctx;
            /* read avro schema */
            json_root_str = read_schema(tag);

            if (!json_root_str) {
                flb_plg_error(ctx->ins,
                        "Cannot find schema file for \"%s\"", tag);
                return NULL;
            }

            json_root = json_loads(json_root_str, JSON_DECODE_ANY,
                    &json_error);
            if (!json_root) {
                flb_plg_error(ctx->ins,
                        "Unable to parse json schema:%s:error:%s:\n",
                        state->avro_schema_json,
                        json_error.text);
                return NULL;
            }

            flb_sds_destroy(json_root_str);
            schema_root = json_object_get(json_root, "avro_schema");
            if (!schema_root) {
                flb_plg_error(ctx->ins,
                        "Unable to find avro_schema key",
                        state->avro_schema_json);
                return NULL;
            }

            avro_schema_json = json_dumps(schema_root, JSON_ENCODE_ANY);
            state->avro_schema_json = flb_sds_create(avro_schema_json);
            if (!avro_schema_json || !state->avro_schema_json) {
                flb_plg_error(ctx->ins,
                        "To serialize avro_schema key");
                return NULL;
            }

            flb_free(avro_schema_json);
            json_decref(json_root);

            if (avro_schema_from_json_length(state->avro_schema_json,
                        flb_sds_len(state->avro_schema_json), &state->aschema)) {
                flb_plg_error(ctx->ins,
                        "Unable to parse aobject schema:%s:error:%s:\n",
                        state->avro_schema_json,
                        avro_strerror());
                return NULL;
            }

            state->aclass = avro_generic_class_from_schema(state->aschema);
            if (!state->aclass) {
                flb_plg_error(
                        ctx->ins,
                        "Unable to instantiate class from schema:%s:\n",
                        avro_strerror());
                return NULL;
            }

            if (avro_generic_value_new(state->aclass, &state->record)) {
                flb_plg_error(
                        ctx->ins,
                        "Unable to allocate new avro value:%s:\n", avro_strerror(),
                        avro_strerror());
                return NULL;
            }

            state->used = true;
            state->tag = flb_strdup(tag);
            state->row_buffer = flb_sds_create("");
            flb_csv_init(&state->state, write_avro_field, state);

            return state;
        }
    }

    return NULL;
}

static void mpack_buffer_flush(mpack_writer_t* writer, const char* buffer, size_t count)
{
    struct filter_avro *ctx = writer->context;
    flb_sds_cat_safe(&ctx->packbuf, buffer, count);
}

static int find_log_key(mpack_reader_t *reader, size_t key_count)
{
    size_t i;
    mpack_tag_t mtag;

    for (i = 0; i < key_count; i++) {
        mtag = mpack_read_tag(reader);
        if (mtag.type != mpack_type_str) {
            return FLB_FILTER_NOTOUCH;
        }

        if (mpack_tag_bytes(&mtag) != 3 || memcmp(reader->data, "log", 3)) {
            /* not the correct key, skip it */
            reader->data += mpack_tag_bytes(&mtag);
            /* also skip the value */
            mtag = mpack_read_tag(reader);
            reader->data += mpack_tag_bytes(&mtag);
            continue;
        }

        reader->data += mpack_tag_bytes(&mtag);
        return 0;
    }

    return FLB_FILTER_NOTOUCH;
}

static int collect_lines(
        struct filter_avro *ctx,
        struct filter_avro_tag_state *state,
        const char *data,
        size_t bytes)
{
    struct flb_time t;
    mpack_reader_t reader;
    mpack_tag_t mtag;
    size_t len;

    mpack_reader_init_data(&reader, data, bytes);

    while (bytes > 0) {
        const char *record_start = reader.data;
        size_t record_size = 0;

        if (flb_time_pop_from_mpack(&t, &reader)) {
            /* failed to parse */
            return FLB_FILTER_NOTOUCH;
        }

        mtag = mpack_read_tag(&reader);
        if (mtag.type != mpack_type_map) {
            /* failed to parse */
            return FLB_FILTER_NOTOUCH;
        }

        if (find_log_key(&reader, mpack_tag_map_count(&mtag))) {
            /* failed to parse */
            return FLB_FILTER_NOTOUCH;
        }

        mtag = mpack_read_tag(&reader);
        if (mtag.type != mpack_type_str) {
            /* failed to parse */
            return FLB_FILTER_NOTOUCH;
        }
        len = mpack_tag_bytes(&mtag);
        flb_sds_cat_safe(&state->row_buffer, reader.data, len);
        reader.data += len;
        flb_sds_cat_safe(&state->row_buffer, "\n", 1);
        record_size = reader.data - record_start;
        bytes -= record_size;
    }

    return 0;
}

static int extract_union_type_it(int i, avro_schema_t schema, void *arg)
{
    struct avro_union_data *data = arg;
    int type = avro_typeof(schema);

    switch (type) {
        case AVRO_NULL:
            if (!data->field_len) {
                data->discriminant = i;
                data->type = type;
            }
            break;
        default:
            if (data->field_len &&
                    (data->discriminant == -1 || type == AVRO_STRING)) {
                /* in the case of a union with more than 2 types,
                 * give preference to string if present, else use the
                 * first one */
                data->discriminant = i;
                data->type = type;
            }
            break;
    }

    return ST_CONTINUE;
}

static int extract_union_type(avro_value_t *value,
        const char *field, size_t field_len)
{
    struct avro_union_data data = {
        .field = field,
        .field_len = field_len,
        .discriminant = -1,
        .type = -1
    };
    avro_schema_t schema = avro_value_get_schema(value);
    struct avro_union_schema_t *uschema = avro_schema_to_union(schema);
    st_foreach(uschema->branches, HASH_FUNCTION_CAST extract_union_type_it,
            (st_data_t)&data);
    avro_value_set_branch(value, data.discriminant, value);
    return data.type;
}

static int extract_avro_type(avro_value_t *value,
        const char *field, size_t field_len)
{
    int type = avro_value_get_type(value);
    switch (type) {
        case AVRO_STRING:
        case AVRO_BYTES:
        case AVRO_BOOLEAN:
        case AVRO_INT32:
        case AVRO_INT64:
        case AVRO_FLOAT:
        case AVRO_FIXED:
        case AVRO_DOUBLE:
        case AVRO_NULL:
            return type;
        case AVRO_UNION:
            return extract_union_type(value, field, field_len);
        default:
            flb_error("unsupported avro type");
            return -1;
    }
}

static int parse_int64(const char *in, int64_t *out)
{
    char *end;
    int64_t val;

    errno = 0;
    val = strtol(in, &end, 10);
    if (end == in || *end != 0 || errno)  {
        return -1;
    }

    *out = val;
    return 0;
}

static int parse_double(const char *in, double *out)
{
    char *end;
    double val;
    errno = 0;
    val = strtod(in, &end);
    if (end == in || *end != 0 || errno) {
        return -1;
    }
    *out = val;
    return 0;
}

static void write_avro_int_value(const char *field, size_t field_len,
        avro_value_t *avalue)
{
    char buf[256];
    int64_t val;

    memcpy(buf, field, field_len);
    buf[field_len] = 0;
    parse_int64(buf, &val);

    switch (avro_value_get_type(avalue)) {
        case AVRO_INT32:
            avro_value_set_int(avalue, val);
            break;
        case AVRO_INT64:
            avro_value_set_long(avalue, val);
            break;
    }
}

static void write_avro_float_value(const char *field, size_t field_len,
        avro_value_t *avalue)
{
    char buf[256];
    double val;

    memcpy(buf, field, field_len);
    buf[field_len] = 0;
    parse_double(buf, &val);

    switch (avro_value_get_type(avalue)) {
        case AVRO_FLOAT:
            avro_value_set_float(avalue, val);
            break;
        case AVRO_DOUBLE:
            avro_value_set_double(avalue, val);
            break;
    }
}

static void write_avro_field(void *data, const char *field, size_t field_len)
{
    int ret;
    bool boolean_val;
    avro_value_t avalue;
    struct filter_avro_tag_state *state = data;
    const char *field_name;
    bool debug;

    debug = flb_log_check_level(state->ctx->ins->log_level, FLB_LOG_TRACE);

    ret = avro_value_get_by_index(
            &state->record,
            state->record_field_index,
            &avalue,
            debug ? &field_name : NULL);
 
    if (debug) {
        char csvfieldbuf[256];
        size_t count = MIN(field_len, sizeof(csvfieldbuf) - 4);
        memcpy(csvfieldbuf, field, count);
        if (count == sizeof(csvfieldbuf) - 4) {
            csvfieldbuf[count] = '.';
            csvfieldbuf[count+1] = '.';
            csvfieldbuf[count+2] = '.';
            csvfieldbuf[count+3] = 0;
        } else {
            csvfieldbuf[count] = 0;
        }
        flb_plg_trace(state->ctx->ins, "csv field (%s): \"%s\"",
                field_name, csvfieldbuf);
    }

    switch (extract_avro_type(&avalue, field, field_len)) {
        case AVRO_STRING:
            avro_value_set_string_len(&avalue, field, field_len + 1);
            break;
        case AVRO_BOOLEAN:
            boolean_val = field_len == 4 && !strncmp(field, "true", 4);
            avro_value_set_boolean(&avalue, boolean_val);
            break;
        case AVRO_INT32:
        case AVRO_INT64:
            write_avro_int_value(field, field_len, &avalue);
            break;
        case AVRO_FLOAT:
        case AVRO_DOUBLE:
            write_avro_float_value(field, field_len, &avalue);
            break;
        case AVRO_NULL:
            avro_value_set_null(&avalue);
            break;
        default:
            flb_error("unsupported avro type");
            break;
    }
    state->record_field_index++;
}

static ssize_t serialize_avro_value(
        struct filter_avro *ctx,
        avro_value_t *value)
{
    int ret;

    while ((ret = avro_value_write(ctx->awriter, value)) == ENOSPC) {
        ctx->avro_write_buffer_size *= 2;
        ctx->avro_write_buffer = flb_realloc(ctx->avro_write_buffer,
                ctx->avro_write_buffer_size);
        if (!ctx->avro_write_buffer) {
            flb_plg_error(ctx->ins, "Unable to allocate avro write buffer");
            return -1;
        }
        avro_writer_memory_set_dest(ctx->awriter, ctx->avro_write_buffer,
                ctx->avro_write_buffer_size);
    }

    if (ret) {
        flb_plg_error(ctx->ins, "Failed to serialize avro: %s", avro_strerror());
        return -1;
    }

    return avro_writer_tell(ctx->awriter);
}

static int write_avro_value(
        struct filter_avro *ctx,
        struct filter_avro_tag_state *state,
        avro_value_t *payload_array)
{
    ssize_t payload_size;
    avro_value_t payload;

    payload_size = serialize_avro_value(ctx, &state->record);
    if (payload_size < 0) {
        return -1;
    }

    if (avro_value_append(payload_array, &payload, NULL)) {
        flb_plg_error(ctx->ins, "failed to append avro payload to array: %s", 
                avro_strerror());
        return -1;
    }

    if (avro_value_set_bytes(&payload, ctx->avro_write_buffer, payload_size)) {
        flb_plg_error(ctx->ins, "failed to write avro payload: %s", avro_strerror());
        return -1;
    }
    ctx->payloads_total_size += payload_size;

    /* reset avro writer pointer */
    avro_writer_memory_set_dest(ctx->awriter, ctx->avro_write_buffer,
            ctx->avro_write_buffer_size);

    return 0;
}


static int csv_to_avro(
        struct filter_avro *ctx,
        struct filter_avro_tag_state *state,
        avro_value_t *payload_array)
{
    int ret;
    char *bufptr;
    char *bufptrstart;
    size_t buflen;
    size_t buflenstart;
    size_t field_count;

    ctx->payloads_total_size = 0;
    bufptr = state->row_buffer;
    buflen = flb_sds_len(state->row_buffer);
    /* parse all csv records */
    while (buflen) {
        bufptrstart = bufptr;
        buflenstart = buflen;
        /* We parse two times. First we do a simple pass to calculate the
         * csv field count */
        ret = flb_csv_parse_record(&state->state, &bufptr, &buflen,
                &field_count);
        if (ret) {
            break;
        }

        if (write_avro_value(ctx, state, payload_array)) {
            return FLB_FILTER_NOTOUCH;
        }
        
        flb_plg_trace(state->ctx->ins, "=== csv record end ===");
        state->record_field_index = 0;
    }

    if (ret == FLB_CSV_EOF) {
        /* move the incomplete csv record to the beginning of the buffer */
        memmove(state->row_buffer, bufptrstart, buflenstart);
        flb_sds_len_set(state->row_buffer, buflenstart);
    } else {
        flb_sds_len_set(state->row_buffer, 0);
    }

    return 0;
}

static int pack_avro(
        struct filter_avro *ctx,
        struct filter_avro_tag_state *state,
        avro_value_t *outer)

{
    ssize_t payload_size;
    struct flb_time t = {0};
    char writebuf[1024];
    mpack_writer_t writer;

    payload_size = serialize_avro_value(ctx, outer);
    if (payload_size < 0) {
        return -1;
    }

    mpack_writer_init(&writer, writebuf, sizeof(writebuf));
    mpack_writer_set_context(&writer, ctx);
    mpack_writer_set_flush(&writer, mpack_buffer_flush);

    mpack_write_tag(&writer, mpack_tag_array(2));
    flb_time_append_to_mpack(&writer, &t, 0);
    mpack_write_tag(&writer, mpack_tag_map(1));
    mpack_write_cstr(&writer, "avro");
    mpack_write_bin(&writer, ctx->avro_write_buffer, payload_size);

    avro_writer_memory_set_dest(ctx->awriter, ctx->avro_write_buffer,
            ctx->avro_write_buffer_size);

    mpack_writer_flush_message(&writer);
    mpack_writer_destroy(&writer);

    return 0;
}

static int cb_avro_filter(const void *data, size_t bytes,
                         const char *tag, int tag_len,
                         void **out_buf, size_t *out_bytes,
                         struct flb_filter_instance *f_ins,
                         void *filter_context,
                         struct flb_config *config)
{
    int ret;
    struct filter_avro *ctx;
    struct filter_avro_tag_state *state;
    char *outbuf;
    avro_value_t outer;
    avro_value_t value;

    ctx = filter_context;
    flb_sds_len_set(ctx->packbuf, 0);

    state = get_tag_state(ctx, tag);

    if (!state) {
        flb_plg_error(ctx->ins, "max number of tag exceeded");
        return FLB_FILTER_NOTOUCH;
    }

    ret = collect_lines(ctx, state, data, bytes);
    if (ret) {
        return ret;
    }

    if (avro_generic_value_new(ctx->outer_class, &outer)) {
        return -1;
    }

    if (avro_value_get_by_name(&outer, "payload", &value, NULL)) {
        flb_plg_error(ctx->ins, "failed to get avro payload array: %s", avro_strerror());
        return -1;
    }

    ret = csv_to_avro(ctx, state, &value);

    if (ret) {
        avro_value_decref(&outer);
        return ret;
    }

    if (avro_value_get_by_name(&outer, "metadata", &value, NULL)) {
        flb_plg_error(ctx->ins, "failed to get avro metadata: %s", avro_strerror());
        return -1;
    }

    if (avro_value_set_bytes(&value, "", 0)) {
        flb_plg_error(ctx->ins, "failed to set avro metadata: %s", avro_strerror());
        return -1;
    }

    if (avro_value_get_by_name(&outer, "max_size", &value, NULL)) {
        flb_plg_error(ctx->ins, "failed to get avro metadata: %s", avro_strerror());
        return -1;
    }

    if (avro_value_set_int(&value, ctx->payloads_total_size)) {
        return -1;
    }

    if (avro_value_get_by_name(&outer, "avro_schema", &value, NULL)) {
        flb_plg_error(ctx->ins, "failed to get avro schema: %s", avro_strerror());
        return -1;
    }

    if (avro_value_set_string_len(&value, state->avro_schema_json,
                flb_sds_len(state->avro_schema_json))) {
        flb_plg_error(ctx->ins, "failed to set avro schema: %s", avro_strerror());
        return -1;
    }

    if (pack_avro(ctx, state, &outer)) {
        avro_value_decref(&outer);
        flb_plg_error(ctx->ins, "failed to pack outer avro object");
        return FLB_FILTER_NOTOUCH;
    }
    avro_value_decref(&outer);

    /* allocate outbuf that contains the modified chunks */
    outbuf = flb_malloc(flb_sds_len(ctx->packbuf));
    if (!outbuf) {
        flb_plg_error(ctx->ins, "failed to allocate outbuf");
        return FLB_FILTER_NOTOUCH;
    }
    memcpy(outbuf, ctx->packbuf, flb_sds_len(ctx->packbuf));
    /* link new buffer */
    *out_buf   = outbuf;
    *out_bytes = flb_sds_len(ctx->packbuf);
    return FLB_FILTER_MODIFIED;
}

static int cb_avro_exit(void *data, struct flb_config *config)
{
    int i;
    struct filter_avro *ctx = data;

    for (i = 0; i < FILTER_AVRO_MAX_TAG_COUNT; i++) {
        struct filter_avro_tag_state *state = ctx->states + i;
        if (state->used) {
            flb_csv_destroy(&state->state);
            flb_free(state->tag);
            flb_sds_destroy(state->row_buffer);
            flb_sds_destroy(state->avro_schema_json);
            avro_value_decref(&state->record);
            avro_value_iface_decref(state->aclass);
            avro_schema_decref(state->aschema);
        }
    }

    flb_free(ctx->avro_write_buffer);
    avro_writer_free(ctx->awriter);
    avro_value_iface_decref(ctx->outer_class);
    avro_schema_decref(ctx->outer_schema);

    flb_sds_destroy(ctx->packbuf);
    flb_free(ctx);

    return 0;
}

static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_BOOL, "convert_to_avro", "false",
     0, FLB_TRUE, offsetof(struct filter_avro, convert_to_avro),
     "If enabled, convert CSV records into avro, using tag path to find schema "
    },
    {0}
};

struct flb_filter_plugin filter_avro_plugin = {
    .name         = "avro",
    .description  = "AVRO filter plugin",
    .cb_init      = cb_avro_init,
    .cb_filter    = cb_avro_filter,
    .cb_exit      = cb_avro_exit,
    .config_map   = config_map,
    .flags        = 0
};
