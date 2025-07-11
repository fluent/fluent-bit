/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <msgpack.h>

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <Shlobj.h>
#include <Shlwapi.h>
#endif

#include "file.h"

#ifdef FLB_SYSTEM_WINDOWS
#define NEWLINE "\r\n"
#define S_ISDIR(m)      (((m) & S_IFMT) == S_IFDIR)
#else
#define NEWLINE "\n"
#endif

#ifdef FLB_SYSTEM_WINDOWS
#define FLB_PATH_SEPARATOR "\\"
#else
#define FLB_PATH_SEPARATOR "/"
#endif

struct flb_file_conf {
    const char *out_path;
    const char *out_file;
    const char *delimiter;
    const char *label_delimiter;
    const char *template;
    int format;
    int csv_column_names;
    int mkdir;
    struct flb_output_instance *ins;
};

static char *check_delimiter(const char *str)
{
    if (str == NULL) {
        return NULL;
    }

    if (!strcasecmp(str, "\\t") || !strcasecmp(str, "tab")) {
        return "\t";
    }
    else if (!strcasecmp(str, "space")) {
        return " ";
    }
    else if (!strcasecmp(str, "comma")) {
        return ",";
    }

    return NULL;
}


static int cb_file_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    const char *tmp;
    char *ret_str;
    (void) config;
    (void) data;
    struct flb_file_conf *ctx;

    ctx = flb_calloc(1, sizeof(struct flb_file_conf));
    if (!ctx) {
        flb_errno();
        return -1;
    }
    ctx->ins = ins;
    ctx->format = FLB_OUT_FILE_FMT_JSON; /* default */
    ctx->delimiter = NULL;
    ctx->label_delimiter = NULL;
    ctx->template = NULL;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        flb_free(ctx);
        return -1;
    }

    /* Optional, file format */
    tmp = flb_output_get_property("Format", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "csv")) {
            ctx->format    = FLB_OUT_FILE_FMT_CSV;
            ctx->delimiter = ",";
        }
        else if (!strcasecmp(tmp, "ltsv")) {
            ctx->format    = FLB_OUT_FILE_FMT_LTSV;
            ctx->delimiter = "\t";
            ctx->label_delimiter = ":";
        }
        else if (!strcasecmp(tmp, "plain")) {
            ctx->format    = FLB_OUT_FILE_FMT_PLAIN;
            ctx->delimiter = NULL;
            ctx->label_delimiter = NULL;
        }
        else if (!strcasecmp(tmp, "msgpack")) {
            ctx->format    = FLB_OUT_FILE_FMT_MSGPACK;
            ctx->delimiter = NULL;
            ctx->label_delimiter = NULL;
        }
        else if (!strcasecmp(tmp, "template")) {
            ctx->format    = FLB_OUT_FILE_FMT_TEMPLATE;
        }
        else if (!strcasecmp(tmp, "out_file")) {
            /* for explicit setting */
            ctx->format = FLB_OUT_FILE_FMT_JSON;
        }
        else {
            flb_plg_error(ctx->ins, "unknown format %s. abort.", tmp);
            flb_free(ctx);
            return -1;
        }
    }

    tmp = flb_output_get_property("delimiter", ins);
    ret_str = check_delimiter(tmp);
    if (ret_str != NULL) {
        ctx->delimiter = ret_str;
    }

    tmp = flb_output_get_property("label_delimiter", ins);
    ret_str = check_delimiter(tmp);
    if (ret_str != NULL) {
        ctx->label_delimiter = ret_str;
    }

    /* Set the context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static int csv_output(FILE *fp, int column_names,
                      struct flb_time *tm, msgpack_object *obj,
                      struct flb_file_conf *ctx)
{
    int i;
    int map_size;
    msgpack_object_kv *kv = NULL;

    if (obj->type == MSGPACK_OBJECT_MAP && obj->via.map.size > 0) {
        kv = obj->via.map.ptr;
        map_size = obj->via.map.size;

        if (column_names == FLB_TRUE) {
            fprintf(fp, "timestamp%s", ctx->delimiter);
            for (i = 0; i < map_size; i++) {
                msgpack_object_print(fp, (kv+i)->key);
                if (i + 1 < map_size) {
                    fprintf(fp, "%s", ctx->delimiter);
                }
            }
            fprintf(fp, NEWLINE);
        }

        fprintf(fp, "%lld.%.09ld%s",
                (long long) tm->tm.tv_sec, tm->tm.tv_nsec, ctx->delimiter);

        for (i = 0; i < map_size - 1; i++) {
            msgpack_object_print(fp, (kv+i)->val);
            fprintf(fp, "%s", ctx->delimiter);
        }

        msgpack_object_print(fp, (kv+(map_size-1))->val);
        fprintf(fp, NEWLINE);
    }
    return 0;
}

static int ltsv_output(FILE *fp, struct flb_time *tm, msgpack_object *obj,
                       struct flb_file_conf *ctx)
{
    msgpack_object_kv *kv = NULL;
    int i;
    int map_size;

    if (obj->type == MSGPACK_OBJECT_MAP && obj->via.map.size > 0) {
        kv = obj->via.map.ptr;
        map_size = obj->via.map.size;
        fprintf(fp, "\"time\"%s%f%s",
                ctx->label_delimiter,
                flb_time_to_double(tm),
                ctx->delimiter);

        for (i = 0; i < map_size - 1; i++) {
            msgpack_object_print(fp, (kv+i)->key);
            fprintf(fp, "%s", ctx->label_delimiter);
            msgpack_object_print(fp, (kv+i)->val);
            fprintf(fp, "%s", ctx->delimiter);
        }

        msgpack_object_print(fp, (kv+(map_size-1))->key);
        fprintf(fp, "%s", ctx->label_delimiter);
        msgpack_object_print(fp, (kv+(map_size-1))->val);
        fprintf(fp, NEWLINE);
    }
    return 0;
}

static int template_output_write(struct flb_file_conf *ctx,
                                 FILE *fp, struct flb_time *tm, msgpack_object *obj,
                                 const char *key, int size)
{
    int i;
    msgpack_object_kv *kv;

    /*
     * Right now we treat "{time}" specially and fill the placeholder
     * with the metadata timestamp (formatted as float).
     */
    if (!strncmp(key, "time", size)) {
        fprintf(fp, "%f", flb_time_to_double(tm));
        return 0;
    }

    if (obj->type != MSGPACK_OBJECT_MAP) {
        flb_plg_error(ctx->ins, "invalid object type (type=%i)", obj->type);
        return -1;
    }

    for (i = 0; i < obj->via.map.size; i++) {
        kv = obj->via.map.ptr + i;

        if (size != kv->key.via.str.size) {
            continue;
        }

        if (!memcmp(key, kv->key.via.str.ptr, size)) {
            if (kv->val.type == MSGPACK_OBJECT_STR) {
                fwrite(kv->val.via.str.ptr, 1, kv->val.via.str.size, fp);
            }
            else {
                msgpack_object_print(fp, kv->val);
            }
            return 0;
        }
    }
    return -1;
}

/*
 * Python-like string templating for out_file.
 *
 * This accepts a format string like "my name is {name}" and fills
 * placeholders using corresponding values in a record.
 *
 * e.g. {"name":"Tom"} => "my name is Tom"
 */
static int template_output(FILE *fp, struct flb_time *tm, msgpack_object *obj,
                           struct flb_file_conf *ctx)
{
    int i;
    int len = strlen(ctx->template);
    int keysize;
    const char *key;
    const char *pos;
    const char *inbrace = NULL;  /* points to the last open brace */

    for (i = 0; i < len; i++) {
        pos = ctx->template + i;
        if (*pos == '{') {
            if (inbrace) {
                /*
                 * This means that we find another open brace inside
                 * braces (e.g. "{a{b}"). Ignore the previous one.
                 */
                fwrite(inbrace, 1, pos - inbrace, fp);
            }
            inbrace = pos;
        }
        else if (*pos == '}' && inbrace) {
            key = inbrace + 1;
            keysize = pos - inbrace - 1;

            if (template_output_write(ctx, fp, tm, obj, key, keysize)) {
                fwrite(inbrace, 1, pos - inbrace + 1, fp);
            }
            inbrace = NULL;
        }
        else {
            if (!inbrace) {
                fputc(*pos, fp);
            }
        }
    }

    /* Handle an unclosed brace like "{abc" */
    if (inbrace) {
        fputs(inbrace, fp);
    }
    fputs(NEWLINE, fp);
    return 0;
}


static int plain_output(FILE *fp, msgpack_object *obj, size_t alloc_size)
{
    char *buf;

    buf = flb_msgpack_to_json_str(alloc_size, obj);
    if (buf) {
        fprintf(fp, "%s" NEWLINE,
                buf);
        flb_free(buf);
    }
    return 0;
}

static void print_metrics_text(struct flb_output_instance *ins,
                               FILE *fp,
                               const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *) data, bytes, &off);
    if (ret != 0) {
        flb_plg_error(ins, "could not process metrics payload");
        return;
    }

    /* convert to text representation */
    text = cmt_encode_text_create(cmt);

    /* destroy cmt context */
    cmt_destroy(cmt);

    fprintf(fp, "%s", text);
    cmt_encode_text_destroy(text);
}

static int mkpath(struct flb_output_instance *ins, const char *dir)
{
    struct stat st;
    char *dup_dir = NULL;
#ifdef FLB_SYSTEM_MACOS
    char *parent_dir = NULL;
#endif
#ifdef FLB_SYSTEM_WINDOWS
    char parent_path[MAX_PATH];
    DWORD err;
    char *p;
    char *sep;
#endif
    int ret;

    if (!dir) {
        errno = EINVAL;
        return -1;
    }

    if (strlen(dir) == 0) {
        errno = EINVAL;
        return -1;
    }

    if (stat(dir, &st) == 0) {
        if (S_ISDIR (st.st_mode)) {
            return 0;
        }
        flb_plg_error(ins, "%s is not a directory", dir);
        errno = ENOTDIR;
        return -1;
    }

#ifdef FLB_SYSTEM_WINDOWS
    if (strncpy_s(parent_path, MAX_PATH, dir, _TRUNCATE) != 0) {
        flb_plg_error(ins, "path is too long: %s", dir);
        return -1;
    }

    p = parent_path;

    /* Skip the drive letter if present (e.g., "C:") */
    if (p[1] == ':') {
        p += 2;
    }

    /* Normalize all forward slashes to backslashes */
    while (*p != '\0') {
        if (*p == '/') {
            *p = '\\';
        }
        p++;
    }

    flb_plg_debug(ins, "starting to create directory %s", parent_path);
    sep = strstr(parent_path, FLB_PATH_SEPARATOR);
    if (sep != NULL && PathRemoveFileSpecA(parent_path)) {
        flb_plg_debug(ins, "creating directory (recursive) %s", parent_path);
        ret = mkpath(ins, parent_path);
        if (ret != 0) {
            /* If creating the parent failed, we cannot continue. */
            return -1;
        }
    }

    flb_plg_debug(ins, "creating directory %s", dir);
    if (!CreateDirectoryA(dir, NULL)) {
        err = GetLastError();

        if (err != ERROR_ALREADY_EXISTS) {
            flb_plg_error(ins, "could not create directory '%s' (error=%lu)",
                          dir, err);
            return -1;
        }
    }

    return 0;
#elif FLB_SYSTEM_MACOS
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return -1;
    }

    /* macOS's dirname(3) should return current directory when slash
     * charachter is not included in passed string.
     * And note that macOS's dirname(3) does not modify passed string.
     */
    parent_dir = dirname(dup_dir);
    if (stat(parent_dir, &st) == 0 && strncmp(parent_dir, ".", 1)) {
        if (S_ISDIR (st.st_mode)) {
            flb_plg_debug(ins, "creating directory %s", dup_dir);
            ret = mkdir(dup_dir, 0755);
            free(dup_dir);
            return ret;
        }
    }

    ret = mkpath(ins, dirname(dup_dir));
    if (ret != 0) {
        free(dup_dir);
        return ret;
    }
    flb_plg_debug(ins, "creating directory %s", dup_dir);
    ret = mkdir(dup_dir, 0755);
    free(dup_dir);
    return ret;
#else
    dup_dir = strdup(dir);
    if (!dup_dir) {
        return -1;
    }
    ret = mkpath(ins, dirname(dup_dir));
    free(dup_dir);
    if (ret != 0) {
        return ret;
    }
    flb_plg_debug(ins, "creating directory %s", dir);
    return mkdir(dir, 0755);
#endif
}

static void cb_file_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins,
                          void *out_context,
                          struct flb_config *config)
{
    int ret;
    int column_names;
    FILE * fp;
    size_t off = 0;
    size_t last_off = 0;
    size_t alloc_size = 0;
    size_t total;
    char out_file[PATH_MAX];
    char *buf;
    long file_pos;
    struct flb_file_conf *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    char* out_file_copy;

    (void) config;

    /* Set the right output file */
    if (ctx->out_path) {
        if (ctx->out_file) {
            snprintf(out_file, PATH_MAX - 1, "%s" FLB_PATH_SEPARATOR "%s",
                     ctx->out_path, ctx->out_file);
        }
        else {
            snprintf(out_file, PATH_MAX - 1, "%s" FLB_PATH_SEPARATOR "%s",
                     ctx->out_path, event_chunk->tag);
        }
    }
    else {
        if (ctx->out_file) {
            snprintf(out_file, PATH_MAX - 1, "%s", ctx->out_file);
        }
        else {
            snprintf(out_file, PATH_MAX - 1, "%s", event_chunk->tag);
        }
    }

    /* Open output file with default name as the Tag */
    fp = fopen(out_file, "ab+");
    if (ctx->mkdir == FLB_TRUE && fp == NULL && errno == ENOENT) {
        out_file_copy = strdup(out_file);
        if (out_file_copy) {
#ifdef FLB_SYSTEM_WINDOWS
            PathRemoveFileSpecA(out_file_copy);
            ret = mkpath(ctx->ins, out_file_copy);
#else
            ret = mkpath(ctx->ins, dirname(out_file_copy));
#endif
            free(out_file_copy);
            if (ret == 0) {
                fp = fopen(out_file, "ab+");
            }
        }
    }
    if (fp == NULL) {
        flb_errno();
        flb_plg_error(ctx->ins, "error opening: %s", out_file);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /*
     * Get current file stream position, we gather this in case 'csv' format
     * needs to write the column names.
     */
    file_pos = ftell(fp);

    /* Check if the event type is metrics, handle the payload differently */
    if (event_chunk->type == FLB_INPUT_METRICS) {
        print_metrics_text(ctx->ins, fp,
                           event_chunk->data, event_chunk->size);
        fclose(fp);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    /*
     * Msgpack output format used to create unit tests files, useful for
     * Fluent Bit developers.
     */
    if (ctx->format == FLB_OUT_FILE_FMT_MSGPACK) {
        off = 0;
        total = 0;

        do {
            ret = fwrite((char *) event_chunk->data + off, 1,
                         event_chunk->size - off, fp);
            if (ret < 0) {
                flb_errno();
                fclose(fp);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            total += ret;
        } while (total < event_chunk->size);

        fclose(fp);
        FLB_OUTPUT_RETURN(FLB_OK);
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        fclose(fp);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        alloc_size = (off - last_off) + 128; /* JSON is larger than msgpack */
        last_off = off;

        switch (ctx->format){
        case FLB_OUT_FILE_FMT_JSON:
            buf = flb_msgpack_to_json_str(alloc_size, log_event.body);
            if (buf) {
                fprintf(fp, "%s: [%"PRIu64".%09lu, %s]" NEWLINE,
                        event_chunk->tag,
                        (uint64_t) log_event.timestamp.tm.tv_sec, log_event.timestamp.tm.tv_nsec,
                        buf);
                flb_free(buf);
            }
            else {
                flb_log_event_decoder_destroy(&log_decoder);
                fclose(fp);
                FLB_OUTPUT_RETURN(FLB_RETRY);
            }
            break;
        case FLB_OUT_FILE_FMT_CSV:
            if (ctx->csv_column_names == FLB_TRUE && file_pos == 0) {
                column_names = FLB_TRUE;
                file_pos = 1;
            }
            else {
                column_names = FLB_FALSE;
            }
            csv_output(fp, column_names,
                       &log_event.timestamp,
                       log_event.body, ctx);
            break;
        case FLB_OUT_FILE_FMT_LTSV:
            ltsv_output(fp,
                        &log_event.timestamp,
                        log_event.body, ctx);
            break;
        case FLB_OUT_FILE_FMT_PLAIN:
            plain_output(fp, log_event.body, alloc_size);

            break;
        case FLB_OUT_FILE_FMT_TEMPLATE:
            template_output(fp,
                            &log_event.timestamp,
                            log_event.body, ctx);

            break;
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    fclose(fp);

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_file_exit(void *data, struct flb_config *config)
{
    struct flb_file_conf *ctx = data;

    if (!ctx) {
        return 0;
    }

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, out_path),
     "Absolute path to store the files. This parameter is optional"
    },

    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, out_file),
     "Name of the target file to write the records. If 'path' is specified, "
     "the value is prefixed"
    },

    {
     FLB_CONFIG_MAP_STR, "format", NULL,
     0, FLB_FALSE, 0,
     "Specify the output data format, the available options are: plain (json), "
     "csv, ltsv and template. If no value is set the outgoing data is formatted "
     "using the tag and the record in json"
    },

    {
     FLB_CONFIG_MAP_STR, "delimiter", NULL,
     0, FLB_FALSE, 0,
     "Set a custom delimiter for the records"
    },

    {
     FLB_CONFIG_MAP_STR, "label_delimiter", NULL,
     0, FLB_FALSE, 0,
     "Set a custom label delimiter, to be used with 'ltsv' format"
    },

    {
     FLB_CONFIG_MAP_STR, "template", "{time} {message}",
     0, FLB_TRUE, offsetof(struct flb_file_conf, template),
     "Set a custom template format for the data"
    },

    {
     FLB_CONFIG_MAP_BOOL, "csv_column_names", "false",
     0, FLB_TRUE, offsetof(struct flb_file_conf, csv_column_names),
     "Add column names (keys) in the first line of the target file"
    },

    {
     FLB_CONFIG_MAP_BOOL, "mkdir", "false",
     0, FLB_TRUE, offsetof(struct flb_file_conf, mkdir),
     "Recursively create output directory if it does not exist. Permissions set to 0755"
    },

    /* EOF */
    {0}
};

struct flb_output_plugin out_file_plugin = {
    .name         = "file",
    .description  = "Generate log file",
    .cb_init      = cb_file_init,
    .cb_flush     = cb_file_flush,
    .cb_exit      = cb_file_exit,
    .flags        = 0,
    .workers      = 1,
    .event_type   = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .config_map   = config_map,
};
