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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_hash_table.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_record_accessor.h>
#include <msgpack.h>

#include <ctype.h>

#include <stdio.h>
#include <string.h>
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

#define FLB_OUT_FILE_DEFAULT_MAX_DYNAMIC_FILES  1024

enum {
    FLB_OUT_FILE_ACTION_ERROR,
    FLB_OUT_FILE_ACTION_DROP,
    FLB_OUT_FILE_ACTION_FALLBACK
};

struct flb_file_conf {
    const char *out_path;
    const char *out_file;
    const char *fallback_path;
    const char *fallback_file;
    const char *on_missing_field;
    const char *on_limit_reached;
    const char *delimiter;
    const char *label_delimiter;
    const char *template;
    int format;
    int csv_column_names;
    int mkdir;
    int max_dynamic_files;
    int missing_field_action;
    int limit_reached_action;
    int dynamic_destination;
    struct flb_record_accessor *ra_path;
    struct flb_record_accessor *ra_file;
    struct flb_hash_table *dynamic_files;
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

/*
 * Convert the user-controlled tag into a safe, relative path. Each component is
 * cleaned so only filesystem-friendly characters remain, ".." segments are
 * collapsed into a single underscore and leading separators are dropped to
 * guarantee the result stays within the configured base path.
 */
static int sanitize_tag_name(const char *tag, char *buf, size_t size)
{
    size_t i;
    size_t out_len = 0;
    size_t component_len;
    char sanitized_char;
    const char *p;
    const char *component_start;

    if (tag == NULL || buf == NULL || size < 2) {
        return -1;
    }

    p = tag;

    while (*p != '\0') {
        component_len = 0;
        component_start = NULL;

        /* Skip consecutive separators so we never generate empty components */
        while (*p == '/' || *p == '\\') {
            p++;
        }

        if (*p == '\0') {
            break;
        }

        component_start = p;

        while (*p != '\0' && *p != '/' && *p != '\\') {
            component_len++;
            p++;
        }

        if (component_len == 0) {
            continue;
        }

        if (out_len > 0) {
            if (out_len >= size - 1) {
                break;
            }

            buf[out_len++] = FLB_PATH_SEPARATOR[0];
        }

        if ((component_len == 1 && component_start[0] == '.') ||
            (component_len == 2 && component_start[0] == '.' && component_start[1] == '.')) {
            if (out_len >= size - 1) {
                break;
            }

            buf[out_len++] = '_';
            continue;
        }

        for (i = 0; i < component_len; i++) {
            sanitized_char = component_start[i];

            if (!isalnum((unsigned char) sanitized_char) && sanitized_char != '-' &&
                sanitized_char != '_' && sanitized_char != '.') {
                sanitized_char = '_';
            }

            if (out_len >= size - 1) {
                break;
            }

            buf[out_len++] = sanitized_char;
        }
    }

    if (out_len == 0) {
        buf[0] = '_';
        buf[1] = '\0';
        return 0;
    }

    buf[out_len] = '\0';

    return 0;
}

static void file_conf_destroy(struct flb_file_conf *ctx)
{
    if (ctx == NULL) {
        return;
    }

    if (ctx->ra_path != NULL) {
        flb_ra_destroy(ctx->ra_path);
    }

    if (ctx->ra_file != NULL) {
        flb_ra_destroy(ctx->ra_file);
    }

    if (ctx->dynamic_files != NULL) {
        flb_hash_table_destroy(ctx->dynamic_files);
    }

    flb_free(ctx);
}

static int parse_dynamic_action(struct flb_file_conf *ctx,
                                const char *name,
                                const char *value)
{
    if (strcasecmp(value, "error") == 0) {
        return FLB_OUT_FILE_ACTION_ERROR;
    }
    else if (strcasecmp(value, "drop") == 0) {
        return FLB_OUT_FILE_ACTION_DROP;
    }
    else if (strcasecmp(value, "fallback") == 0) {
        return FLB_OUT_FILE_ACTION_FALLBACK;
    }

    flb_plg_error(ctx->ins, "invalid %s value '%s', expected error, drop or fallback",
                  name, value);

    return -1;
}

static int validate_dynamic_file(const char *file)
{
    const unsigned char *p;

    if (file == NULL || file[0] == '\0' ||
        strcmp(file, ".") == 0 || strcmp(file, "..") == 0) {
        return -1;
    }

    for (p = (const unsigned char *) file; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\' || *p == ':' || *p == '*' || *p == '?' ||
            *p == '"' || *p == '<' || *p == '>' || *p == '|' ||
            *p < 0x20 || *p == 0x7f) {
            return -1;
        }
    }

    return 0;
}

static int validate_dynamic_path(const char *path)
{
    size_t component_length;
    const unsigned char *p;
    const unsigned char *component;

    if (path == NULL || path[0] == '\0') {
        return -1;
    }

    p = (const unsigned char *) path;
    while (*p != '\0') {
        if (*p < 0x20 || *p == 0x7f) {
            return -1;
        }

        while (*p == '/' || *p == '\\') {
            p++;
        }

        component = p;
        while (*p != '\0' && *p != '/' && *p != '\\') {
            if (*p < 0x20 || *p == 0x7f) {
                return -1;
            }
            p++;
        }

        component_length = p - component;
        if ((component_length == 1 && component[0] == '.') ||
            (component_length == 2 && component[0] == '.' && component[1] == '.')) {
            return -1;
        }
    }

    return 0;
}

static int compose_output_file(const char *path,
                               const char *file,
                               char *output,
                               size_t output_size)
{
    int ret;

    if (path != NULL) {
        ret = snprintf(output, output_size, "%s" FLB_PATH_SEPARATOR "%s", path, file);
    }
    else {
        ret = snprintf(output, output_size, "%s", file);
    }

    if (ret < 0 || (size_t) ret >= output_size) {
        return -1;
    }

    return 0;
}

static int use_fallback_destination(struct flb_file_conf *ctx,
                                    char *output,
                                    size_t output_size)
{
    if (ctx->fallback_file == NULL) {
        return -1;
    }

    return compose_output_file(ctx->fallback_path, ctx->fallback_file,
                               output, output_size);
}

static int apply_destination_action(struct flb_file_conf *ctx,
                                    int action,
                                    const char *reason,
                                    char *output,
                                    size_t output_size)
{
    if (action == FLB_OUT_FILE_ACTION_DROP) {
        flb_plg_warn(ctx->ins, "dropping record: %s", reason);
        return 1;
    }

    if (action == FLB_OUT_FILE_ACTION_FALLBACK) {
        if (use_fallback_destination(ctx, output, output_size) == 0) {
            return 0;
        }
        flb_plg_error(ctx->ins, "cannot apply fallback destination: %s", reason);
        return -1;
    }

    flb_plg_error(ctx->ins, "%s", reason);
    return -1;
}

static int resolve_dynamic_destination(struct flb_file_conf *ctx,
                                       const char *tag,
                                       msgpack_object map,
                                       char *output,
                                       size_t output_size,
                                       int *new_destination)
{
    int ret;
    char sanitized_tag[PATH_MAX];
    void *stored_value;
    size_t stored_size;
    flb_sds_t dynamic_path = NULL;
    flb_sds_t dynamic_file = NULL;
    const char *path;
    const char *file;

    *new_destination = FLB_FALSE;
    path = ctx->out_path;
    file = ctx->out_file;

    if (ctx->ra_path != NULL) {
        dynamic_path = flb_ra_translate_check(ctx->ra_path,
                                              (char *) tag, strlen(tag),
                                              map, NULL, FLB_TRUE);
        if (dynamic_path == NULL) {
            return apply_destination_action(ctx, ctx->missing_field_action,
                                            "record accessor field missing from path",
                                            output, output_size);
        }
        path = dynamic_path;
    }

    if (ctx->ra_file != NULL) {
        dynamic_file = flb_ra_translate_check(ctx->ra_file,
                                              (char *) tag, strlen(tag),
                                              map, NULL, FLB_TRUE);
        if (dynamic_file == NULL) {
            flb_sds_destroy(dynamic_path);
            return apply_destination_action(ctx, ctx->missing_field_action,
                                            "record accessor field missing from file",
                                            output, output_size);
        }
        file = dynamic_file;
    }
    else if (file == NULL) {
        ret = sanitize_tag_name(tag, sanitized_tag, sizeof(sanitized_tag));
        if (ret != 0) {
            flb_sds_destroy(dynamic_path);
            return -1;
        }
        file = sanitized_tag;
    }

    if ((ctx->ra_path != NULL && validate_dynamic_path(path) != 0) ||
        (ctx->ra_file != NULL && validate_dynamic_file(file) != 0)) {
        flb_sds_destroy(dynamic_path);
        flb_sds_destroy(dynamic_file);
        return apply_destination_action(ctx, ctx->missing_field_action,
                                        "unsafe dynamic output destination",
                                        output, output_size);
    }

    ret = compose_output_file(path, file, output, output_size);
    flb_sds_destroy(dynamic_path);
    flb_sds_destroy(dynamic_file);
    if (ret != 0) {
        return -1;
    }

    if (ctx->dynamic_files == NULL) {
        return 0;
    }

    ret = flb_hash_table_get(ctx->dynamic_files, output, strlen(output),
                             &stored_value, &stored_size);
    if (ret >= 0) {
        return 0;
    }

    if (ctx->dynamic_files->total_count >= ctx->max_dynamic_files) {
        return apply_destination_action(ctx, ctx->limit_reached_action,
                                        "max_dynamic_files limit reached",
                                        output, output_size);
    }

    *new_destination = FLB_TRUE;
    return 0;
}


static int cb_file_init(struct flb_output_instance *ins,
                        struct flb_config *config,
                        void *data)
{
    int ret;
    int table_size;
    const char *tmp;
    const char *accessor;
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
    ctx->max_dynamic_files = FLB_OUT_FILE_DEFAULT_MAX_DYNAMIC_FILES;

    ret = flb_output_config_map_set(ins, (void *) ctx);
    if (ret == -1) {
        file_conf_destroy(ctx);
        return -1;
    }

    ctx->missing_field_action = parse_dynamic_action(ctx, "on_missing_field",
                                                     ctx->on_missing_field);
    ctx->limit_reached_action = parse_dynamic_action(ctx, "on_limit_reached",
                                                     ctx->on_limit_reached);
    if (ctx->missing_field_action < 0 || ctx->limit_reached_action < 0 ||
        ctx->max_dynamic_files < 0) {
        file_conf_destroy(ctx);
        return -1;
    }

    if ((ctx->missing_field_action == FLB_OUT_FILE_ACTION_FALLBACK ||
         ctx->limit_reached_action == FLB_OUT_FILE_ACTION_FALLBACK) &&
        ctx->fallback_file == NULL) {
        flb_plg_error(ctx->ins, "fallback_file is required for fallback actions");
        file_conf_destroy(ctx);
        return -1;
    }

    if (ctx->out_path != NULL && strchr(ctx->out_path, '$') != NULL) {
        accessor = strchr(ctx->out_path, '$');
        if (accessor == ctx->out_path) {
            flb_plg_error(ctx->ins,
                          "dynamic 'path' must include a static prefix before record accessors");
            file_conf_destroy(ctx);
            return -1;
        }

        ctx->ra_path = flb_ra_create((char *) ctx->out_path, FLB_TRUE);
        if (ctx->ra_path == NULL) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern set for 'path'");
            file_conf_destroy(ctx);
            return -1;
        }
        ctx->dynamic_destination = FLB_TRUE;
    }

    if (ctx->out_file != NULL && strchr(ctx->out_file, '$') != NULL) {
        ctx->ra_file = flb_ra_create((char *) ctx->out_file, FLB_TRUE);
        if (ctx->ra_file == NULL) {
            flb_plg_error(ctx->ins, "invalid record accessor pattern set for 'file'");
            file_conf_destroy(ctx);
            return -1;
        }
        ctx->dynamic_destination = FLB_TRUE;
    }

    if (ctx->dynamic_destination == FLB_TRUE && ctx->fallback_file == NULL) {
        flb_plg_error(ctx->ins,
                      "fallback_file is required when dynamic destinations are configured");
        file_conf_destroy(ctx);
        return -1;
    }

    if (ctx->dynamic_destination == FLB_TRUE && ctx->max_dynamic_files > 0) {
        table_size = ctx->max_dynamic_files;
        if (table_size > 128) {
            table_size = 128;
        }

        ctx->dynamic_files = flb_hash_table_create(FLB_HASH_TABLE_EVICT_NONE,
                                                   table_size,
                                                   ctx->max_dynamic_files);
        if (ctx->dynamic_files == NULL) {
            file_conf_destroy(ctx);
            return -1;
        }
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
            file_conf_destroy(ctx);
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


static int plain_output(FILE *fp, msgpack_object *obj, size_t alloc_size, int escape_unicode)
{
    char *buf;

    buf = flb_msgpack_to_json_str(alloc_size, obj, escape_unicode);
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

    flb_plg_debug(ins, "processing path '%s'", parent_path);
    sep = strstr(parent_path, FLB_PATH_SEPARATOR);
    if (sep != NULL && PathRemoveFileSpecA(parent_path)) {
        flb_plg_debug(ins, "creating directory (recursive) %s", parent_path);
        ret = mkpath(ins, parent_path);
        if (ret != 0) {
            /* If creating the parent failed, we cannot continue. */
            return -1;
        }
    }

    flb_plg_debug(ins, "attempting to create final directory '%s'", dir);
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

static FILE *open_output_file(struct flb_file_conf *ctx, const char *output)
{
    int ret;
    FILE *fp;
    char *output_copy;

    fp = fopen(output, "ab+");
    if (ctx->mkdir == FLB_TRUE && fp == NULL && errno == ENOENT) {
        output_copy = strdup(output);
        if (output_copy != NULL) {
#ifdef FLB_SYSTEM_WINDOWS
            PathRemoveFileSpecA(output_copy);
            ret = mkpath(ctx->ins, output_copy);
#else
            ret = mkpath(ctx->ins, dirname(output_copy));
#endif
            free(output_copy);
            if (ret == 0) {
                fp = fopen(output, "ab+");
            }
        }
    }

    return fp;
}

static int write_log_record(FILE *fp,
                            long *file_pos,
                            struct flb_event_chunk *event_chunk,
                            struct flb_log_event *log_event,
                            struct flb_file_conf *ctx,
                            struct flb_config *config)
{
    int column_names;
    char *buf;

    switch (ctx->format) {
    case FLB_OUT_FILE_FMT_JSON:
        buf = flb_msgpack_to_json_str(128, log_event->body,
                                      config->json_escape_unicode);
        if (buf == NULL) {
            return FLB_RETRY;
        }

        fprintf(fp, "%s: [%"PRIu64".%09lu, %s]" NEWLINE,
                event_chunk->tag,
                (uint64_t) log_event->timestamp.tm.tv_sec,
                log_event->timestamp.tm.tv_nsec,
                buf);
        flb_free(buf);
        break;
    case FLB_OUT_FILE_FMT_CSV:
        if (ctx->csv_column_names == FLB_TRUE && *file_pos == 0) {
            column_names = FLB_TRUE;
            *file_pos = 1;
        }
        else {
            column_names = FLB_FALSE;
        }
        csv_output(fp, column_names, &log_event->timestamp, log_event->body, ctx);
        break;
    case FLB_OUT_FILE_FMT_LTSV:
        ltsv_output(fp, &log_event->timestamp, log_event->body, ctx);
        break;
    case FLB_OUT_FILE_FMT_PLAIN:
        plain_output(fp, log_event->body, 128, config->json_escape_unicode);
        break;
    case FLB_OUT_FILE_FMT_TEMPLATE:
        template_output(fp, &log_event->timestamp, log_event->body, ctx);
        break;
    }

    return FLB_OK;
}

static int flush_dynamic_logs(struct flb_event_chunk *event_chunk,
                              struct flb_file_conf *ctx,
                              struct flb_config *config,
                              char *output,
                              size_t output_size,
                              struct flb_log_event_decoder *log_decoder,
                              struct flb_log_event *log_event)
{
    int ret;
    int new_destination;
    FILE *fp;
    long file_pos;

    ret = flb_log_event_decoder_init(log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error : %d", ret);
        return FLB_ERROR;
    }

    while ((ret = flb_log_event_decoder_next(log_decoder,
                                              log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        ret = resolve_dynamic_destination(ctx, event_chunk->tag, *log_event->body,
                                          output, output_size, &new_destination);
        if (ret == 1) {
            continue;
        }
        else if (ret != 0) {
            flb_log_event_decoder_destroy(log_decoder);
            return FLB_ERROR;
        }

        fp = open_output_file(ctx, output);
        if (fp == NULL) {
            flb_errno();
            flb_plg_error(ctx->ins, "error opening: %s", output);
            flb_log_event_decoder_destroy(log_decoder);
            return FLB_ERROR;
        }

        if (new_destination == FLB_TRUE) {
            ret = flb_hash_table_add(ctx->dynamic_files, output, strlen(output), "", 0);
            if (ret < 0) {
                fclose(fp);
                flb_log_event_decoder_destroy(log_decoder);
                return FLB_ERROR;
            }
        }

        file_pos = ftell(fp);
        if (ctx->format == FLB_OUT_FILE_FMT_MSGPACK) {
            if (fwrite(log_decoder->record_base, 1, log_decoder->record_length, fp) !=
                log_decoder->record_length) {
                fclose(fp);
                flb_log_event_decoder_destroy(log_decoder);
                return FLB_RETRY;
            }
        }
        else {
            ret = write_log_record(fp, &file_pos, event_chunk, log_event, ctx, config);
            if (ret != FLB_OK) {
                fclose(fp);
                flb_log_event_decoder_destroy(log_decoder);
                return ret;
            }
        }

        fclose(fp);
    }

    flb_log_event_decoder_destroy(log_decoder);

    return FLB_OK;
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
    char out_file[PATH_MAX * 2];
    char sanitized_tag[PATH_MAX];
    char *buf;
    long file_pos;
    struct flb_file_conf *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    char* out_file_copy;

    (void) config;

    if (ctx->dynamic_destination == FLB_TRUE &&
        event_chunk->type != FLB_INPUT_METRICS) {
        ret = flush_dynamic_logs(event_chunk, ctx, config,
                                 out_file, sizeof(out_file),
                                 &log_decoder, &log_event);
        FLB_OUTPUT_RETURN(ret);
    }

    if (ctx->dynamic_destination == FLB_TRUE &&
        event_chunk->type == FLB_INPUT_METRICS) {
        ret = use_fallback_destination(ctx, out_file, sizeof(out_file));
        if (ret != 0) {
            flb_plg_error(ctx->ins,
                          "dynamic path and file record accessors are unsupported for metrics");
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }
    /* Set the right output file */
    else if (ctx->out_file == NULL) {
        ret = sanitize_tag_name(event_chunk->tag,
                                sanitized_tag,
                                sizeof(sanitized_tag));

        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to sanitize tag for output file");
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }
    }

    if (ctx->dynamic_destination == FLB_FALSE && ctx->out_path) {
        if (ctx->out_file) {
            snprintf(out_file, sizeof(out_file) , "%s" FLB_PATH_SEPARATOR "%s",
                     ctx->out_path, ctx->out_file);
        }
        else {
            snprintf(out_file, sizeof(out_file), "%s" FLB_PATH_SEPARATOR "%s",
                     ctx->out_path, sanitized_tag);
        }
    }
    else if (ctx->dynamic_destination == FLB_FALSE) {
        if (ctx->out_file) {
            snprintf(out_file, PATH_MAX, "%s", ctx->out_file);
        }
        else {
            snprintf(out_file, PATH_MAX, "%s", sanitized_tag);
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
            buf = flb_msgpack_to_json_str(alloc_size, log_event.body,
                                          config->json_escape_unicode);
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
            plain_output(fp, log_event.body, alloc_size, config->json_escape_unicode);

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

    file_conf_destroy(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "path", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, out_path),
     "Absolute path to store the files. Log record accessor expressions are supported, "
     "and dynamic paths must retain a static prefix"
    },

    {
     FLB_CONFIG_MAP_STR, "file", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, out_file),
     "Name of the target file to write the records. If 'path' is specified, "
     "the value is prefixed. Log record accessor expressions are supported"
    },

    {
     FLB_CONFIG_MAP_INT, "max_dynamic_files", "1024",
     0, FLB_TRUE, offsetof(struct flb_file_conf, max_dynamic_files),
     "Maximum number of distinct record-accessor destinations. Set to 0 for unlimited"
    },

    {
     FLB_CONFIG_MAP_STR, "on_missing_field", "error",
     0, FLB_TRUE, offsetof(struct flb_file_conf, on_missing_field),
     "Action for missing or unsafe dynamic destination values: error, drop or fallback"
    },

    {
     FLB_CONFIG_MAP_STR, "on_limit_reached", "error",
     0, FLB_TRUE, offsetof(struct flb_file_conf, on_limit_reached),
     "Action when max_dynamic_files would be exceeded: error, drop or fallback"
    },

    {
     FLB_CONFIG_MAP_STR, "fallback_path", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, fallback_path),
     "Static output path used when a configured fallback action is applied"
    },

    {
     FLB_CONFIG_MAP_STR, "fallback_file", NULL,
     0, FLB_TRUE, offsetof(struct flb_file_conf, fallback_file),
     "Static output file used when a configured fallback action is applied"
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
