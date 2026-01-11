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

#include <fluent-bit/flb_compat.h>
#include <fluent-bit/flb_lock.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_metrics.h>
#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_utils.h>
#include <msgpack.h>

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <miniz/miniz.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#ifdef FLB_SYSTEM_WINDOWS
#include <Shlobj.h>
#include <Shlwapi.h>
#else
#include <dirent.h>
#include <libgen.h>
#include <unistd.h>
#endif

#include "file.h"

#ifdef FLB_SYSTEM_WINDOWS
#define NEWLINE "\r\n"
#define S_ISDIR(m) (((m) & S_IFMT) == S_IFDIR)
#else
#define NEWLINE "\n"
#endif

#ifdef FLB_SYSTEM_WINDOWS
#define FLB_PATH_SEPARATOR "\\"
#else
#define FLB_PATH_SEPARATOR "/"
#endif

/* Constants for streaming gzip compression */
#define GZIP_CHUNK_SIZE (16 * 1024)
#define GZIP_HEADER_SIZE 10
#define GZIP_FOOTER_SIZE 8

struct file_file_size {
    flb_sds_t filename;
    size_t size;
    flb_lock_t lock;
    struct mk_list _head;
};

struct flb_file_conf {
    const char *out_path;
    const char *out_file;
    const char *delimiter;
    const char *label_delimiter;
    const char *template;
    int format;
    int csv_column_names;
    int mkdir;
    /* Rotation-related fields */
    int files_rotation;
    size_t max_size;
    int max_files;
    int gzip;
    struct mk_list file_sizes;
    flb_lock_t list_lock;
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
            (component_len == 2 && component_start[0] == '.' &&
             component_start[1] == '.')) {
            if (out_len >= size - 1) {
                break;
            }

            buf[out_len++] = '_';
            continue;
        }

        for (i = 0; i < component_len; i++) {
            sanitized_char = component_start[i];

            if (!isalnum((unsigned char)sanitized_char) &&
                sanitized_char != '-' && sanitized_char != '_' &&
                sanitized_char != '.') {
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

static int cb_file_init(struct flb_output_instance *ins,
                        struct flb_config *config, void *data)
{
    int ret;
    const char *tmp;
    char *ret_str;
    (void)config;
    (void)data;
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

    /* Initialize rotation-related structures */
    mk_list_init(&ctx->file_sizes);
    if (flb_lock_init(&ctx->list_lock) != 0) {
        flb_plg_error(ins, "failed to initialize files rotation list mutex");
        flb_free(ctx);
        return -1;
    }

    ret = flb_output_config_map_set(ins, (void *)ctx);
    if (ret == -1) {
        flb_lock_destroy(&ctx->list_lock);
        flb_free(ctx);
        return -1;
    }

    /* Validate max_files only if rotation is enabled */
    if (ctx->files_rotation == FLB_TRUE && ctx->max_files <= 0) {
        flb_plg_error(ctx->ins, "invalid max_files=%d; must be >= 1",
                      ctx->max_files);
        flb_lock_destroy(&ctx->list_lock);
        flb_free(ctx);
        return -1;
    }

    /* Optional, file format */
    tmp = flb_output_get_property("Format", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "csv")) {
            ctx->format = FLB_OUT_FILE_FMT_CSV;
            ctx->delimiter = ",";
        }
        else if (!strcasecmp(tmp, "ltsv")) {
            ctx->format = FLB_OUT_FILE_FMT_LTSV;
            ctx->delimiter = "\t";
            ctx->label_delimiter = ":";
        }
        else if (!strcasecmp(tmp, "plain")) {
            ctx->format = FLB_OUT_FILE_FMT_PLAIN;
            ctx->delimiter = NULL;
            ctx->label_delimiter = NULL;
        }
        else if (!strcasecmp(tmp, "msgpack")) {
            ctx->format = FLB_OUT_FILE_FMT_MSGPACK;
            ctx->delimiter = NULL;
            ctx->label_delimiter = NULL;
        }
        else if (!strcasecmp(tmp, "template")) {
            ctx->format = FLB_OUT_FILE_FMT_TEMPLATE;
        }
        else if (!strcasecmp(tmp, "out_file")) {
            /* for explicit setting */
            ctx->format = FLB_OUT_FILE_FMT_JSON;
        }
        else {
            flb_plg_error(ctx->ins, "unknown format %s. abort.", tmp);
            flb_lock_destroy(&ctx->list_lock);
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

    /* Log configuration if rotation is enabled */
    if (ctx->files_rotation == FLB_TRUE && ctx->max_size > 0) {
        flb_plg_info(ctx->ins,
                     "file rotation enabled: max_size=%zu, max_files=%d, "
                     "gzip=%s, path=%s",
                     ctx->max_size, ctx->max_files,
                     ctx->gzip == FLB_TRUE ? "true" : "false",
                     ctx->out_path ? ctx->out_path : "not set");
    }

    /* Set the context */
    flb_output_set_context(ins, ctx);

    return 0;
}

static int csv_output(FILE *fp, int column_names, struct flb_time *tm,
                      msgpack_object *obj, struct flb_file_conf *ctx)
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
                msgpack_object_print(fp, (kv + i)->key);
                if (i + 1 < map_size) {
                    fprintf(fp, "%s", ctx->delimiter);
                }
            }
            fprintf(fp, NEWLINE);
        }

        fprintf(fp, "%lld.%.09ld%s", (long long)tm->tm.tv_sec, tm->tm.tv_nsec,
                ctx->delimiter);

        for (i = 0; i < map_size - 1; i++) {
            msgpack_object_print(fp, (kv + i)->val);
            fprintf(fp, "%s", ctx->delimiter);
        }

        msgpack_object_print(fp, (kv + (map_size - 1))->val);
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
        fprintf(fp, "\"time\"%s%f%s", ctx->label_delimiter,
                flb_time_to_double(tm), ctx->delimiter);

        for (i = 0; i < map_size - 1; i++) {
            msgpack_object_print(fp, (kv + i)->key);
            fprintf(fp, "%s", ctx->label_delimiter);
            msgpack_object_print(fp, (kv + i)->val);
            fprintf(fp, "%s", ctx->delimiter);
        }

        msgpack_object_print(fp, (kv + (map_size - 1))->key);
        fprintf(fp, "%s", ctx->label_delimiter);
        msgpack_object_print(fp, (kv + (map_size - 1))->val);
        fprintf(fp, NEWLINE);
    }
    return 0;
}

static int template_output_write(struct flb_file_conf *ctx, FILE *fp,
                                 struct flb_time *tm, msgpack_object *obj,
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
    const char *inbrace = NULL; /* points to the last open brace */

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

static int plain_output(FILE *fp, msgpack_object *obj, size_t alloc_size,
                        int escape_unicode)
{
    char *buf;

    buf = flb_msgpack_to_json_str(alloc_size, obj, escape_unicode);
    if (buf) {
        fprintf(fp, "%s" NEWLINE, buf);
        flb_free(buf);
    }
    return 0;
}

static void print_metrics_text(struct flb_output_instance *ins, FILE *fp,
                               const void *data, size_t bytes)
{
    int ret;
    size_t off = 0;
    cfl_sds_t text;
    struct cmt *cmt = NULL;

    /* get cmetrics context */
    ret = cmt_decode_msgpack_create(&cmt, (char *)data, bytes, &off);
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
        if (S_ISDIR(st.st_mode)) {
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
        if (S_ISDIR(st.st_mode)) {
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

/* Helper function to find a file size entry by filename */
static struct file_file_size *find_file_size_entry(struct flb_file_conf *ctx,
                                                   const char *filename)
{
    struct mk_list *head;
    struct file_file_size *entry;

    /* Caller must hold ctx->list_lock */
    mk_list_foreach(head, &ctx->file_sizes)
    {
        entry = mk_list_entry(head, struct file_file_size, _head);
        if (entry->filename && strcmp(entry->filename, filename) == 0) {
            return entry;
        }
    }
    return NULL;
}

/* Helper function to create file size entry */
static struct file_file_size *create_file_size_entry(struct flb_file_conf *ctx,
                                                     const char *filename,
                                                     size_t size)
{
    struct file_file_size *entry;
    flb_sds_t filename_copy;

    /* Caller must hold ctx->list_lock */

    /* Create new entry */
    entry = flb_calloc(1, sizeof(struct file_file_size));
    if (!entry) {
        flb_errno();
        return NULL;
    }

    filename_copy = flb_sds_create(filename);
    if (!filename_copy) {
        flb_free(entry);
        flb_errno();
        return NULL;
    }

    entry->filename = filename_copy;
    entry->size = size;

    /* Initialize mutex for this file entry */
    if (flb_lock_init(&entry->lock) != 0) {
        flb_plg_error(ctx->ins, "failed to initialize mutex for file %s",
                      filename);
        flb_sds_destroy(filename_copy);
        flb_free(entry);
        return NULL;
    }

    mk_list_add(&entry->_head, &ctx->file_sizes);

    return entry;
}

/* Function to generate timestamp for rotated file */
static void generate_timestamp(char *timestamp, size_t size)
{
    time_t now = time(NULL);
    struct tm tm_info;
    if (localtime_r(&now, &tm_info) == NULL) {
        /* Keep a valid deterministic suffix if localtime conversion fails. */
        snprintf(timestamp, size, "19700101_000000");
        return;
    }
    strftime(timestamp, size, "%Y%m%d_%H%M%S", &tm_info);
}

/* Helper function to write gzip header (based on flb_gzip.c) */
static void write_gzip_header(FILE *fp)
{
    time_t now;
    uint32_t mtime;
    uint8_t header[GZIP_HEADER_SIZE] = {
        0x1F, 0x8B,             /* Magic bytes */
        0x08,                   /* Compression method (deflate) */
        0x00,                   /* Flags */
        0x00, 0x00, 0x00, 0x00, /* Timestamp */
        0x00,                   /* Compression flags */
        0xFF                    /* OS (unknown) */
    };

    now = time(NULL);
    if (now == (time_t) -1) {
        mtime = 0;
    }
    else {
        mtime = (uint32_t) now;
    }

    /* RFC1952 MTIME field in little-endian format */
    header[4] = (uint8_t) (mtime & 0xFF);
    header[5] = (uint8_t) ((mtime >> 8) & 0xFF);
    header[6] = (uint8_t) ((mtime >> 16) & 0xFF);
    header[7] = (uint8_t) ((mtime >> 24) & 0xFF);

    fwrite(header, 1, GZIP_HEADER_SIZE, fp);
}

/* Helper function to write gzip footer */
static void write_gzip_footer(FILE *fp, mz_ulong crc, size_t original_size)
{
    uint8_t footer[GZIP_FOOTER_SIZE];

    /* Write CRC32 */
    footer[0] = crc & 0xFF;
    footer[1] = (crc >> 8) & 0xFF;
    footer[2] = (crc >> 16) & 0xFF;
    footer[3] = (crc >> 24) & 0xFF;

    /* Write original size */
    footer[4] = original_size & 0xFF;
    footer[5] = (original_size >> 8) & 0xFF;
    footer[6] = (original_size >> 16) & 0xFF;
    footer[7] = (original_size >> 24) & 0xFF;

    fwrite(footer, 1, GZIP_FOOTER_SIZE, fp);
}

/* Function to compress a file using streaming gzip (memory-safe for large
 * files) */
static int gzip_compress_file(const char *input_filename,
                              const char *output_filename,
                              struct flb_output_instance *ins)
{
    FILE *src_fp = NULL, *dst_fp = NULL;
    char *input_buffer = NULL, *output_buffer = NULL;
    size_t bytes_read, output_buffer_size;
    size_t total_input_size = 0;
    size_t compressed_bytes = 0;
    mz_ulong crc = MZ_CRC32_INIT;
    z_stream strm;
    int ret = 0, flush, status;
    int deflate_initialized = 0;

    /* Open source file */
    src_fp = fopen(input_filename, "rb");
    if (!src_fp) {
        flb_plg_error(ins, "failed to open source file for gzip: %s",
                      input_filename);
        return -1;
    }

    /* Open destination file */
    dst_fp = fopen(output_filename, "wb");
    if (!dst_fp) {
        flb_plg_error(ins, "failed to create gzip file: %s", output_filename);
        fclose(src_fp);
        return -1;
    }

    /* Allocate input and output buffers */
    input_buffer = flb_malloc(GZIP_CHUNK_SIZE);
    /* Use mz_compressBound to ensure sufficient buffer size for miniz */
    output_buffer_size = mz_compressBound(GZIP_CHUNK_SIZE);
    output_buffer = flb_malloc(output_buffer_size);

    if (!input_buffer || !output_buffer) {
        flb_plg_error(ins, "failed to allocate compression buffers");
        ret = -1;
        goto cleanup;
    }

    /* Write gzip header */
    write_gzip_header(dst_fp);

    /* Initialize deflate stream (raw deflate without gzip wrapper) */
    memset(&strm, 0, sizeof(strm));
    strm.zalloc = Z_NULL;
    strm.zfree = Z_NULL;
    strm.opaque = Z_NULL;

    status = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
                          -Z_DEFAULT_WINDOW_BITS, 9, Z_DEFAULT_STRATEGY);
    if (status != Z_OK) {
        flb_plg_error(ins, "failed to initialize deflate stream");
        ret = -1;
        goto cleanup;
    }
    deflate_initialized = 1;

    /* Process file in chunks */
    do {
        bytes_read = fread(input_buffer, 1, GZIP_CHUNK_SIZE, src_fp);
        if (bytes_read > 0) {
            /* Update CRC and total size */
            crc =
                mz_crc32(crc, (const unsigned char *)input_buffer, bytes_read);
            total_input_size += bytes_read;

            /* Set up deflate input */
            strm.next_in = (Bytef *)input_buffer;
            strm.avail_in = bytes_read;

            /* Determine flush mode based on EOF after this read */
            flush = feof(src_fp) ? Z_FINISH : Z_NO_FLUSH;

            /* Compress chunk */
            do {
                strm.next_out = (Bytef *)output_buffer;
                strm.avail_out = output_buffer_size;

                status = deflate(&strm, flush);
                if (status == Z_STREAM_ERROR) {
                    flb_plg_error(ins,
                                  "deflate stream error during compression");
                    ret = -1;
                    goto deflate_cleanup;
                }

                /* Write compressed data */
                compressed_bytes = output_buffer_size - strm.avail_out;
                if (compressed_bytes > 0) {
                    if (fwrite(output_buffer, 1, compressed_bytes, dst_fp) !=
                        compressed_bytes) {
                        flb_plg_error(ins, "failed to write compressed data");
                        ret = -1;
                        goto deflate_cleanup;
                    }
                }
            } while (strm.avail_out == 0);

            /* Verify all input was consumed */
            if (strm.avail_in != 0) {
                flb_plg_error(ins, "deflate did not consume all input data");
                ret = -1;
                goto deflate_cleanup;
            }
        }
    } while (bytes_read > 0 && status != Z_STREAM_END);

    /* Distinguish I/O error from normal EOF */
    if (ferror(src_fp)) {
        flb_plg_error(ins, "read error on source file: %s", input_filename);
        ret = -1;
        goto deflate_cleanup;
    }
    

    /*
     * If the file size is a multiple of GZIP_CHUNK_SIZE, the loop above
     * finishes because bytes_read == 0, but Z_FINISH was never called (flush
     * was Z_NO_FLUSH). We must ensure the stream is finished.
     */
    if (status != Z_STREAM_END) {
        strm.next_in = Z_NULL;
        strm.avail_in = 0;

        do {
            strm.next_out = (Bytef *)output_buffer;
            strm.avail_out = output_buffer_size;

            status = deflate(&strm, Z_FINISH);
            if (status == Z_STREAM_ERROR) {
                flb_plg_error(ins, "deflate stream error during final flush");
                ret = -1;
                goto deflate_cleanup;
            }

            compressed_bytes = output_buffer_size - strm.avail_out;
            if (compressed_bytes > 0) {
                if (fwrite(output_buffer, 1, compressed_bytes, dst_fp) !=
                    compressed_bytes) {
                    flb_plg_error(
                        ins, "failed to write compressed data (final flush)");
                    ret = -1;
                    goto deflate_cleanup;
                }
            }
        } while (status != Z_STREAM_END);
    }

    /* Verify compression completed successfully */
    if (status != Z_STREAM_END) {
        flb_plg_error(ins, "compression did not complete properly");
        ret = -1;
    }
    else {
        /* Write gzip footer (CRC32 + original size) */
        write_gzip_footer(dst_fp, crc, total_input_size);
    }

deflate_cleanup:
    if (deflate_initialized) {
        deflateEnd(&strm);
        deflate_initialized = 0;
    }

cleanup:
    if (input_buffer) {
        flb_free(input_buffer);
        input_buffer = NULL;
    }
    if (output_buffer) {
        flb_free(output_buffer);
        output_buffer = NULL;
    }
    if (src_fp) {
        fclose(src_fp);
        src_fp = NULL;
    }
    if (dst_fp) {
        fclose(dst_fp);
        dst_fp = NULL;
    }

    return ret;
}

/* Function to rotate file */
static int rotate_file(struct flb_file_conf *ctx, const char *filename,
                       struct file_file_size *entry)
{
    char timestamp[32];
    char *rotated_filename = NULL;
    char *gzip_filename = NULL;
    size_t file_size = 0;
    int ret = 0;

    /* Caller must hold entry->lock */

    rotated_filename = flb_malloc(PATH_MAX);
    if (!rotated_filename) {
        flb_errno();
        return -1;
    }

    if (ctx->gzip == FLB_TRUE) {
        gzip_filename = flb_malloc(PATH_MAX);
        if (!gzip_filename) {
            flb_free(rotated_filename);
            flb_errno();
            return -1;
        }
    }

    file_size = entry->size;

    /* Log rotation event */
    flb_plg_info(ctx->ins, "rotating file: %s (current size: %zu bytes)",
                 filename, file_size);

    /* Generate timestamp */
    generate_timestamp(timestamp, sizeof(timestamp));

    /* Create rotated filename with timestamp */
    snprintf(rotated_filename, PATH_MAX - 1, "%s.%s", filename, timestamp);

#ifndef FLB_SYSTEM_WINDOWS
    /*
     * Best-effort durability fence before renaming the active file.
     * This keeps rotation boundary semantics without paying fsync cost
     * on every flush.
     */
    {
        int fd;

        fd = open(filename, O_RDONLY);
        if (fd >= 0) {
            if (fsync(fd) != 0) {
                flb_plg_warn(ctx->ins, "failed to sync file before rotation: %s",
                             filename);
            }
            close(fd);
        }
    }
#endif

    /* Rename current file to rotated filename */
    if (rename(filename, rotated_filename) != 0) {
        flb_plg_error(ctx->ins, "failed to rename file from %s to %s", filename,
                      rotated_filename);
        ret = -1;
        goto cleanup;
    }

    /* If gzip is enabled, compress the rotated file */
    if (ctx->gzip == FLB_TRUE) {
        snprintf(gzip_filename, PATH_MAX - 1, "%s.gz", rotated_filename);
        flb_plg_debug(ctx->ins, "compressing file: %s to %s", rotated_filename,
                      gzip_filename);
        ret = gzip_compress_file(rotated_filename, gzip_filename, ctx->ins);
        if (ret == 0) {
            /* Remove the uncompressed file */
#ifdef FLB_SYSTEM_WINDOWS
            DeleteFileA(rotated_filename);
#else
            unlink(rotated_filename);
#endif
            flb_plg_debug(ctx->ins, "rotated and compressed file: %s",
                          gzip_filename);
        }
        else {
            /* Remove the failed gzip file */
#ifdef FLB_SYSTEM_WINDOWS
            DeleteFileA(gzip_filename);
#else
            unlink(gzip_filename);
#endif
            ret = -1;
            goto cleanup;
        }
    }
    else {
        flb_plg_debug(ctx->ins, "rotated file: %s (no compression)",
                      rotated_filename);
    }

    /* Reset file size in the entry since we rotated */
    entry->size = 0;

cleanup:
    if (rotated_filename) {
        flb_free(rotated_filename);
    }
    if (gzip_filename) {
        flb_free(gzip_filename);
    }

    return ret;
}

/*
 * Function to validate if a filename matches the rotation pattern format
 * Valid formats:
 *   - base_filename.YYYYMMDD_HHMMSS (15 chars after pattern)
 *   - base_filename.YYYYMMDD_HHMMSS.gz (18 chars after pattern)
 */
static int is_valid_rotation_filename(const char *filename, const char *pattern)
{
    size_t pattern_len = strlen(pattern);
    size_t filename_len = strlen(filename);
    const char *suffix;
    size_t suffix_len;
    int i;

    /* Check that filename starts with pattern */
    if (strncmp(filename, pattern, pattern_len) != 0) {
        return 0;
    }

    /* Get the suffix after the pattern */
    suffix = filename + pattern_len;
    suffix_len = filename_len - pattern_len;

    /* Must be exactly 15 or 18 characters */
    if (suffix_len != 15 && suffix_len != 18) {
        return 0;
    }

    /* For 18 characters, must end with .gz */
    if (suffix_len == 18) {
        if (strcmp(suffix + 15, ".gz") != 0) {
            return 0;
        }
    }

    /* Validate timestamp format: YYYYMMDD_HHMMSS
     * 8 digits (YYYYMMDD)
     * underscore at position 8
     * 6 digits (HHMMSS)
     */
    for (i = 0; i < 8; i++) {
        if (suffix[i] < '0' || suffix[i] > '9') {
            return 0;
        }
    }
    if (suffix[8] != '_') {
        return 0;
    }
    for (i = 9; i < 15; i++) {
        if (suffix[i] < '0' || suffix[i] > '9') {
            return 0;
        }
    }

    return 1;
}

/* Function to clean up old rotated files */
static int cleanup_old_files(struct flb_file_conf *ctx, const char *directory,
                             const char *base_filename)
{
    char pattern[PATH_MAX];
    char full_path[PATH_MAX];
#ifdef FLB_SYSTEM_WINDOWS
    char search_path[PATH_MAX];
#endif
    char **files = NULL;
    int file_count = 0;
    int max_files = ctx->max_files;
    int i, j;

    /* Create pattern to match rotated files */
    snprintf(pattern, PATH_MAX - 1, "%s.", base_filename);

#ifdef FLB_SYSTEM_WINDOWS
    HANDLE hFind;
    WIN32_FIND_DATA findData;

    /* Create search path: directory\* */
    snprintf(search_path, PATH_MAX - 1, "%s" FLB_PATH_SEPARATOR "*", directory);

    hFind = FindFirstFileA(search_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        return 0; /* Directory doesn't exist or can't be opened */
    }

    /* Count matching files */
    do {
        /* Skip . and .. */
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }
        /* Skip directories */
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (is_valid_rotation_filename(findData.cFileName, pattern)) {
            file_count++;
        }
    } while (FindNextFileA(hFind, &findData) != 0);

    if (file_count <= max_files) {
        FindClose(hFind);
        return 0;
    }

    /* Allocate array for file names */
    files = flb_calloc(file_count, sizeof(char *));
    if (!files) {
        FindClose(hFind);
        return -1;
    }

    /* Collect file names - restart search */
    FindClose(hFind);
    hFind = FindFirstFileA(search_path, &findData);
    if (hFind == INVALID_HANDLE_VALUE) {
        flb_free(files);
        return -1;
    }

    i = 0;
    do {
        /* Skip . and .. */
        if (strcmp(findData.cFileName, ".") == 0 ||
            strcmp(findData.cFileName, "..") == 0) {
            continue;
        }
        /* Skip directories */
        if (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        if (is_valid_rotation_filename(findData.cFileName, pattern) &&
            i < file_count) {
            snprintf(full_path, PATH_MAX - 1, "%s" FLB_PATH_SEPARATOR "%s",
                     directory, findData.cFileName);
            files[i] = flb_strdup(full_path);
            i++;
        }
    } while (FindNextFileA(hFind, &findData) != 0 && i < file_count);

    FindClose(hFind);
#else
    DIR *dir;
    struct dirent *entry;

    dir = opendir(directory);
    if (!dir) {
        return 0; /* Directory doesn't exist or can't be opened */
    }

    /* Count matching files */
    while ((entry = readdir(dir)) != NULL) {
        if (is_valid_rotation_filename(entry->d_name, pattern)) {
            file_count++;
        }
    }

    if (file_count <= max_files) {
        closedir(dir);
        return 0;
    }

    /* Allocate array for file names */
    files = flb_calloc(file_count, sizeof(char *));
    if (!files) {
        closedir(dir);
        return -1;
    }

    /* Collect file names */
    rewinddir(dir);
    i = 0;
    while ((entry = readdir(dir)) != NULL && i < file_count) {
        if (is_valid_rotation_filename(entry->d_name, pattern)) {
            snprintf(full_path, PATH_MAX - 1, "%s" FLB_PATH_SEPARATOR "%s",
                     directory, entry->d_name);
            files[i] = flb_strdup(full_path);
            i++;
        }
    }
    closedir(dir);
#endif

    /* Sort files by modification time (oldest first) */
    for (i = 0; i < file_count - 1; i++) {
        for (j = i + 1; j < file_count; j++) {
            struct stat st1;
            struct stat st2;

            if (!files[i] || !files[j]) {
                continue;
            }

            if (stat(files[i], &st1) == 0 && stat(files[j], &st2) == 0) {
                if (st1.st_mtime > st2.st_mtime) {
                    char *temp = files[i];
                    files[i] = files[j];
                    files[j] = temp;
                }
            }
        }
    }

    /* Remove oldest files */
    if (file_count > max_files) {
        flb_plg_info(
            ctx->ins,
            "cleaning up old rotated files: removing %d files (keeping %d)",
            file_count - max_files, max_files);
    }
    for (i = 0; i < file_count - max_files; i++) {
        if (files[i]) {
#ifdef FLB_SYSTEM_WINDOWS
            if (DeleteFileA(files[i]) != 0) {
#else
            if (unlink(files[i]) == 0) {
#endif
                flb_plg_debug(ctx->ins, "removed old rotated file: %s",
                              files[i]);
            }
            flb_free(files[i]);
        }
    }

    /* Free remaining file names */
    for (i = file_count - max_files; i < file_count; i++) {
        if (files[i]) {
            flb_free(files[i]);
        }
    }

    flb_free(files);
    return 0;
}

static void cb_file_flush(struct flb_event_chunk *event_chunk,
                          struct flb_output_flush *out_flush,
                          struct flb_input_instance *ins, void *out_context,
                          struct flb_config *config)
{
    int ret;
    int ret_val = FLB_OK;
    int column_names;
    FILE *fp;
    size_t off = 0;
    size_t last_off = 0;
    size_t alloc_size = 0;
    size_t total;
    size_t file_size = 0;
    size_t tag_len;
    size_t file_name_len;
    size_t path_len;
    size_t sep_len;
    size_t out_file_size;
    int use_out_path;
    char *out_file = NULL;
    char *sanitized_tag = NULL;
    char *buf;
    char *out_file_copy;
    char *directory = NULL;
    char *base_filename = NULL;
    int written;
    long file_pos;
    bool have_directory;
    struct flb_file_conf *ctx = out_context;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    struct file_file_size *entry = NULL;
    struct stat st;
    bool entry_just_created = false;

    (void)config;

    /* Set the right output file */
    if (ctx->out_file == NULL) {
        tag_len = strlen(event_chunk->tag);
        sanitized_tag = flb_malloc(tag_len + 1);
        if (!sanitized_tag) {
            flb_errno();
            ret_val = FLB_ERROR;
            goto cleanup;
        }

        ret = sanitize_tag_name(event_chunk->tag, sanitized_tag, tag_len + 1);

        if (ret != 0) {
            flb_plg_error(ctx->ins, "failed to sanitize tag for output file");
            ret_val = FLB_ERROR;
            goto cleanup;
        }
    }

    file_name_len = strlen(ctx->out_file ? ctx->out_file : sanitized_tag);
    use_out_path = (ctx->out_path != NULL && ctx->out_path[0] != '\0');
    path_len = use_out_path ? strlen(ctx->out_path) : 0;
    sep_len = use_out_path ? strlen(FLB_PATH_SEPARATOR) : 0;
    out_file_size = path_len + sep_len + file_name_len + 1;

    out_file = flb_malloc(out_file_size);
    if (!out_file) {
        flb_errno();
        ret_val = FLB_ERROR;
        goto cleanup;
    }

    if (use_out_path) {
        written = snprintf(out_file, out_file_size, "%s" FLB_PATH_SEPARATOR "%s",
                           ctx->out_path,
                           ctx->out_file ? ctx->out_file : sanitized_tag);
    }
    else {
        written = snprintf(out_file, out_file_size, "%s",
                           ctx->out_file ? ctx->out_file : sanitized_tag);
    }

    if (written < 0 || (size_t) written >= out_file_size) {
        flb_plg_error(ctx->ins, "failed to build output file path");
        ret_val = FLB_ERROR;
        goto cleanup;
    }

    /* Rotation logic - only if files_rotation enabled and max_size > 0 */
    if (ctx->files_rotation == FLB_TRUE && ctx->max_size > 0) {
        /* Find or create file size entry and acquire lock (Hand-Over-Hand) */
        if (flb_lock_acquire(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY) != 0) {
            ret_val = FLB_ERROR;
            goto cleanup;
        }

        entry = find_file_size_entry(ctx, out_file);
        if (entry == NULL) {
            /* Entry doesn't exist yet, create it with initial size 0 */
            entry = create_file_size_entry(ctx, out_file, 0);
            if (entry == NULL) {
                flb_lock_release(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                                 FLB_LOCK_DEFAULT_RETRY_DELAY);
                ret_val = FLB_ERROR;
                goto cleanup;
            }
            entry_just_created = true;
        }

        /* Acquire lock before any file operations */
        if (flb_lock_acquire(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY) != 0) {
            flb_plg_error(ctx->ins, "failed to acquire lock for file %s",
                          out_file);
            flb_lock_release(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
            ret_val = FLB_ERROR;
            goto cleanup;
        }

        /* Release list lock now that we hold the entry lock */
        flb_lock_release(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY);

        /* If entry was just created, seed size from on-disk file to handle
         * pre-existing files that may already exceed max_size on startup.
         * This ensures rotation decision is correct on first flush.
         */
        if (entry_just_created && entry->size == 0) {
            if (stat(out_file, &st) == 0 && st.st_size >= 0) {
                entry->size = (size_t)st.st_size;
            }
        }

        /* Check if file needs rotation based on current size counter */
        file_size = entry->size;

        if (file_size >= ctx->max_size) {
            have_directory = false;

            directory = flb_malloc(PATH_MAX);
            if (!directory) {
                flb_errno();
                flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                                 FLB_LOCK_DEFAULT_RETRY_DELAY);
                ret_val = FLB_ERROR;
                goto cleanup;
            }
            directory[0] = '\0';

            base_filename = flb_malloc(PATH_MAX);
            if (!base_filename) {
                flb_errno();
                flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                                 FLB_LOCK_DEFAULT_RETRY_DELAY);
                ret_val = FLB_ERROR;
                goto cleanup;
            }

            /* Extract directory and base filename for cleanup */
            out_file_copy = flb_strdup(out_file);
            if (out_file_copy) {
#ifdef FLB_SYSTEM_WINDOWS
                PathRemoveFileSpecA(out_file_copy);
                strncpy(directory, out_file_copy, PATH_MAX - 1);
                directory[PATH_MAX - 1] = '\0';
#else
                strncpy(directory, dirname(out_file_copy), PATH_MAX - 1);
                directory[PATH_MAX - 1] = '\0';
#endif
                flb_free(out_file_copy);
                have_directory = true;
            }

            /* Get base filename for cleanup */
            {
                char *last_sep = strrchr(out_file, FLB_PATH_SEPARATOR[0]);
                if (last_sep) {
                    strncpy(base_filename, last_sep + 1, PATH_MAX - 1);
                }
                else {
                    strncpy(base_filename, out_file, PATH_MAX - 1);
                }
                base_filename[PATH_MAX - 1] = '\0';
            }

            /* Rotate the file - passing entry, with lock held */
            if (rotate_file(ctx, out_file, entry) == 0) {
                /* Clean up old rotated files */
                if (have_directory) {
                    cleanup_old_files(ctx, directory, base_filename);
                }
            }
        }
    }

    /* Open output file with default name as the Tag */
    /* Use "a" mode for thread-safe append operations - automatically seeks to
     * end */
    fp = fopen(out_file, "ab");
    if (ctx->mkdir == FLB_TRUE && fp == NULL && errno == ENOENT) {
        out_file_copy = flb_strdup(out_file);
        if (out_file_copy) {
#ifdef FLB_SYSTEM_WINDOWS
            PathRemoveFileSpecA(out_file_copy);
            ret = mkpath(ctx->ins, out_file_copy);
#else
            ret = mkpath(ctx->ins, dirname(out_file_copy));
#endif
            flb_free(out_file_copy);
            if (ret == 0) {
                fp = fopen(out_file, "ab");
            }
        }
    }
    if (fp == NULL) {
        flb_errno();
        flb_plg_error(ctx->ins, "error opening: %s", out_file);
        /* Release lock before returning */
        if (entry != NULL) {
            flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
        }
        ret_val = FLB_ERROR;
        goto cleanup;
    }

    /* Initialize file size counter if this is a new file (for rotation) */
    if (ctx->files_rotation == FLB_TRUE && ctx->max_size > 0 && entry != NULL) {
        if (entry->size == 0) {
            /* We already have the entry and the lock, update size directly. */
            /* Flush first to ensure all previous writes are visible */
            fflush(fp);
            if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
                entry->size = (size_t)st.st_size;
            }
        }
    }

    /*
     * Get current file stream position, we gather this in case 'csv' format
     * needs to write the column names.
     * With "a" mode, ftell() returns the current position (end of file).
     */
    file_pos = ftell(fp);

    /* Check if the event type is metrics, handle the payload differently */
    if (event_chunk->type == FLB_INPUT_METRICS) {
        print_metrics_text(ctx->ins, fp, event_chunk->data, event_chunk->size);
        /* Flush all buffered data before updating size counter */
        fflush(fp);
        /* Update file size counter - we already hold the lock */
        if (entry != NULL) {
            if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
                entry->size = (size_t)st.st_size;
            }
        }
        fclose(fp);
        /* Release lock before returning */
        if (entry != NULL) {
            flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
        }
        ret_val = FLB_OK;
        goto cleanup;
    }

    /*
     * Msgpack output format used to create unit tests files, useful for
     * Fluent Bit developers.
     */
    if (ctx->format == FLB_OUT_FILE_FMT_MSGPACK) {
        off = 0;
        total = 0;

        do {
            ret = fwrite((char *)event_chunk->data + off, 1,
                         event_chunk->size - off, fp);
            if (ret < 0) {
                flb_errno();
                fclose(fp);
                /* Release lock before returning */
                if (entry != NULL) {
                    flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                                     FLB_LOCK_DEFAULT_RETRY_DELAY);
                }
                ret_val = FLB_RETRY;
                goto cleanup;
            }
            total += ret;
        } while (total < event_chunk->size);

        /* Flush all buffered data before updating size counter */
        fflush(fp);
        /* Update file size counter - we already hold the lock */
        if (entry != NULL) {
            if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
                entry->size = (size_t)st.st_size;
            }
        }
        fclose(fp);
        /* Release lock before returning */
        if (entry != NULL) {
            flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
        }
        ret_val = FLB_OK;
        goto cleanup;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *)event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins, "Log event decoder initialization error : %d",
                      ret);

        /* Flush any buffered data before updating size counter */
        fflush(fp);
        /* Update file size counter before closing - we already hold the lock */
        if (entry != NULL) {
            if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
                entry->size = (size_t)st.st_size;
            }
        }
        fclose(fp);
        /* Release lock before returning */
        if (entry != NULL) {
            flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                             FLB_LOCK_DEFAULT_RETRY_DELAY);
        }
        ret_val = FLB_ERROR;
        goto cleanup;
    }

    /*
     * Upon flush, for each array, lookup the time and the first field
     * of the map to use as a data point.
     */
    while ((ret = flb_log_event_decoder_next(&log_decoder, &log_event)) ==
           FLB_EVENT_DECODER_SUCCESS) {
        alloc_size = (off - last_off) + 128; /* JSON is larger than msgpack */
        last_off = off;

        switch (ctx->format) {
        case FLB_OUT_FILE_FMT_JSON:
            buf = flb_msgpack_to_json_str(alloc_size, log_event.body,
                                          config->json_escape_unicode);
            if (buf) {
                fprintf(fp, "%s: [%" PRIu64 ".%09lu, %s]" NEWLINE,
                        event_chunk->tag,
                        (uint64_t)log_event.timestamp.tm.tv_sec,
                        log_event.timestamp.tm.tv_nsec, buf);
                flb_free(buf);
            }
            else {
                /* Flush any buffered data before updating size counter */
                fflush(fp);
                /* Update file size counter - we already hold the lock */
                if (entry != NULL) {
                    if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
                        entry->size = (size_t)st.st_size;
                    }
                }
                flb_log_event_decoder_destroy(&log_decoder);
                fclose(fp);
                /* Release lock before returning */
                if (entry != NULL) {
                    flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                                     FLB_LOCK_DEFAULT_RETRY_DELAY);
                }
                ret_val = FLB_RETRY;
                goto cleanup;
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
            csv_output(fp, column_names, &log_event.timestamp, log_event.body,
                       ctx);
            break;
        case FLB_OUT_FILE_FMT_LTSV:
            ltsv_output(fp, &log_event.timestamp, log_event.body, ctx);
            break;
        case FLB_OUT_FILE_FMT_PLAIN:
            plain_output(fp, log_event.body, alloc_size,
                         config->json_escape_unicode);

            break;
        case FLB_OUT_FILE_FMT_TEMPLATE:
            template_output(fp, &log_event.timestamp, log_event.body, ctx);

            break;
        }
    }

    flb_log_event_decoder_destroy(&log_decoder);

    /* Flush all buffered data before updating size counter */
    fflush(fp);
    /* Update file size counter - we already hold the lock */
    if (entry != NULL) {
        if (fstat(fileno(fp), &st) == 0 && st.st_size >= 0) {
            entry->size = (size_t)st.st_size;
        }
    }
    fclose(fp);

    /* Release lock before returning */
    if (entry != NULL) {
        flb_lock_release(&entry->lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                         FLB_LOCK_DEFAULT_RETRY_DELAY);
    }

    ret_val = FLB_OK;

cleanup:
    if (out_file) {
        flb_free(out_file);
    }
    if (sanitized_tag) {
        flb_free(sanitized_tag);
    }
    if (directory) {
        flb_free(directory);
    }
    if (base_filename) {
        flb_free(base_filename);
    }
    FLB_OUTPUT_RETURN(ret_val);
}

static int cb_file_exit(void *data, struct flb_config *config)
{
    struct flb_file_conf *ctx = data;
    struct mk_list *head;
    struct mk_list *tmp;
    struct file_file_size *entry;

    if (!ctx) {
        return 0;
    }

    /* Free all file size entries from linked list */
    flb_lock_acquire(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);
    mk_list_foreach_safe(head, tmp, &ctx->file_sizes)
    {
        entry = mk_list_entry(head, struct file_file_size, _head);
        mk_list_del(&entry->_head);
        /* Destroy mutex before freeing entry */
        flb_lock_destroy(&entry->lock);
        if (entry->filename) {
            flb_sds_destroy(entry->filename);
        }
        flb_free(entry);
    }
    flb_lock_release(&ctx->list_lock, FLB_LOCK_DEFAULT_RETRY_LIMIT,
                     FLB_LOCK_DEFAULT_RETRY_DELAY);
    flb_lock_destroy(&ctx->list_lock);

    flb_free(ctx);
    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {FLB_CONFIG_MAP_STR, "path", NULL, 0, FLB_TRUE,
     offsetof(struct flb_file_conf, out_path),
     "Absolute path to store the files. This parameter is optional"},

    {FLB_CONFIG_MAP_STR, "file", NULL, 0, FLB_TRUE,
     offsetof(struct flb_file_conf, out_file),
     "Name of the target file to write the records. If 'path' is specified, "
     "the value is prefixed"},

    {FLB_CONFIG_MAP_STR, "format", NULL, 0, FLB_FALSE, 0,
     "Specify the output data format, the available options are: plain (json), "
     "csv, ltsv and template. If no value is set the outgoing data is "
     "formatted "
     "using the tag and the record in json"},

    {FLB_CONFIG_MAP_STR, "delimiter", NULL, 0, FLB_FALSE, 0,
     "Set a custom delimiter for the records"},

    {FLB_CONFIG_MAP_STR, "label_delimiter", NULL, 0, FLB_FALSE, 0,
     "Set a custom label delimiter, to be used with 'ltsv' format"},

    {FLB_CONFIG_MAP_STR, "template", "{time} {message}", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, template),
     "Set a custom template format for the data"},

    {FLB_CONFIG_MAP_BOOL, "csv_column_names", "false", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, csv_column_names),
     "Add column names (keys) in the first line of the target file"},

    {FLB_CONFIG_MAP_BOOL, "mkdir", "false", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, mkdir),
     "Recursively create output directory if it does not exist. Permissions "
     "set to 0755"},

    {FLB_CONFIG_MAP_BOOL, "files_rotation", "false", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, files_rotation),
     "Enable file rotation feature (default: false)"},

    {FLB_CONFIG_MAP_SIZE, "max_size", "100000000", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, max_size),
     "Maximum size of file before rotation (default: 100MB)"},

    {FLB_CONFIG_MAP_INT, "max_files", "7", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, max_files),
     "Maximum number of rotated files to keep (default: 7)"},

    {FLB_CONFIG_MAP_BOOL, "gzip", "true", 0, FLB_TRUE,
     offsetof(struct flb_file_conf, gzip),
     "Whether to gzip rotated files (default: true)"},

    /* EOF */
    {0}};

struct flb_output_plugin out_file_plugin = {
    .name = "file",
    .description = "Generate log file",
    .cb_init = cb_file_init,
    .cb_flush = cb_file_flush,
    .cb_exit = cb_file_exit,
    .flags = 0,
    .workers = 1,
    .event_type = FLB_OUTPUT_LOGS | FLB_OUTPUT_METRICS,
    .config_map = config_map,
};
