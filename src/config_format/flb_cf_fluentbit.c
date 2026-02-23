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
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_compat.h>

#include <monkey/mk_core.h>

#include <ctype.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _MSC_VER
#include <glob.h>
#endif

#ifdef _WIN32
#include <Windows.h>
#include <strsafe.h>
#define PATH_MAX MAX_PATH
#endif

#define FLB_CF_FILE_NUM_LIMIT 1000

/* indent checker return codes */
#define INDENT_ERROR          -1
#define INDENT_OK              0
#define INDENT_GROUP_CONTENT   1

/* Included file by configuration */
struct local_file {
    flb_sds_t path;
    struct mk_list _head;
};

/* Local context to keep state of variables and general  */
struct local_ctx {
    int level;
    char *file;
    flb_sds_t root_path;

    /* included files */
    struct mk_list includes;

    /* meta instructions */
    struct mk_list metas;

    /* list of sections */
    struct mk_list sections;
};

static int read_config(struct flb_cf *cf, struct local_ctx *ctx, char *cfg_file,
                       char *buf, size_t size, ino_t *ino_table, int *ino_num);

/* Raise a configuration schema error */
static void config_error(const char *path, int line, const char *msg)
{
    flb_error("[config] error in %s:%i: %s", path, line, msg);
}

/* Raise a warning */
static void config_warn(const char *path, int line, const char *msg)
{
    mk_warn("Config file warning '%s':\n"
            "\t\t\t\tat line %i: %s",
            path, line, msg);
}

static int char_search(const char *string, int c, int len)
{
    char *p;

    if (len < 0) {
        len = strlen(string);
    }

    p = memchr(string, c, len);
    if (p) {
        return (p - string);
    }

    return -1;
}

/*
 * Helper function to simulate a fgets(2) but instead of using a real file stream
 * uses the data buffer provided.
 */
#ifdef FLB_HAVE_STATIC_CONF

static int static_fgets(char *out, size_t size, const char *data, size_t *off)
{
    size_t len;
    const char *start = data + *off;
    char *end;

    end = strchr(start, '\n');

    if (!end || *off >= size) {
        len = size - *off - 1;
        memcpy(out, start, len);
        out[len] = '\0';
        *off += len + 1;
        return 0;
    }

    len = end - start;
    if (len >= size) {
        len = size - 1;
    }
    memcpy(out, start, len);
    out[len] = '\0';
    *off += len + 1;

    return 1;
}
#endif

#ifndef _WIN32
static int read_glob(struct flb_cf *cf, struct local_ctx *ctx, const char * path,
                     ino_t *ino_table, int *ino_num)
{
    int ret = -1;
    glob_t glb;
    char tmp[PATH_MAX];

    const char *glb_path;
    size_t i;
    int ret_glb = -1;

    if (ctx->root_path && path[0] != '/') {
        snprintf(tmp, PATH_MAX, "%s/%s", ctx->root_path, path);
        glb_path = tmp;
    }
    else {
        glb_path = path;
    }

    ret_glb = glob(glb_path, GLOB_NOSORT, NULL, &glb);
    if (ret_glb != 0) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            flb_warn("[%s] glob: [%s] no space", __FUNCTION__, glb_path);
            break;
        case GLOB_NOMATCH:
            flb_warn("[%s] glob: [%s] no match", __FUNCTION__, glb_path);
            break;
        case GLOB_ABORTED:
            flb_warn("[%s] glob: [%s] aborted", __FUNCTION__, glb_path);
            break;
        default:
            flb_warn("[%s] glob: [%s] other error", __FUNCTION__, glb_path);
        }
        return ret;
    }

    for (i = 0; i < glb.gl_pathc; i++) {
        ret = read_config(cf, ctx, glb.gl_pathv[i], NULL, 0, ino_table, ino_num);
        if (ret < 0) {
            break;
        }
    }

    globfree(&glb);
    return ret;
}
#else
static int read_glob(struct flb_cf *cf, struct local_ctx *ctx, const char *path,
                     ino_t *ino_table, int *ino_num)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    struct stat st;
    HANDLE h;
    WIN32_FIND_DATA data;

    if (strlen(path) > MAX_PATH - 1) {
        return -1;
    }

    star = strchr(path, '*');
    if (star == NULL) {
        return -1;
    }

    /*
     * C:\data\tmp\input_*.conf
     *            0<-----|
     */
    p0 = star;
    while (path <= p0 && *p0 != '\\') {
        p0--;
    }

    /*
     * C:\data\tmp\input_*.conf
     *                   |---->1
     */
    p1 = star;
    while (*p1 && *p1 != '\\') {
        p1++;
    }

    memcpy(pattern, path, (p1 - path));
    pattern[p1 - path] = '\0';

    h = FindFirstFileA(pattern, &data);
    if (h == INVALID_HANDLE_VALUE) {
        return 0;
    }

    do {
        /* Ignore the current and parent dirs */
        if (!strcmp(".", data.cFileName) || !strcmp("..", data.cFileName)) {
            continue;
        }

        /* Avoid an infinite loop */
        if (strchr(data.cFileName, '*')) {
            continue;
        }

        /* Create a path (prefix + filename + suffix) */
        memcpy(buf, path, p0 - path + 1);
        buf[p0 - path + 1] = '\0';

        if (FAILED(StringCchCatA(buf, MAX_PATH, data.cFileName))) {
            continue;
        }
        if (FAILED(StringCchCatA(buf, MAX_PATH, p1))) {
            continue;
        }

        if (strchr(p1, '*')) {
            read_glob(cf, ctx, buf, ino_table, ino_num); /* recursive */
            continue;
        }

        ret = stat(buf, &st);
        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
            if (read_config(cf, ctx, buf, NULL, 0, ino_table, ino_num) < 0) {
                return -1;
            }
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return 0;
}
#endif

static int local_init(struct local_ctx *ctx, char *file)
{
    char *end;
    char path[PATH_MAX + 1] = {0};

#ifndef FLB_HAVE_STATIC_CONF
    char *p;

    if (file) {
#ifdef _MSC_VER
        p = _fullpath(path, file, PATH_MAX + 1);
#else
        p = realpath(file, path);
#endif
        if (!p) {
            flb_errno();
            flb_error("file=%s", file);
            return -1;
        }
    }
#endif

    /* lookup path ending and truncate */
#ifdef _MSC_VER
    end = strrchr(path, '\\');
#else
    end = strrchr(path, '/');
#endif

    if (end) {
        end++;
        *end = '\0';
    }

    if (file) {
        ctx->file = flb_sds_create(file);
        ctx->root_path = flb_sds_create(path);
    }
    else {
        ctx->file = NULL;
        ctx->root_path = NULL;
    }

    ctx->level = 0;
    mk_list_init(&ctx->metas);
    mk_list_init(&ctx->sections);
    mk_list_init(&ctx->includes);

    return 0;
}

static void local_exit(struct local_ctx *ctx)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct local_file *f;

    mk_list_foreach_safe(head, tmp, &ctx->includes) {
        f = mk_list_entry(head, struct local_file, _head);
        flb_sds_destroy(f->path);
        mk_list_del(&f->_head);
        flb_free(f);
    }

    if (ctx->file) {
        flb_sds_destroy(ctx->file);
    }

    if (ctx->root_path) {
        flb_sds_destroy(ctx->root_path);
    }
}

static int is_file_included(struct local_ctx *ctx, const char *path)
{
    struct mk_list *head;
    struct local_file *file;

    mk_list_foreach(head, &ctx->includes) {
        file = mk_list_entry(head, struct local_file, _head);
        if (strcmp(file->path, path) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

static int check_indent(const char *line, const char *indent, int *out_level)
{
    int extra = 0;
    int level = 0;

    while (*line == *indent && *indent) {
        line++;
        indent++;
        level++;
    }

    if (*indent != '\0') {
        if (isblank(*line)) {
            flb_error("[config] inconsistent use of tab and space");
        }
        else {
            flb_error("[config] indentation level is too low");
        }
        return INDENT_ERROR;;
    }

    if (isblank(*line)) {
        /* check if we have a 'group' key/value line */
        while (isblank(*line)) {
            line++;
            extra++;
        }

        if (extra == level) {
            *out_level = level + extra;
            return INDENT_GROUP_CONTENT;
        }

        flb_error("[config] extra indentation level found");
        return -1;
    }

    *out_level = level;
    return INDENT_OK;
}

static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       char *cfg_file, char *in_data, size_t in_size,
                       ino_t *ino_table, int *ino_num)
{
    int i;
    int len;
    int ret;
    int end;
    int level;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char *key = NULL;
    int key_len;
    char *val = NULL;
    int val_len;
    char *buf;
    char *fgets_ptr;
    size_t bufsize = FLB_DEFAULT_CF_BUF_SIZE;
    char tmp[PATH_MAX];
    flb_sds_t section = NULL;
    flb_sds_t indent = NULL;
    struct stat st;
    struct local_file *file;
    struct flb_cf_meta *meta;
    struct flb_cf_section *current_section = NULL;
    struct flb_cf_group *current_group = NULL;
    struct cfl_variant *var;
    unsigned long line_hard_limit;

    line_hard_limit = 32 * 1024 * 1024; /* 32MiB */

    FILE *f = NULL;

    if (*ino_num >= FLB_CF_FILE_NUM_LIMIT) {
        return -1;
    }

    /* Check if the path exists (relative cases for included files) */
#ifndef FLB_HAVE_STATIC_CONF
    if (ctx->level >= 0) {
        ret = stat(cfg_file, &st);
        if (ret == -1 && errno == ENOENT) {
            /* Try to resolve the real path (if exists) */
            if (cfg_file[0] == '/') {
                return -1;
            }

            if (ctx->root_path) {
                snprintf(tmp, PATH_MAX, "%s/%s", ctx->root_path, cfg_file);
                cfg_file = tmp;
            }
            /* stat again */
            ret = stat(cfg_file, &st);
            if (ret < 0) {
                flb_errno();
                return -1;
            }
        }
#ifndef _WIN32
        /* check if readed file */
        for (i=0; i<*ino_num; i++) {
            if (st.st_ino == ino_table[i]) {
                flb_warn("[config] Read twice. path=%s", cfg_file);
                return -1;
            }
        }
        ino_table[*ino_num]  = st.st_ino;
        *ino_num += 1;
#endif
    }
#endif

    /* Check this file have not been included before */
    ret = is_file_included(ctx, cfg_file);
    if (ret) {
        flb_error("[config] file already included %s", cfg_file);
        return -1;
    }
    ctx->level++;

#ifndef FLB_HAVE_STATIC_CONF
    /* Open configuration file */
    if ((f = fopen(cfg_file, "rb")) == NULL) {
        flb_warn("[config] I cannot open %s file", cfg_file);
        return -1;
    }
#endif

    /* Allocate temporal buffer to read file content */
    buf = flb_malloc(bufsize);
    if (!buf) {
        flb_errno();
        goto error;
    }

#ifdef FLB_HAVE_STATIC_CONF
    /*
     * a static configuration comes from a buffer, so we use the static_fgets()
     * workaround to retrieve the lines.
     */
    size_t off = 0;
    while (static_fgets(buf, FLB_DEFAULT_CF_BUF_SIZE, in_data, &off)) {
#else
    /* normal mode, read lines into a buffer */
    /* note that we use "fgets_ptr" so we can continue reading after realloc */
    fgets_ptr = buf;
    while (fgets(fgets_ptr, bufsize - (fgets_ptr - buf), f)) {
#endif
        len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
            /* after a successful line read, restore "fgets_ptr" to point to the
             * beginning of buffer */
            fgets_ptr = buf;
        }
#ifndef FLB_HAVE_STATIC_CONF
        /* When using static conf build, FILE pointer is absent and
         * always as NULL. */
        else if (feof(f)) {
            /* handle EOF without a newline(CRLF or LF) */
            fgets_ptr = buf;
        }
#endif
#ifndef FLB_HAVE_STATIC_CONF
        else {
            /* resize the line buffer */
            bufsize *= 2;
            if (bufsize > line_hard_limit) {
                flb_error("reading line is exceeded to the limit size of %lu. Current size is: %zu",
                          line_hard_limit, bufsize);
                goto error;
            }
            buf = flb_realloc(buf, bufsize);
            if (!buf) {
                flb_error("failed to resize line buffer to %zu", bufsize);
                flb_errno();
                goto error;
            }
            /* read more, starting at the buf + len position */
            fgets_ptr = buf + len;
            continue;
        }
#endif

        /* Line number */
        line++;

        if (!buf[0]) {
            continue;
        }

        /* Skip commented lines */
        if (buf[0] == '#') {
            continue;
        }

        if (len > 9 && strncasecmp(buf, "@INCLUDE ", 9) == 0) {
            if (strchr(buf + 9, '*') != NULL) {
                ret = read_glob(cf, ctx, buf + 9, ino_table, ino_num);
            }
            else {
                ret = read_config(cf, ctx, buf + 9, NULL, 0, ino_table, ino_num);
            }
            if (ret == -1) {
                ctx->level--;
                if (indent) {
                    flb_sds_destroy(indent);
                    indent = NULL;
                }
                goto error;
            }
            continue;
        }
        else if (buf[0] == '@' && len > 3) {
            meta = flb_cf_meta_property_add(cf, buf, len);
            if (meta == NULL) {
                goto error;
            }
            continue;
        }

        /* Section definition */
        if (buf[0] == '[') {
            current_group = NULL;

            end = char_search(buf, ']', len);
            if (end > 0) {
                /*
                 * Before to add a new section, lets check the previous
                 * one have at least one key set
                 */
                if (current_section && n_keys == 0) {
                    config_warn(cfg_file, line,
                                "previous section did not have keys");
                }

                /* Create new section */
                current_section = flb_cf_section_create(cf, buf + 1, end - 1);
                if (!current_section) {
                    continue;
                }
                current_group = NULL;
                n_keys = 0;
                continue;
            }
            else {
                config_error(cfg_file, line, "bad header definition");
                goto error;
            }
        }

        /* No separator defined */
        if (!indent) {
            i = 0;

            do { i++; } while (i < len && isblank(buf[i]));

            indent = flb_sds_create_len(buf, i);
            indent_len = flb_sds_len(indent);

            /* Blank indented line */
            if (i == len) {
                continue;
            }
        }

        /* Validate indentation level */
        ret = check_indent(buf, indent, &level);
        if (ret == INDENT_ERROR) {
            config_error(cfg_file, line, "invalid indentation level");
            goto error;
        }
        else {
            if (ret == INDENT_OK && current_group) {
                current_group = NULL;
            }
            indent_len = level;
        }

        if (buf[indent_len] == '#' || indent_len == len) {
            continue;
        }

        /* get the key value separator */
        i = char_search(buf + indent_len, ' ', len - indent_len);

        /* key */
        key = buf + indent_len;
        key_len = i;

        if (!key) {
            config_error(cfg_file, line, "undefined key - check config is in valid classic format");
            goto error;
        }
        else if(i < 0) {
            config_error(cfg_file, line, "undefined value - check config is in valid classic format");
            goto error;
        }

        /* Check possible start of a group */
        if (key[0] == '[') {
            end = char_search(key, ']', len - indent_len);
            if (end == -1) {
                config_error(cfg_file, line, "expected a valid group name: [..]");
                goto error;
            }

            if (!current_section) {
                config_warn(cfg_file, line,
                            "current group don't have a parent section");
                goto error;
            }

            /* check if a previous group exists with one key */
            if (current_group && n_keys == 0) {
                config_warn(cfg_file, line, "previous group did not have keys");
                goto error;
            }

            /* Create new group */
            current_group = flb_cf_group_create(cf, current_section,
                                                key + 1, end - 1);
            if (!current_group) {
                continue;
            }
            n_keys = 0;

            /* continue processing since we need key/value pairs */
            continue;
        }

        /* val */
        val = buf + indent_len + i + 1;
        val_len = len - indent_len - i - 1;

        if (!key || !val || i < 0) {
            config_error(cfg_file, line, "each key must have a value");
            goto error;
        }

        if (val_len == 0) {
            config_error(cfg_file, line, "key has an empty value");
            goto error;
        }

        /* register entry: key and val are copied as duplicated */
        var = NULL;
        if (current_group) {
            var = flb_cf_section_property_add(cf, current_group->properties,
                                              key, key_len,
                                              val, val_len);
        }
        else if (current_section) {
            var = flb_cf_section_property_add(cf, current_section->properties,
                                              key, key_len,
                                              val, val_len);
        }
        if (var == NULL) {
            config_error(cfg_file, line, "could not allocate key value pair");
            goto error;
        }

        /* Free temporary key and val */
        n_keys++;
    }

    if (section && n_keys == 0) {
        /* No key, no warning */
    }

    if (f) {
        fclose(f);
    }

    if (indent) {
        flb_sds_destroy(indent);
        indent = NULL;
    }

    /* Append this file to the list */
    file = flb_malloc(sizeof(struct local_file));
    if (!file) {
        flb_errno();
        ctx->level--;
        goto error;
    }

    flb_free(buf);
    file->path = flb_sds_create(cfg_file);
    mk_list_add(&file->_head, &ctx->includes);
    ctx->level--;

    return 0;

error:
    if (f) {
        fclose(f);
    }
    if (indent) {
        flb_sds_destroy(indent);
    }
    flb_free(buf);
    return -1;
}

struct flb_cf *flb_cf_fluentbit_create(struct flb_cf *cf,
                                       char *file_path, char *buf, size_t size)
{
    int ret;
    struct local_ctx ctx;
    ino_t ino_table[FLB_CF_FILE_NUM_LIMIT];
    int ino_num = 0;

    if (!cf) {
        cf = flb_cf_create();
        if (!cf) {
            return NULL;
        }

        flb_cf_set_origin_format(cf, FLB_CF_CLASSIC);
    }

    ret = local_init(&ctx, file_path);
    if (ret != 0) {
        if (cf) {
            flb_cf_destroy(cf);
        }
        return NULL;
    }

    ret = read_config(cf, &ctx, file_path, buf, size, &ino_table[0], &ino_num);

    local_exit(&ctx);

    if (ret == -1) {
        flb_cf_destroy(cf);
        if (ino_num >= FLB_CF_FILE_NUM_LIMIT) {
            flb_error("Too many config files. Limit = %d", FLB_CF_FILE_NUM_LIMIT);
        }
        return NULL;
    }

    return cf;
}
