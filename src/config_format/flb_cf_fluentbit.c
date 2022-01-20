/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

#define FLB_CF_BUF_SIZE   4096

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

static int read_config(struct flb_cf *cf, struct local_ctx *ctx, char *cfg_file);

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

#ifndef _WIN32
static int read_glob(struct flb_cf *cf, struct local_ctx *ctx, const char * path)
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
        ret = read_config(cf, ctx, glb.gl_pathv[i]);
        if (ret < 0) {
            break;
        }
    }

    globfree(&glb);
    return ret;
}
#else
static int read_glob(struct flb_cf *cf, struct local_ctx *ctx, const char *path)
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
            read_glob(cf, ctx, buf); /* recursive */
            continue;
        }

        ret = stat(buf, &st);
        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
            if (read_config(cf, ctx, buf) < 0) {
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
    char *p;
    char *end;
    char path[PATH_MAX + 1];

    if (file) {
#ifdef _MSC_VER
        p = _fullpath(path, file, PATH_MAX + 1);
#else
        p = realpath(file, path);
#endif
        if (!p) {
            return -1;
        }
    }

    /* lookup path ending and truncate */
    end = strrchr(path, '/');
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

static int check_indent(const char *line, const char *indent)
{
    while (*line == *indent && *indent) {
        line++;
        indent++;
    }

    if (*indent != '\0') {
        if (isblank(*line)) {
            flb_error("[config] inconsistent use of tab and space");
        }
        else {
            flb_error("[config] indentation level is too low");
        }
        return -1;
    }

    if (isblank(*line)) {
        flb_error("[config] Extra indentation level found");
        return -1;
    }

    return 0;
}

static int read_config(struct flb_cf *cf, struct local_ctx *ctx, char *cfg_file)
{
    int i;
    int len;
    int ret;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char *key;
    int key_len;
    char *val;
    int val_len;
    char *buf;
    char tmp[PATH_MAX];
    flb_sds_t section = NULL;
    flb_sds_t indent = NULL;
    struct stat st;
    struct local_file *file;
    struct flb_cf_meta *meta;
    struct flb_cf_section *current = NULL;
    struct flb_kv *kv;
    FILE *f;

    /* Check if the path exists (relative cases for included files) */
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
        }
    }

    /* Check this file have not been included before */
    ret = is_file_included(ctx, cfg_file);
    if (ret) {
        flb_error("[config] file already included %s", cfg_file);
        return -1;
    }
    ctx->level++;

    /* Open configuration file */
    if ((f = fopen(cfg_file, "r")) == NULL) {
        flb_warn("[config] I cannot open %s file", cfg_file);
        return -1;
    }

    /* Allocate temporal buffer to read file content */
    buf = flb_malloc(FLB_CF_BUF_SIZE);
    if (!buf) {
        flb_errno();
        return -1;
    }

    /* looking for configuration directives */
    while (fgets(buf, FLB_CF_BUF_SIZE, f)) {
        len = strlen(buf);
        if (len > 0 && buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
            }
        }
        else {
            /*
             * If we don't find a break line, validate if we got an EOF or not. No EOF
             * means that the incoming string is not finished so we must raise an
             * exception.
             */
            if (!feof(f)) {
                config_error(cfg_file, line, "length of content has exceeded limit");
                flb_free(buf);
                return -1;
            }
        }

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
                ret = read_glob(cf, ctx, buf + 9);
            }
            else {
                ret = read_config(cf, ctx, buf + 9);
            }
            if (ret == -1) {
                ctx->level--;
                fclose(f);
                if (indent) {
                    flb_sds_destroy(indent);
                }
                flb_free(buf);
                return -1;
            }
            continue;
        }
        else if (buf[0] == '@' && len > 3) {
            meta = flb_cf_meta_create(cf, buf, len);
            if (!meta) {
                fclose(f);
                if (indent) {
                    flb_sds_destroy(indent);
                }
                flb_free(buf);
                return -1;
            }
            continue;
        }

        /* Section definition */
        if (buf[0] == '[') {
            int end = -1;
            end = char_search(buf, ']', len);
            if (end > 0) {
                /*
                 * Before to add a new section, lets check the previous
                 * one have at least one key set
                 */
                if (current && n_keys == 0) {
                    config_warn(cfg_file, line,
                                "previous section did not have keys");
                }

                /* Create new section */
                current = flb_cf_section_create(cf, buf + 1, end - 1);
                n_keys = 0;
                continue;
            }
            else {
                config_error(cfg_file, line, "bad header definition");
                flb_free(buf);
                return -1;
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
        if (check_indent(buf, indent) < 0) {
            config_error(cfg_file, line, "Invalid indentation level");
            flb_sds_destroy(key);
            flb_sds_destroy(val);
            return -1;
        }

        if (buf[indent_len] == '#' || indent_len == len) {
            continue;
        }

        if (len - indent_len >= 3 && strncmp(buf + indent_len, "---", 3) == 0) {
            continue;
        }

        /* Get the separator */
        i = char_search(buf + indent_len, ' ', len - indent_len);

        /* key */
        key = buf + indent_len;
        key_len = i;

        /* val */
        val = buf + indent_len + i + 1;
        val_len = len - indent_len - i - 1;

        if (!key || !val || i < 0) {
            config_error(cfg_file, line, "Each key must have a value");
            return -1;
        }

        if (val_len == 0) {
            config_error(cfg_file, line, "Key has an empty value");
            return -1;
        }

        /* Register entry: key and val are copied as duplicated */
        kv = flb_cf_property_add(cf, &current->properties,
                                 key, key_len,
                                 val, val_len);
        if (!kv) {
            config_error(cfg_file, line, "could not allocate key value pair");
            return -1;
        }

        /* Free temporary key and val */
        n_keys++;
    }

    if (section && n_keys == 0) {
        /* No key, no warning */
    }

    fclose(f);
    if (indent) {
        flb_sds_destroy(indent);
    }
    flb_free(buf);

    /* Append this file to the list */
    file = flb_malloc(sizeof(struct local_file));
    if (!file) {
        flb_errno();
        ctx->level--;
        return -1;
    }
    file->path = flb_sds_create(cfg_file);
    mk_list_add(&file->_head, &ctx->includes);
    ctx->level--;

    return 0;
}

struct flb_cf *flb_cf_fluentbit_create(struct flb_cf *cf,
                                       char *file_path, char *buf, size_t size)
{
    int ret;
    struct local_ctx ctx;

    if (!cf) {
        cf = flb_cf_create();
        if (!cf) {
            return NULL;
        }
    }

    local_init(&ctx, file_path);

    ret = read_config(cf, &ctx, file_path);

    local_exit(&ctx);

    if (ret == -1) {
        exit(28);
    }

    return cf;
}
