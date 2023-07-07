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
#include <fluent-bit/flb_input_plugin.h>
#include <fluent-bit/flb_sds.h>
#include "ne.h"

/* required by stat(2), open(2) */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>

#include <glob.h>

int ne_utils_str_to_double(char *str, double *out_val)
{
    double val;
    char *end;

    errno = 0;
    val = strtod(str, &end);
    if (errno != 0 || *end != '\0') {
        return -1;
    }
    *out_val = val;
    return 0;
}

int ne_utils_str_to_uint64(char *str, uint64_t *out_val)
{
    uint64_t val;
    char *end;

    errno = 0;
    val = strtoll(str, &end, 10);
    if ((errno == ERANGE && (val == LONG_MAX || val == LONG_MIN))
        || (errno != 0 && val == 0)) {
        flb_errno();
        return -1;
    }

    if (end == str) {
        return -1;
    }

    *out_val = val;
    return 0;
}

int ne_utils_file_read_uint64(const char *mount,
                              const char *path,
                              const char *join_a, const char *join_b,
                              uint64_t *out_val)
{
    int fd;
    int len;
    int ret;
    flb_sds_t p;
    uint64_t val;
    ssize_t bytes;
    char tmp[32];

    /* Check the path starts with the mount point to prevent duplication. */
    if (strncasecmp(path, mount, strlen(mount)) == 0 &&
        path[strlen(mount)] == '/') {
        mount = "";
    }

    /* Compose the final path */
    p = flb_sds_create(mount);
    if (!p) {
        return -1;
    }

    len = strlen(path);
    if (flb_sds_cat_safe(&p, path, len) < 0) {
        flb_sds_destroy(p);
        return -1;
    }

    if (join_a) {
        if (flb_sds_cat_safe(&p, "/", 1) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
        len = strlen(join_a);
        if (flb_sds_cat_safe(&p, join_a, len) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
    }

    if (join_b) {
        if (flb_sds_cat_safe(&p, "/", 1) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
        len = strlen(join_b);
        if (flb_sds_cat_safe(&p, join_b, len) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
    }

    fd = open(p, O_RDONLY);
    if (fd == -1) {
        flb_sds_destroy(p);
        return -1;
    }
    flb_sds_destroy(p);

    bytes = read(fd, &tmp, sizeof(tmp));
    if (bytes == -1) {
        flb_errno();
        close(fd);
        return -1;
    }
    close(fd);

    ret = ne_utils_str_to_uint64(tmp, &val);
    if (ret == -1) {
        return -1;
    }

    *out_val = val;
    return 0;
}

/*
 * Read a file and every non-empty line is stored as a flb_slist_entry in the
 * given list.
 */
int ne_utils_file_read_lines(const char *mount, const char *path, struct mk_list *list)
{
    int len;
    int ret;
    FILE *f;
    char line[512];
    char real_path[2048];

    mk_list_init(list);

    /* Check the path starts with the mount point to prevent duplication. */
    if (strncasecmp(path, mount, strlen(mount)) == 0 &&
        path[strlen(mount)] == '/') {
        mount = "";
    }

    snprintf(real_path, sizeof(real_path) - 1, "%s%s", mount, path);
    f = fopen(real_path, "r");
    if (f == NULL) {
        flb_errno();
        return -1;
    }

    /* Read the content */
    while (fgets(line, sizeof(line) - 1, f)) {
        len = strlen(line);
        if (line[len - 1] == '\n') {
            line[--len] = 0;
            if (len && line[len - 1] == '\r') {
                line[--len] = 0;
            }
        }

        ret = flb_slist_add(list, line);
        if (ret == -1) {
            fclose(f);
            flb_slist_destroy(list);
            return -1;
        }
    }

    fclose(f);
    return 0;
}

/*
 * Read a file and store the first line as a string.
 */
int ne_utils_file_read_sds(const char *mount, 
                           const char *path, 
                           const char *join_a, 
                           const char *join_b,
                           flb_sds_t *str)
{
    int fd;
    int len;
    int i;
    flb_sds_t p;
    ssize_t bytes;
    char tmp[32];

    /* Check the path starts with the mount point to prevent duplication. */
    if (strncasecmp(path, mount, strlen(mount)) == 0 &&
        path[strlen(mount)] == '/') {
        mount = "";
    }

    /* Compose the final path */
    p = flb_sds_create(mount);
    if (!p) {
        return -1;
    }

    len = strlen(path);
    flb_sds_cat_safe(&p, path, len);

    if (join_a) {
        if (flb_sds_cat_safe(&p, "/", 1) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
        len = strlen(join_a);
        if (flb_sds_cat_safe(&p, join_a, len) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
    }

    if (join_b) {
        if (flb_sds_cat_safe(&p, "/", 1) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
        len = strlen(join_b);
        if (flb_sds_cat_safe(&p, join_b, len) < 0) {
            flb_sds_destroy(p);
            return -1;
        }
    }

    fd = open(p, O_RDONLY);
    if (fd == -1) {
        flb_sds_destroy(p);
        return -1;
    }
    flb_sds_destroy(p);

    bytes = read(fd, &tmp, sizeof(tmp));
    if (bytes == -1) {
        flb_errno();
        close(fd);
        return -1;
    }
    close(fd);

    for (i = bytes-1; i > 0; i--) {
        if (tmp[i] != '\n' && tmp[i] != '\r') {
            break;
        }
    }

    *str = flb_sds_create_len(tmp, i+1);
    if (*str == NULL) {
        return -1;
    }

    return 0;
}

int ne_utils_path_scan(struct flb_ne *ctx, const char *mount, const char *path,
                       int expected, struct mk_list *list)
{
    int i;
    int ret;
    glob_t globbuf;
    struct stat st;
    char real_path[2048];

    if (!path) {
        return -1;
    }

    /* Safe reset for globfree() */
    globbuf.gl_pathv = NULL;

    /* Scan the real path */
    snprintf(real_path, sizeof(real_path) - 1, "%s%s", mount, path);
    ret = glob(real_path, GLOB_TILDE | GLOB_ERR, NULL, &globbuf);
    if (ret != 0) {
        switch (ret) {
        case GLOB_NOSPACE:
            flb_plg_error(ctx->ins, "no memory space available");
            return -1;
        case GLOB_ABORTED:
            flb_plg_error(ctx->ins, "read error, check permissions: %s", path);
            return -1;;
        case GLOB_NOMATCH:
            ret = stat(path, &st);
            if (ret == -1) {
                flb_plg_debug(ctx->ins, "cannot read info from: %s", path);
            }
            else {
                ret = access(path, R_OK);
                if (ret == -1 && errno == EACCES) {
                    flb_plg_error(ctx->ins, "NO read access for path: %s", path);
                }
                else {
                    flb_plg_debug(ctx->ins, "NO matches for path: %s", path);
                }
            }
            return -1;
        }
    }

    if (globbuf.gl_pathc <= 0) {
        globfree(&globbuf);
        return -1;
    }

    /* Initialize list */
    flb_slist_create(list);

    /* For every entry found, generate an output list */
    for (i = 0; i < globbuf.gl_pathc; i++) {
        ret = stat(globbuf.gl_pathv[i], &st);
        if (ret != 0) {
            continue;
        }

        if ((expected == NE_SCAN_FILE && S_ISREG(st.st_mode)) ||
            (expected == NE_SCAN_DIR && S_ISDIR(st.st_mode))) {

            /* Compose the path */
            ret = flb_slist_add(list, globbuf.gl_pathv[i]);
            if (ret != 0) {
                globfree(&globbuf);
                flb_slist_destroy(list);
                return -1;
            }
        }
    }

    globfree(&globbuf);
    return 0;
}
