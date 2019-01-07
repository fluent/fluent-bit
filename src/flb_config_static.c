/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/conf/flb_static_conf.h>

#include <monkey/mk_core.h>
#include <ctype.h>

static int is_file_included(struct mk_rconf *conf, const char *path)
{
    struct mk_list *head;
    struct mk_rconf_file *file;

    mk_list_foreach(head, &conf->includes) {
        file = mk_list_entry(head, struct mk_rconf_file, _head);
        if (strcmp(file->path, path) == 0) {
            return MK_TRUE;
        }
    }

    return MK_FALSE;
}

static int rconf_meta_add(struct mk_rconf *conf, char *buf, int len)
{
    int xlen;
    char *p;
    char *tmp;
    struct mk_rconf_entry *meta;

    if (buf[0] != '@') {
        return -1;
    }

    meta = mk_mem_alloc(sizeof(struct mk_rconf_entry));
    if (!meta) {
        perror("malloc");
        return -1;
    }

    p = buf;
    tmp = strchr(p, ' ');
    xlen = (tmp - p);
    meta->key = mk_string_copy_substr(buf, 1, xlen);
    mk_string_trim(&meta->key);

    meta->val = mk_string_copy_substr(buf, xlen + 1, len);
    mk_string_trim(&meta->val);

    mk_list_add(&meta->_head, &conf->metas);
    return 0;
}

static void rconf_section_entry_add(struct mk_rconf *conf,
                                    const char *key, const char *val)
{
    struct mk_rconf_section *section;
    struct mk_rconf_entry *new;
    struct mk_list *head = &conf->sections;

    if (mk_list_is_empty(&conf->sections) == 0) {
        mk_err("Error: there are not sections available on %s!", conf->file);
        return;
    }

    /* Last section */
    section = mk_list_entry_last(head, struct mk_rconf_section, _head);

    /* Alloc new entry */
    new = mk_mem_alloc(sizeof(struct mk_rconf_entry));
    new->key = mk_string_dup(key);
    new->val = mk_string_dup(val);

    mk_list_add(&new->_head, &section->entries);
}

struct mk_rconf_section *rconf_section_add(struct mk_rconf *conf,
                                           char *name)
{
    struct mk_rconf_section *new;

    /* Alloc section node */
    new = mk_mem_alloc(sizeof(struct mk_rconf_section));
    new->name = mk_string_dup(name);
    mk_list_init(&new->entries);
    mk_list_add(&new->_head, &conf->sections);

    return new;
}

/*
 * Helper function to simulate a fgets(2) but instead of using
 * a real file stream uses the data buffer provided.
 */
static int static_fgets(char *out, size_t size, char *data, size_t *off)
{
    size_t len;
    char *start;
    char *end;

    start = data + *off;
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

static int flb_config_static_read(struct mk_rconf *conf,
                                  const char *fname, const char *data)
{
    int i;
    int len;
    int ret;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char *buf;
    char *section = NULL;
    char *indent = NULL;
    char *key, *val;
    char *cfg_file = (char *) fname;
    size_t off;
    struct mk_rconf_file *file;
    struct mk_rconf_section *current = NULL;

    /* Check this file have not been included before */
    ret = is_file_included(conf, cfg_file);
    if (ret == MK_TRUE) {
        mk_err("[config] file already included %s", cfg_file);
        return -1;
    }

    conf->level++;

    /* Allocate temporal buffer to read file content */
    buf = mk_mem_alloc(MK_RCONF_KV_SIZE);
    if (!buf) {
        perror("malloc");
        return -1;
    }

    /* looking for configuration directives */
    off = 0;
    while (static_fgets(buf, MK_RCONF_KV_SIZE, (char *) data, &off)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
            buf[--len] = 0;
            if (len && buf[len - 1] == '\r') {
                buf[--len] = 0;
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
                //ret = mk_rconf_read_glob(conf, buf + 9);
            }
            else {
                //ret = flb_config_static_read(conf,
                //                  const char *fname, const char *data)
                //ret = mk_rconf_read(conf, buf + 9);
            }
            if (ret == -1) {
                conf->level--;
                if (indent) {
                    mk_mem_free(indent);
                }
                mk_mem_free(buf);
                return -1;
            }
            continue;
        }
        else if (buf[0] == '@' && len > 3) {
            ret = rconf_meta_add(conf, buf, len);
            if (ret == -1) {
                if (indent) {
                    mk_mem_free(indent);
                }
                mk_mem_free(buf);
                return -1;
            }
            continue;
        }

        /* Section definition */
        if (buf[0] == '[') {
            int end = -1;
            end = mk_string_char_search(buf, ']', len);
            if (end > 0) {
                /*
                 * Before to add a new section, lets check the previous
                 * one have at least one key set
                 */
                if (current && n_keys == 0) {
                    flb_warn("[static conf: %s] "
                             "Section do not have keys", fname);
                }

                /* Create new section */
                section = mk_string_copy_substr(buf, 1, end);
                current = rconf_section_add(conf, section);
                mk_mem_free(section);
                n_keys = 0;
                continue;
            }
            else {
                flb_error("[static conf: %s] Bad header definition",
                          fname);
            }
        }

        /* No separator defined */
        if (!indent) {
            i = 0;

            do { i++; } while (i < len && isblank(buf[i]));

            indent = mk_string_copy_substr(buf, 0, i);
            indent_len = strlen(indent);

            /* Blank indented line */
            if (i == len) {
                continue;
            }
        }

        /* Validate indentation level */
        if (strncmp(buf, indent, indent_len) != 0 ||
            isblank(buf[indent_len]) != 0) {
            //mk_config_error(path, line, "Invalid indentation level");
        }

        if (buf[indent_len] == '#' || indent_len == len) {
            continue;
        }

        /* Get key and val */
        i = mk_string_char_search(buf + indent_len, ' ', len - indent_len);
        key = mk_string_copy_substr(buf + indent_len, 0, i);
        val = mk_string_copy_substr(buf + indent_len + i, 1, len - indent_len - i);

        if (!key || !val || i < 0) {
            //mk_config_error(path, line, "Each key must have a value");
        }

        /* Trim strings */
        mk_string_trim(&key);
        mk_string_trim(&val);

        if (strlen(val) == 0) {
            //mk_config_error(path, line, "Key has an empty value");
        }

        /* Register entry: key and val are copied as duplicated */
        rconf_section_entry_add(conf, key, val);

        /* Free temporal key and val */
        mk_mem_free(key);
        mk_mem_free(val);

        n_keys++;
    }

    if (section && n_keys == 0) {
        /* No key, no warning */
    }

    /*
    struct mk_config_section *s;
    struct mk_rconf_entry *e;

    s = conf->section;
    while(s) {
        printf("\n[%s]", s->name);
        e = s->entry;
        while(e) {
            printf("\n   %s = %s", e->key, e->val);
            e = e->next;
        }
        s = s->next;
    }
    fflush(stdout);
    */
    if (indent) {
        mk_mem_free(indent);
    }
    mk_mem_free(buf);

    /* Append this file to the list */
    file = mk_mem_alloc(sizeof(struct mk_rconf_file));
    if (!file) {
        perror("malloc");
        conf->level--;
        return -1;
    }

    file->path = mk_string_dup(fname);
    mk_list_add(&file->_head, &conf->includes);
    conf->level--;
    return 0;
}

/*
 * If Fluent Bit have static configuration support, this function
 * allows to lookup, parse and create configuration file contexts
 * from the entries generated by CMake at build-time.
 *
 * The routine is a modified version from mk_rconf_read() but with
 * the differences that it does all operations on top of the global
 * entries at flb_config_files[] defined at:
 *
 *   include/fluent-bit/conf/flb_static_conf.h
 *
 */
struct mk_rconf *flb_config_static_open(char *file)
{
    int i;
    int ret;
    char *k;
    char *v;
    struct mk_rconf *conf = NULL;

    /* Iterate static array and lookup the file name */
    for (i = 0; i < flb_config_files_size; i++) {
        k = (char *) flb_config_files[i][0];
        v = (char *) flb_config_files[i][1];

        if (strcmp(k, file) == 0) {
            break;
        }
        k = NULL;
    }

    if (!k) {
        return NULL;
    }

    /* Alloc configuration node */
    conf = mk_mem_alloc(sizeof(struct mk_rconf));
    conf->created = time(NULL);
    conf->file = mk_string_dup(file);
    conf->level = -1;
    mk_list_init(&conf->sections);
    mk_list_init(&conf->includes);
    mk_list_init(&conf->metas);

    /* Set the absolute path for the entrypoint file */
    conf->root_path = mk_string_dup("/");

    /* Read entrypoint */
    ret = flb_config_static_read(conf, k, v);
    if (ret == -1) {
        mk_rconf_free(conf);
        return NULL;
    }

    return conf;
}
