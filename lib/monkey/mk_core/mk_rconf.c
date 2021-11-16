/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2017 Eduardo Silva <eduardo@monkey.io>
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

#include <ctype.h>
#include <string.h>
#include <time.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#ifndef _MSC_VER
#include <glob.h>
#endif

#include <mk_core/mk_rconf.h>
#include <mk_core/mk_utils.h>
#include <mk_core/mk_string.h>
#include <mk_core/mk_list.h>

#ifdef _WIN32
#include <Windows.h>
#include <strsafe.h>
#define PATH_MAX MAX_PATH
#endif

/* Raise a configuration schema error */
static void mk_config_error(const char *path, int line, const char *msg)
{
    mk_err("File %s", path);
    mk_err("Error in line %i: %s", line, msg);
}

/* Raise a warning */
static void mk_rconf_warning(const char *path, int line, const char *msg)
{
    mk_warn("Config file warning '%s':\n"
            "\t\t\t\tat line %i: %s",
            path, line, msg);
}


/* Returns a configuration section by [section name] */
struct mk_rconf_section *mk_rconf_section_get(struct mk_rconf *conf,
                                              const char *name)
{
    struct mk_list *head;
    struct mk_rconf_section *section;

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, name) == 0) {
            return section;
        }
    }

    return NULL;
}

/* Register a key/value entry in the last section available of the struct */
static void mk_rconf_section_entry_add(struct mk_rconf *conf,
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

/* Create a configuration schema */
struct mk_rconf *mk_rconf_create(const char *name)
{
    struct mk_rconf *conf = NULL;

    /* Alloc configuration node */
    conf = mk_mem_alloc_z(sizeof(struct mk_rconf));
    conf->created = time(NULL);
    conf->file = mk_string_dup(name);
    mk_list_init(&conf->sections);

    return conf;
}

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

char *mk_rconf_meta_get(struct mk_rconf *conf, char *key)
{
    struct mk_list *head;
    struct mk_rconf_entry *meta;

    mk_list_foreach(head, &conf->metas) {
        meta = mk_list_entry(head, struct mk_rconf_entry, _head);
        if (strcmp(meta->key, key) == 0) {
            return meta->val;
        }
    }

    return NULL;
}

static int mk_rconf_meta_add(struct mk_rconf *conf, char *buf, int len)
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

/* To call this function from mk_rconf_read */
static int mk_rconf_read_glob(struct mk_rconf *conf, const char * path);

static int mk_rconf_read(struct mk_rconf *conf, const char *path)
{
    int i;
    int len;
    int ret;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char *buf;
    char tmp[PATH_MAX];
    char *section = NULL;
    char *indent = NULL;
    char *key, *val;
    char *cfg_file = (char *) path;
    struct stat st;
    struct mk_rconf_file *file;
    struct mk_rconf_section *current = NULL;
    FILE *f;

    /* Check if the path exists (relative cases for included files) */
    if (conf->level >= 0) {
        ret = stat(path, &st);
        if (ret == -1 && errno == ENOENT) {
            /* Try to resolve the real path (if exists) */
            if (path[0] == '/') {
                return -1;
            }

            if (conf->root_path) {
                snprintf(tmp, PATH_MAX, "%s/%s", conf->root_path, path);
                cfg_file = tmp;
            }
        }
    }

    /* Check this file have not been included before */
    ret = is_file_included(conf, cfg_file);
    if (ret == MK_TRUE) {
        mk_err("[config] file already included %s", cfg_file);
        return -1;
    }

    conf->level++;

    /* Open configuration file */
    if ((f = fopen(cfg_file, "r")) == NULL) {
        mk_warn("[config] I cannot open %s file", cfg_file);
        return -1;
    }

    /* Allocate temporal buffer to read file content */
    buf = mk_mem_alloc(MK_RCONF_KV_SIZE);
    if (!buf) {
        perror("malloc");
        return -1;
    }

    /* looking for configuration directives */
    while (fgets(buf, MK_RCONF_KV_SIZE, f)) {
        len = strlen(buf);
        if (buf[len - 1] == '\n') {
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
                mk_config_error(path, line, "Length of content has exceeded limit");
                mk_mem_free(buf);
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
                ret = mk_rconf_read_glob(conf, buf + 9);
            }
            else {
                ret = mk_rconf_read(conf, buf + 9);
            }
            if (ret == -1) {
                conf->level--;
                fclose(f);
                if (indent) {
                    mk_mem_free(indent);
                }
                mk_mem_free(buf);
                return -1;
            }
            continue;
        }
        else if (buf[0] == '@' && len > 3) {
            ret = mk_rconf_meta_add(conf, buf, len);
            if (ret == -1) {
                fclose(f);
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
                    mk_rconf_warning(path, line, "Previous section did not have keys");
                }

                /* Create new section */
                section = mk_string_copy_substr(buf, 1, end);
                current = mk_rconf_section_add(conf, section);
                mk_mem_free(section);
                n_keys = 0;
                continue;
            }
            else {
                mk_config_error(path, line, "Bad header definition");
                mk_mem_free(buf);
                return -1;
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
            mk_config_error(path, line, "Invalid indentation level");
            mk_mem_free(key);
            mk_mem_free(val);
            return -1;
        }

        if (buf[indent_len] == '#' || indent_len == len) {
            continue;
        }

        /* Get key and val */
        i = mk_string_char_search(buf + indent_len, ' ', len - indent_len);
        key = mk_string_copy_substr(buf + indent_len, 0, i);
        val = mk_string_copy_substr(buf + indent_len + i, 1, len - indent_len - i);

        if (!key || !val || i < 0) {
            mk_config_error(path, line, "Each key must have a value");
            mk_mem_free(key);
            mk_mem_free(val);
            return -1;
        }

        /* Trim strings */
        mk_string_trim(&key);
        mk_string_trim(&val);

        if (strlen(val) == 0) {
            mk_config_error(path, line, "Key has an empty value");
            mk_mem_free(key);
            mk_mem_free(val);
            return -1;
        }

        /* Register entry: key and val are copied as duplicated */
        mk_rconf_section_entry_add(conf, key, val);

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
    fclose(f);
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

    file->path = mk_string_dup(path);
    mk_list_add(&file->_head, &conf->includes);
    conf->level--;
    return 0;
}

#ifndef _WIN32
static int mk_rconf_read_glob(struct mk_rconf *conf, const char * path)
{
    int ret = -1;
    glob_t glb;
    char tmp[PATH_MAX];

    const char *glb_path;
    size_t i;
    int ret_glb = -1;

    if (conf->root_path) {
        snprintf(tmp, PATH_MAX, "%s/%s", conf->root_path, path);
        glb_path = tmp;
    }
    else {
        glb_path = path;
    }

    ret_glb = glob(glb_path, GLOB_NOSORT, NULL, &glb);
    if (ret_glb != 0) {
        switch(ret_glb){
        case GLOB_NOSPACE:
            mk_warn("[%s] glob: no space", __FUNCTION__);
            break;
        case GLOB_NOMATCH:
            mk_warn("[%s] glob: no match", __FUNCTION__);
            break;
        case GLOB_ABORTED:
            mk_warn("[%s] glob: aborted", __FUNCTION__);
            break;
        default:
            mk_warn("[%s] glob: other error", __FUNCTION__);
        }
        return ret;
    }

    for (i = 0; i < glb.gl_pathc; i++) {
        ret = mk_rconf_read(conf, glb.gl_pathv[i]);
        if (ret < 0) {
            break;
        }
    }

    globfree(&glb);
    return ret;
}
#else
static int mk_rconf_read_glob(struct mk_rconf *conf, const char *path)
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
            mk_rconf_read_glob(conf, buf); /* recursive */
            continue;
        }

        ret = stat(buf, &st);
        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {
            if (mk_rconf_read(conf, buf) < 0) {
                return -1;
            }
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return 0;
}
#endif

static int mk_rconf_path_set(struct mk_rconf *conf, char *file)
{
    char *p;
    char *end;
    char path[PATH_MAX + 1];

#ifdef _MSC_VER
    p = _fullpath(path, file, PATH_MAX + 1);
#else
    p = realpath(file, path);
#endif
    if (!p) {
        return -1;
    }

    /* lookup path ending and truncate */
    end = strrchr(path, '/');
    if (!end) {
        return -1;
    }

    end++;
    *end = '\0';
    conf->root_path = mk_string_dup(path);

    return 0;
}

struct mk_rconf *mk_rconf_open(const char *path)
{
    int ret;
    struct mk_rconf *conf = NULL;

    if (!path) {
        mk_warn("[config] invalid path file %s", path);
        return NULL;
    }

    /* Alloc configuration node */
    conf = mk_mem_alloc_z(sizeof(struct mk_rconf));
    conf->created = time(NULL);
    conf->file = mk_string_dup(path);
    conf->level = -1;
    mk_list_init(&conf->sections);
    mk_list_init(&conf->includes);
    mk_list_init(&conf->metas);

    /* Set the absolute path for the entrypoint file */
    mk_rconf_path_set(conf, (char *) path);

    /* Read entrypoint */
    ret = mk_rconf_read(conf, path);
    if (ret == -1) {
        mk_rconf_free(conf);
        return NULL;
    }

    return conf;
}

void mk_rconf_free(struct mk_rconf *conf)
{
    struct mk_list *head, *tmp;
    struct mk_rconf_section *section;
    struct mk_rconf_entry *entry;
    struct mk_rconf_file *file;

    /* Remove included files */
    mk_list_foreach_safe(head, tmp, &conf->includes) {
        file = mk_list_entry(head, struct mk_rconf_file, _head);
        mk_list_del(&file->_head);
        mk_mem_free(file->path);
        mk_mem_free(file);
    }

    /* Remove metas */
    mk_list_foreach_safe(head, tmp, &conf->metas) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        mk_list_del(&entry->_head);
        mk_mem_free(entry->key);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }

    /* Free sections */
    mk_list_foreach_safe(head, tmp, &conf->sections) {
        section = mk_list_entry(head, struct mk_rconf_section, _head);
        mk_list_del(&section->_head);

        /* Free section entries */
        mk_rconf_free_entries(section);

        /* Free section node */
        mk_mem_free(section->name);
        mk_mem_free(section);
    }
    if (conf->file) {
        mk_mem_free(conf->file);
    }

    mk_mem_free(conf->root_path);
    mk_mem_free(conf);
}

void mk_rconf_free_entries(struct mk_rconf_section *section)
{
    struct mk_rconf_entry *entry;
    struct mk_list *head, *tmp;

    mk_list_foreach_safe(head, tmp, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);
        mk_list_del(&entry->_head);

        /* Free memory assigned */
        mk_mem_free(entry->key);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }
}

/* Register a new section into the configuration struct */
struct mk_rconf_section *mk_rconf_section_add(struct mk_rconf *conf,
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

/* Return the value of a key of a specific section */
void *mk_rconf_section_get_key(struct mk_rconf_section *section,
                               char *key, int mode)
{
    int on, off;
    struct mk_rconf_entry *entry;
    struct mk_list *head;

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_rconf_entry, _head);

        if (strcasecmp(entry->key, key) == 0) {
            switch (mode) {
            case MK_RCONF_STR:
                return (void *) mk_string_dup(entry->val);
            case MK_RCONF_NUM:
                return (void *) strtol(entry->val, (char **) NULL, 10);
            case MK_RCONF_BOOL:
                on = strcasecmp(entry->val, MK_RCONF_ON);
                off = strcasecmp(entry->val, MK_RCONF_OFF);

                if (on != 0 && off != 0) {
                    return (void *) -1;
                }
                else if (on >= 0) {
                    return (void *) MK_TRUE;
                }
                else {
                    return (void *) MK_FALSE;
                }
            case MK_RCONF_LIST:
                return (void *)mk_string_split_line(entry->val);
            }
        }
    }
    return NULL;
}
