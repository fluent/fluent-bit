/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Monkey HTTP Server
 *  ==================
 *  Copyright 2001-2015 Monkey Software LLC <eduardo@monkey.io>
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

/* isblank is not in C89 */
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <ctype.h>
#include <limits.h>
#include <time.h>

#include "mk_config.h"
#include "mk_string.h"

/* Raise a configuration schema error */
void mk_config_error(const char *path, int line, const char *msg)
{
    fprintf(stderr, "File %s", path);
    fprintf(stderr, "Error in line %i: %s", line, msg);
    exit(EXIT_FAILURE);
}

/* Raise a warning */
void mk_config_warning(const char *path, int line, const char *msg)
{
    printf("Config file warning '%s':\n"
           "\t\t\t\tat line %i: %s",
           path, line, msg);
}

/* Returns a configuration section by [section name] */
struct mk_config_section *mk_config_section_get(struct mk_config *conf,
                                                const char *section_name)
{
    struct mk_config_section *section;
    struct mk_list *head;

    mk_list_foreach(head, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        if (strcasecmp(section->name, section_name) == 0) {
            return section;
        }
    }

    return NULL;
}

/* Register a new section into the configuration struct */
struct mk_config_section *mk_config_section_add(struct mk_config *conf,
                                                char *section_name)
{
    struct mk_config_section *new;

    /* Alloc section node */
    new = malloc(sizeof(struct mk_config_section));
    new->name = mk_string_dup(section_name);
    mk_list_init(&new->entries);
    mk_list_add(&new->_head, &conf->sections);

    return new;
}

/* Register a key/value entry in the last section available of the struct */
static void mk_config_entry_add(struct mk_config *conf,
                         const char *key, const char *val)
{
    struct mk_config_section *section;
    struct mk_config_entry *new;
    struct mk_list *head = &conf->sections;

    if (mk_list_is_empty(&conf->sections) == 0) {
        printf("Error: there are not sections available on %s!", conf->file);
        return;
    }

    /* Last section */
    section = mk_list_entry_last(head, struct mk_config_section, _head);

    /* Alloc new entry */
    new = malloc(sizeof(struct mk_config_entry));
    new->key = mk_string_dup(key);
    new->val = mk_string_dup(val);

    mk_list_add(&new->_head, &section->entries);
}

struct mk_config *mk_config_create(const char *path)
{
    int i;
    int len;
    int line = 0;
    int indent_len = -1;
    int n_keys = 0;
    char buf[255];
    char *section = NULL;
    char *indent = NULL;
    char *key, *val;
    struct mk_config *conf = NULL;
    struct mk_config_section *current = NULL;
    FILE *f;

    /* Open configuration file */
    if ((f = fopen(path, "r")) == NULL) {
        printf("Config: I cannot open %s file", path);
        return NULL;
    }

    /* Alloc configuration node */
    conf = calloc(1, sizeof(struct mk_config));
    conf->created = time(NULL);
    conf->file = mk_string_dup(path);
    mk_list_init(&conf->sections);

    /* looking for configuration directives */
    while (fgets(buf, 255, f)) {
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
                    mk_config_warning(path, line, "Previous section did not have keys");
                }

                /* Create new section */
                section = mk_string_copy_substr(buf, 1, end);
                current = mk_config_section_add(conf, section);
                mk_mem_free(section);
                n_keys = 0;
                continue;
            }
            else {
                mk_config_error(path, line, "Bad header definition");
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
        }

        /* Trim strings */
        mk_string_trim(&key);
        mk_string_trim(&val);

        /* Register entry: key and val are copied as duplicated */
        mk_config_entry_add(conf, key, val);

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
    struct mk_config_entry *e;

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
    if (indent) mk_mem_free(indent);
    return conf;
}

void mk_config_free(struct mk_config *conf)
{
    struct mk_config_section *section;
    struct mk_list *head, *tmp;

    /* Free sections */
    mk_list_foreach_safe(head, tmp, &conf->sections) {
        section = mk_list_entry(head, struct mk_config_section, _head);
        mk_list_del(&section->_head);

        /* Free section entries */
        mk_config_free_entries(section);

        /* Free section node */
        mk_mem_free(section->name);
        mk_mem_free(section);
    }
    if (conf->file) mk_mem_free(conf->file);
    if (conf) mk_mem_free(conf);
}

void mk_config_free_entries(struct mk_config_section *section)
{
    struct mk_config_entry *entry;
    struct mk_list *head, *tmp;

    mk_list_foreach_safe(head, tmp, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);
        mk_list_del(&entry->_head);

        /* Free memory assigned */
        mk_mem_free(entry->key);
        mk_mem_free(entry->val);
        mk_mem_free(entry);
    }
}

void *mk_config_section_getval(struct mk_config_section *section, char *key, int mode)
{
    int on, off;
    struct mk_config_entry *entry;
    struct mk_list *head;

    mk_list_foreach(head, &section->entries) {
        entry = mk_list_entry(head, struct mk_config_entry, _head);

        if (strcasecmp(entry->key, key) == 0) {
            switch (mode) {
            case MK_CONFIG_VAL_STR:
                return (void *) mk_string_dup(entry->val);
            case MK_CONFIG_VAL_NUM:
                return (void *) strtol(entry->val, (char **) NULL, 10);
            case MK_CONFIG_VAL_BOOL:
                on = strcasecmp(entry->val, "On");
                off = strcasecmp(entry->val, "Off");

                if (on != 0 && off != 0) {
                    return (void *) -1;
                }
                else if (on >= 0) {
                    return (void *) MK_TRUE;
                }
                else {
                    return (void *) MK_FALSE;
                }
            case MK_CONFIG_VAL_LIST:
                return (void *) mk_string_split_line(entry->val);
            }
        }
    }
    return NULL;
}

/* Print a specific error */
static void mk_config_print_error_msg(char *variable, char *path)
{
    printf("Error in %s variable under %s, has an invalid value",
           variable, path);
    mk_mem_free(path);
    exit(EXIT_FAILURE);
}
