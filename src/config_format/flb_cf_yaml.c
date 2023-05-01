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
#include <fluent-bit/flb_config_format.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_slist.h>

#include <cfl/cfl.h>
#include <cfl/cfl_sds.h>
#include <cfl/cfl_variant.h>
#include <cfl/cfl_kvlist.h>

#include <yaml.h>

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

#include <stdio.h>

enum section {
    SECTION_ENV,
    SECTION_INCLUDE,
    SECTION_SERVICE,
    SECTION_PIPELINE,
    SECTION_CUSTOM,
    SECTION_INPUT,
    SECTION_FILTER,
    SECTION_OUTPUT,
    SECTION_OTHER,
};

enum state {
    STATE_START,           /* start state */
    STATE_STREAM,          /* start/end stream */
    STATE_DOCUMENT,        /* start/end document */

    STATE_SECTION,         /* top level */
    STATE_SECTION_KEY,
    STATE_SECTION_VAL,

    STATE_SERVICE,         /* 'service' section */
    STATE_INCLUDE,         /* 'includes' section */
    STATE_OTHER,           /* any other unknown section */

    STATE_PIPELINE,        /* pipeline groups customs inputs, filters and outputs */

    STATE_PLUGIN_INPUT,    /* input plugins section */
    STATE_PLUGIN_FILTER,   /* filter plugins section */
    STATE_PLUGIN_OUTPUT,   /* output plugins section */

    STATE_CUSTOM,                  /* custom plugins */
    STATE_CUSTOM_SEQUENCE,
    STATE_CUSTOM_KEY_VALUE_PAIR,
    STATE_CUSTOM_KEY,
    STATE_CUSTOM_VAL,

    STATE_PLUGIN_TYPE,
    STATE_PLUGIN_KEY,
    STATE_PLUGIN_VAL,
    STATE_PLUGIN_VAL_LIST,

    STATE_GROUP_KEY,
    STATE_GROUP_VAL,

    STATE_INPUT_PROCESSOR,
    STATE_INPUT_PROCESSOR_LOGS_KEY,
    STATE_INPUT_PROCESSOR_LOGS_VAL,

    STATE_INPUT_PROCESSOR_METRICS_KEY,
    STATE_INPUT_PROCESSOR_METRICS_VAL,

    STATE_INPUT_PROCESSOR_TRACES_KEY,
    STATE_INPUT_PROCESSOR_TRACES_VAL,

    /* environment variables */
    STATE_ENV,


    STATE_STOP            /* end state */
};

struct parser_state {
    /* tokens state */
    enum state state;

    /* active section (if any) */
    enum section section;

    /* temporary key value pair */
    flb_sds_t key;
    flb_sds_t val;

    /* active section */
    struct flb_cf_section *cf_section;
    struct cfl_array *values; /* pointer to current values in a list. */

    /* active group */
    struct flb_cf_group *cf_group;

    /* active processor group: logs, metrics or traces */
    struct cfl_kvlist *cf_processor_kv;
    struct cfl_array *cf_processor_type_array;
    struct cfl_kvlist *cf_processor_type_list;

    /* file */
    flb_sds_t file;                /* file name */
    flb_sds_t root_path;           /* file root path */

    /* caller file */
    flb_sds_t caller_file;         /* caller file name */
    flb_sds_t caller_root_path;    /* caller file root path */
};

struct local_ctx {
    int level;                     /* inclusion level */

    struct mk_list includes;

    int service_set;
};

/* yaml_* functions return 1 on success and 0 on failure. */
enum status {
    YAML_SUCCESS = 1,
    YAML_FAILURE = 0
};

static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       char *caller_file, char *cfg_file);

static int add_section_type(struct flb_cf *cf, struct parser_state *s)
{
    if (s->section == SECTION_INPUT) {
        s->cf_section = flb_cf_section_create(cf, "INPUT", 0);
    }
    else if (s->section == SECTION_FILTER) {
        s->cf_section = flb_cf_section_create(cf, "FILTER", 0);
    }
    else if (s->section == SECTION_OUTPUT) {
        s->cf_section = flb_cf_section_create(cf, "OUTPUT", 0);
    }

    if (!s->cf_section) {
        return -1;
    }

    return 0;
}

static char *event_type_str(yaml_event_t *event)
{
    switch (event->type) {
    case YAML_NO_EVENT:
        return "no-event";
    case YAML_STREAM_START_EVENT:
        return "stream-start-event";
    case YAML_STREAM_END_EVENT:
        return "stream-end-event";
    case YAML_DOCUMENT_START_EVENT:
        return "document-start-event";
    case YAML_DOCUMENT_END_EVENT:
        return "document-end-event";
    case YAML_ALIAS_EVENT:
        return "alias-event";
    case YAML_SCALAR_EVENT:
        return "scalar-event";
    case YAML_SEQUENCE_START_EVENT:
        return "sequence-start-event";
        break;
    case YAML_SEQUENCE_END_EVENT:
        return "sequence-end-event";
    case YAML_MAPPING_START_EVENT:
        return "mapping-start-event";
    case YAML_MAPPING_END_EVENT:
        return "mapping-end-event";
    default:
        return "unknown";
    }
}

static char *get_last_included_file(struct local_ctx *ctx)
{
    struct flb_slist_entry *e;

    e = mk_list_entry_last(&ctx->includes, struct flb_slist_entry, _head);
    return e->str;
}

static void yaml_error_event(struct local_ctx *ctx, struct parser_state *s,
                             yaml_event_t *event)
{
    struct flb_slist_entry *e;

    e = mk_list_entry_last(&ctx->includes, struct flb_slist_entry, _head);

    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "unexpected event '%s' (%d) in state %d.",
              e->str, event->start_mark.line + 1, event->start_mark.column,
              event_type_str(event), event->type, s->state);
}

static void yaml_error_definition(struct local_ctx *ctx, struct parser_state *s,
                                  yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "duplicated definition of '%s'",
              s->file, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static void yaml_error_plugin_category(struct local_ctx *ctx, struct parser_state *s,
                                       yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "the pipeline component '%s' is not valid. Try one of these values: "
              "customs, inputs, filters or outputs.",
              s->file, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static int is_file_included(struct local_ctx *ctx, const char *path)
{
    struct mk_list *head;
    struct flb_slist_entry *e;

    mk_list_foreach(head, &ctx->includes) {
        e = mk_list_entry(head, struct flb_slist_entry, _head);
        if (strcmp(e->str, path) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

#ifndef _WIN32
static int read_glob(struct flb_cf *cf, struct local_ctx *ctx,
                     struct parser_state *state, const char *path)
{
    int ret = -1;
    glob_t glb;
    char tmp[PATH_MAX];

    const char *glb_path;
    size_t i;
    int ret_glb = -1;

    if (state->root_path && path[0] != '/') {
        snprintf(tmp, PATH_MAX, "%s/%s", state->root_path, path);
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
        ret = read_config(cf, ctx, state->file, glb.gl_pathv[i]);
        if (ret < 0) {
            break;
        }
    }

    globfree(&glb);
    return ret;
}
#else
static int read_glob(struct flb_cf *cf, struct parser_state *ctx, const char *path)
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
            if (read_config(cf, ctx, data.cFileName, buf) < 0) {
                return -1;
            }
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return 0;
}
#endif

static int consume_event(struct flb_cf *cf, struct local_ctx *ctx,
                         struct parser_state *s, yaml_event_t *event)
{
    int len;
    int ret;
    char *value;
    struct flb_kv *kv;
    char *last_included = get_last_included_file(ctx);

    switch (s->state) {
    case STATE_START:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            s->state = STATE_STREAM;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_STREAM:
        switch (event->type) {
        case YAML_DOCUMENT_START_EVENT:
            s->state = STATE_DOCUMENT;
            break;
        case YAML_STREAM_END_EVENT:
            s->state = STATE_STOP;  /* all done */
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_DOCUMENT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_SECTION;
            break;
        case YAML_DOCUMENT_END_EVENT:
            s->state = STATE_STREAM;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    /*
     * 'customs'
     *  --------
     */
    case STATE_CUSTOM:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            s->state = STATE_CUSTOM_SEQUENCE;
            break;

        case YAML_SEQUENCE_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_CUSTOM_SEQUENCE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            len = strlen(value);
            if (len == 0) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }

            /* create the 'customs' section */
            s->cf_section = flb_cf_section_create(cf, "customs", 0);
            if (!s->cf_section) {
                return YAML_FAILURE;
            }

            /* value is the 'custom plugin name', create a section instance */
            if (flb_cf_section_property_add(cf, s->cf_section->properties,
                                            "name", 4,
                                            value, len) < 0) {
                return YAML_FAILURE;
            }

            /* next state are key value pairs for the custom plugin*/
            s->state = STATE_CUSTOM_KEY_VALUE_PAIR;
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            break;
        case YAML_SEQUENCE_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;
    case STATE_CUSTOM_KEY_VALUE_PAIR:
        switch(event->type) {
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_CUSTOM_KEY;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_CUSTOM;
            break;
        case YAML_SEQUENCE_END_EVENT:
            break;

        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_CUSTOM_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_CUSTOM_VAL;
            value = (char *) event->data.scalar.value;
            s->key = flb_sds_create(value);
            break;
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_CUSTOM;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_CUSTOM_SEQUENCE;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_CUSTOM_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_CUSTOM_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* register key/value pair as a property */
            flb_cf_section_property_add(cf, s->cf_section->properties,
                                        s->key, flb_sds_len(s->key),
                                        s->val, flb_sds_len(s->val));
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            break;
        case YAML_MAPPING_START_EVENT: /* start a new group */
            s->state = STATE_GROUP_KEY;
            s->cf_group = flb_cf_group_create(cf, s->cf_section,
                                              s->key, flb_sds_len(s->key));
            flb_sds_destroy(s->key);
            if (!s->cf_group) {
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;
    /* end of 'customs' */

    /*
     * 'includes'
     *  --------
     */
    case STATE_INCLUDE:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            break;
        case YAML_SEQUENCE_END_EVENT:
            s->state = STATE_SECTION;
            break;
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;
            flb_debug("[config yaml] including: %s", value);
            if (strchr(value, '*') != NULL) {
                ret = read_glob(cf, ctx, s, value);
            }
            else {
                ret = read_config(cf, ctx, s->file, value);
            }
            if (ret == -1) {
                flb_error("[config]  including file '%s' at %s:%zu",
                          value,
                          last_included, event->start_mark.line + 1);
                return YAML_FAILURE;
            }
            ctx->level++;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;
    /* end of 'includes' */

    case STATE_PIPELINE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            if (strcasecmp(value, "inputs") == 0) {
                s->state = STATE_PLUGIN_INPUT;
                s->section = SECTION_INPUT;
            }
            else if (strcasecmp(value, "filters") == 0) {
                s->state = STATE_PLUGIN_FILTER;
                s->section = SECTION_FILTER;
            }
            else if (strcasecmp(value, "outputs") == 0) {
                s->state = STATE_PLUGIN_OUTPUT;
                s->section = SECTION_OUTPUT;
            }
            else {
                yaml_error_plugin_category(ctx, s, event, value);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION:
        s->section = SECTION_OTHER;
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            if (strcasecmp(value, "env") == 0) {
                s->state = STATE_ENV;
                s->section = SECTION_ENV;
            }
            else if (strcasecmp(value, "pipeline") == 0) {
                s->state = STATE_PIPELINE;
                s->section = SECTION_PIPELINE;
            }
            else if (strcasecmp(value, "service") == 0) {
                if (ctx->service_set) {
                    yaml_error_definition(ctx, s, event, value);
                    return YAML_FAILURE;
                }
                s->state = STATE_SERVICE;
                s->section = SECTION_SERVICE;
                s->cf_section = flb_cf_section_create(cf, value, 0);
                if (!s->cf_section) {
                    return YAML_FAILURE;
                }
                ctx->service_set = 1;
            }
            else if (strcasecmp(value, "customs") == 0) {
                s->state = STATE_CUSTOM;
                s->section = SECTION_CUSTOM;
            }
            else if (strcasecmp(value, "includes") == 0) {
                s->state = STATE_INCLUDE;
                s->section = SECTION_INCLUDE;
            }
            else {
                /* any other main section definition (e.g: similar to STATE_SERVICE) */
                s->state = STATE_OTHER;
                s->cf_section = flb_cf_section_create(cf, value, 0);
                if (!s->cf_section) {
                    return YAML_FAILURE;
                }
            }
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_DOCUMENT;
            break;
        case YAML_DOCUMENT_END_EVENT:
            s->state = STATE_STREAM;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    /* service or others */
    case STATE_ENV:
    case STATE_SERVICE:
    case STATE_OTHER:
        switch(event->type) {
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_SECTION_KEY;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_SECTION_VAL;
            value = (char *) event->data.scalar.value;
            s->key = flb_sds_create(value);
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_SECTION_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* Check if the incoming k/v pair set a config environment variable */
            if (s->section == SECTION_ENV) {
                kv = flb_cf_env_property_add(cf,
                                             s->key, flb_sds_len(s->key),
                                             s->val, flb_sds_len(s->val));
                if (kv == NULL) {
                    return YAML_FAILURE;
                }
            }
            else {
                /* register key/value pair as a property */
                if (s->cf_section == NULL) {
                    return YAML_FAILURE;
                }
                if (flb_cf_section_property_add(cf, s->cf_section->properties,
                                                s->key, flb_sds_len(s->key),
                                                s->val, flb_sds_len(s->val)) < 0) {
                    return YAML_FAILURE;
                }
            }
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    /* Plugin types */
    case STATE_PLUGIN_INPUT:
    case STATE_PLUGIN_FILTER:
    case STATE_PLUGIN_OUTPUT:
        switch(event->type) {
        case YAML_SEQUENCE_START_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        case YAML_SEQUENCE_END_EVENT:
            break;
        case YAML_SCALAR_EVENT:
            s->state = STATE_SECTION;
            break;
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION_KEY;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_TYPE:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* register the section by type */
            ret = add_section_type(cf, s);
            if (ret == -1) {
                return YAML_FAILURE;
            }

            /* the next state is the keys of the properties of the plugin. */
            s->state = STATE_PLUGIN_KEY;
            break;
        case YAML_MAPPING_START_EVENT:
            ret = add_section_type(cf, s);
            if (ret == -1) {
                return YAML_FAILURE;
            }
            s->state = STATE_PLUGIN_KEY;
            break;
        case YAML_MAPPING_END_EVENT:
            break;
        case YAML_SEQUENCE_END_EVENT:
            s->state = STATE_PIPELINE;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_PLUGIN_VAL;
            value = (char *) event->data.scalar.value;
            s->key = flb_sds_create(value);
            break;
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        case YAML_SEQUENCE_END_EVENT:
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_INPUT_PROCESSOR:
        switch(event->type) {
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                s->state = STATE_PLUGIN_KEY;
                break;
            case YAML_SCALAR_EVENT:
                /* remove 'processors' key, not longer needed */
                if (s->key) {
                    flb_sds_destroy(s->key);
                    s->key = NULL;
                }
                /* Check if we are entering a 'logs', 'metrics' or 'traces' section */
                value = (char *) event->data.scalar.value;
                if (strcasecmp(value, "logs") == 0) {
                    /* logs state */
                    s->state = STATE_INPUT_PROCESSOR_LOGS_KEY;

                    /* create the array for definitions found under 'log' */
                    s->cf_processor_type_array = cfl_array_create(1);
                    cfl_array_resizable(s->cf_processor_type_array, CFL_TRUE);

                    cfl_kvlist_insert_array(s->cf_group->properties, "logs", s->cf_processor_type_array);
                }
                else if (strcasecmp(value, "metrics") == 0) {
                    /* metrics state */
                    s->state = STATE_INPUT_PROCESSOR_METRICS_KEY;

                    /* create the array for definitions found under 'log' */
                    s->cf_processor_type_array = cfl_array_create(1);
                    cfl_array_resizable(s->cf_processor_type_array, CFL_TRUE);

                    cfl_kvlist_insert_array(s->cf_group->properties, "metrics", s->cf_processor_type_array);
                }
                else if (strcasecmp(value, "traces") == 0) {
                    /* metrics state */
                    s->state = STATE_INPUT_PROCESSOR_TRACES_KEY;

                    /* create the array for definitions found under 'log' */
                    s->cf_processor_type_array = cfl_array_create(1);
                    cfl_array_resizable(s->cf_processor_type_array, CFL_TRUE);

                    cfl_kvlist_insert_array(s->cf_group->properties, "traces", s->cf_processor_type_array);
                }
                else {
                    flb_error("[config] unknown processor '%s'", value);
                    yaml_error_event(ctx, s, event);
                    return YAML_FAILURE;
                }
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;
    case STATE_INPUT_PROCESSOR_LOGS_KEY:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:
                s->state = STATE_INPUT_PROCESSOR;
                break;
            case YAML_MAPPING_START_EVENT:
                s->cf_processor_type_list = cfl_kvlist_create();
                cfl_array_append_kvlist(s->cf_processor_type_array, s->cf_processor_type_list);
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                /* Check if we are entering a 'logs', 'metrics' or 'traces' section */
                value = (char *) event->data.scalar.value;
                s->key = flb_sds_create(value);
                s->state = STATE_INPUT_PROCESSOR_LOGS_VAL;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR_LOGS_VAL:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                s->state = STATE_INPUT_PROCESSOR_LOGS_KEY;
                break;
            case YAML_SEQUENCE_END_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                value = (char *) event->data.scalar.value;
                if (!s->cf_processor_type_list || !s->key || !value) {
                    s->state = STATE_INPUT_PROCESSOR;
                    break;
                }
                cfl_kvlist_insert_string(s->cf_processor_type_list, s->key, value);
                flb_sds_destroy(s->key);
                s->key = NULL;
                s->state = STATE_INPUT_PROCESSOR_LOGS_KEY;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR_METRICS_KEY:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:
                s->state = STATE_INPUT_PROCESSOR;
                break;
            case YAML_MAPPING_START_EVENT:
                s->cf_processor_type_list = cfl_kvlist_create();
                cfl_array_append_kvlist(s->cf_processor_type_array, s->cf_processor_type_list);
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                value = (char *) event->data.scalar.value;
                s->key = flb_sds_create(value);
                s->state = STATE_INPUT_PROCESSOR_METRICS_VAL;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR_METRICS_VAL:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                s->state = STATE_INPUT_PROCESSOR_METRICS_KEY;
                break;
            case YAML_SEQUENCE_END_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                value = (char *) event->data.scalar.value;
                cfl_kvlist_insert_string(s->cf_processor_type_list, s->key, value);
                flb_sds_destroy(s->key);
                s->key = NULL;
                s->val = NULL;
                s->state = STATE_INPUT_PROCESSOR_METRICS_KEY;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR_TRACES_KEY:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:
                s->state = STATE_INPUT_PROCESSOR;
                break;
            case YAML_MAPPING_START_EVENT:
                s->cf_processor_type_list = cfl_kvlist_create();
                cfl_array_append_kvlist(s->cf_processor_type_array, s->cf_processor_type_list);
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                value = (char *) event->data.scalar.value;
                s->key = flb_sds_create(value);
                s->state = STATE_INPUT_PROCESSOR_TRACES_VAL;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR_TRACES_VAL:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                s->state = STATE_INPUT_PROCESSOR_TRACES_KEY;
                break;
            case YAML_SEQUENCE_END_EVENT:
                break;
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                break;
            case YAML_SCALAR_EVENT:
                value = (char *) event->data.scalar.value;
                cfl_kvlist_insert_string(s->cf_processor_type_list, s->key, value);
                flb_sds_destroy(s->key);
                s->key = NULL;
                s->val = NULL;
                s->state = STATE_INPUT_PROCESSOR_TRACES_KEY;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;
    case STATE_PLUGIN_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_PLUGIN_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* register key/value pair as a property */
            if (flb_cf_section_property_add(cf, s->cf_section->properties,
                                            s->key, flb_sds_len(s->key),
                                            s->val, flb_sds_len(s->val)) < 0) {
                return YAML_FAILURE;
            }
            if (cfl_kvlist_count(s->cf_section->properties) <= 0) {
                return YAML_FAILURE;
            }
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            s->key = NULL;
            s->val = NULL;
            break;
        case YAML_SEQUENCE_START_EVENT: /* start a new group */
            if (strcmp(s->key, "processors") == 0) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            s->state = STATE_GROUP_KEY;
            s->cf_group = flb_cf_group_create(cf, s->cf_section,
                                              s->key, flb_sds_len(s->key));
            flb_sds_destroy(s->key);
            if (!s->cf_group) {
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:   /* end of group */
            s->state = STATE_PLUGIN_KEY;
            break;
        case YAML_MAPPING_START_EVENT:
            /* create group */
            s->cf_group = flb_cf_group_create(cf, s->cf_section, s->key, strlen(s->key));

            /* Special handling for input processor */
            if (strcmp(s->key, "processors") == 0) {
                s->state = STATE_INPUT_PROCESSOR;
                break;
            }

            s->state = STATE_GROUP_KEY;
            s->values = flb_cf_section_property_add_list(cf,
                                                         s->cf_section->properties,
                                                         s->key, flb_sds_len(s->key));
            if (s->values == NULL) {
                return YAML_FAILURE;
            }
            flb_sds_destroy(s->key);
            s->key = NULL;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_PLUGIN_KEY;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_VAL_LIST:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            if (s->values == NULL) {
                return YAML_FAILURE;
            }
            cfl_array_append_string(s->values, (char *)event->data.scalar.value);
            break;
        case YAML_SEQUENCE_END_EVENT:
            s->values = NULL;
            s->state = STATE_PLUGIN_KEY;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    /* groups: a group is a sub-section and here we handle the key/value pairs */
    case STATE_GROUP_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* next state */
            s->state = STATE_GROUP_VAL;

            /* grab current value (key) */
            value = (char *) event->data.scalar.value;
            s->key = flb_sds_create(value);
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_PLUGIN_KEY;
            break;
        case YAML_SEQUENCE_END_EVENT:
            s->state = STATE_PLUGIN_KEY;
            s->cf_group = NULL;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_GROUP_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_GROUP_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* add the kv pair to the active group properties */
            flb_cf_section_property_add(cf, s->cf_group->properties,
                                        s->key, flb_sds_len(s->key),
                                        s->val, flb_sds_len(s->val));
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            s->key = NULL;
            s->val = NULL;

            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_STOP:
        break;
    }

    return YAML_SUCCESS;
}

static char *get_real_path(char *file, char *path, size_t size)
{
    int len;
    char *p;
    char *end;

#ifdef _MSC_VER
    p = _fullpath(path, file, size);
#else
    p = realpath(file, path);
#endif

    if (!p) {
        len = strlen(file);
        if (len > size) {
            return NULL;
        }
        memcpy(path, file, len);
        path[len] = '\0';
    }

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

    return path;
}

static void state_destroy(struct parser_state *s)
{
    if (s->caller_file) {
        flb_sds_destroy(s->caller_file);
    }
    if (s->caller_root_path) {
        flb_sds_destroy(s->caller_root_path);
    }

    if (s->file) {
        flb_sds_destroy(s->file);
    }

    if (s->root_path) {
        flb_sds_destroy(s->root_path);
    }
    flb_free(s);
}

static struct parser_state *state_create(char *caller_file, char *file)
{
    int ret;
    char *p;
    char file_path[PATH_MAX + 1] = {0};
    char caller_path[PATH_MAX + 1] = {0};
    struct parser_state *s;
    struct stat st;

    if (!file) {
        return NULL;
    }

    /* allocate context */
    s = flb_calloc(1, sizeof(struct parser_state));
    if (!s) {
        flb_errno();
        return NULL;
    }

    /* resolve real path for caller file and target file */
#ifndef FLB_HAVE_STATIC_CONF
    if (caller_file) {
        p = get_real_path(caller_file, caller_path, PATH_MAX + 1);
        if (!p) {
            state_destroy(s);
            return NULL;
        }
        s->caller_file = flb_sds_create(caller_file);
        s->caller_root_path = flb_sds_create(caller_path);
    }
    else {
        s->caller_file = flb_sds_create(s->file);
        s->caller_root_path = flb_sds_create(s->root_path);
    }

    /* check if the file exists */
    ret = stat(file, &st);
    if (ret == 0) {
        p = get_real_path(file, file_path, PATH_MAX + 1);
        s->file = flb_sds_create(file);
        s->root_path = flb_sds_create(file_path);
    }
    else if (errno == ENOENT && caller_file && s->caller_root_path != NULL) {
        snprintf(file_path, PATH_MAX, "%s/%s", s->caller_root_path, file);
        s->file = flb_sds_create(file_path);
    }
#endif

    return s;
}

static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       char *caller_file, char *cfg_file)
{
    int ret;
    int status;
    int code = 0;
    char *file;
    struct parser_state *state;
    yaml_parser_t parser;
    yaml_event_t event;
    FILE *fh;

    state = state_create(caller_file, cfg_file);
    if (!state) {
        return -1;
    }
    file = state->file;

    /* check if this file has been included before */
    ret = is_file_included(ctx, file);
    if (ret) {
        flb_error("[config] file '%s' is already included", file);
        state_destroy(state);
        return -1;
    }

    fh = fopen(file, "r");
    if (!fh) {
        flb_errno();
        state_destroy(state);
        return -1;
    }

    /* add file to the list of included files */
    ret = flb_slist_add(&ctx->includes, file);
    if (ret == -1) {
        flb_error("[config] could not register file %s", file);
        fclose(fh);
        state_destroy(state);
        return -1;
    }
    ctx->level++;

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    do {
        status = yaml_parser_parse(&parser, &event);
        if (status == YAML_FAILURE) {
            flb_error("[config] invalid YAML format in file %s", file);
            code = -1;
            goto done;
        }
        status = consume_event(cf, ctx, state, &event);
        if (status == YAML_FAILURE) {
            code = -1;
            goto done;
        }
        yaml_event_delete(&event);
    } while (state->state != STATE_STOP);

done:
    if (code == -1) {
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    state_destroy(state);

    fclose(fh);
    ctx->level--;

    return code;
}

static int local_init(struct local_ctx *ctx, char *file)
{
    char *end;
    char path[PATH_MAX + 1] = {0};

    /* reset the state */
    memset(ctx, '\0', sizeof(struct local_ctx));

#ifndef FLB_HAVE_STATIC_CONF
    char *p;

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
#endif

    /* lookup path ending and truncate */
    end = strrchr(path, '/');
    if (end) {
        end++;
        *end = '\0';
    }

    ctx->level = 0;
    flb_slist_create(&ctx->includes);

    return 0;
}

static void local_exit(struct local_ctx *ctx)
{
    flb_slist_destroy(&ctx->includes);
}

struct flb_cf *flb_cf_yaml_create(struct flb_cf *cf, char *file_path,
                                  char *buf, size_t size)
{
    int ret;
    struct local_ctx ctx;

    if (!cf) {
        cf = flb_cf_create();
        if (!cf) {
            return NULL;
        }
    }

    /* initialize the parser state */
    ret = local_init(&ctx, file_path);
    if (ret == -1) {
        flb_cf_destroy(cf);
        return NULL;
    }

    /* process the entry poing config file */
    ret = read_config(cf, &ctx, NULL, file_path);
    if (ret == -1) {
        flb_cf_destroy(cf);
        local_exit(&ctx);
        return NULL;
    }

    local_exit(&ctx);
    return cf;
}
