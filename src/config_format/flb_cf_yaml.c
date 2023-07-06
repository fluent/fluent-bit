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
    SECTION_PROCESSOR,
    SECTION_OTHER,
};

static char *section_names[] = {
    "env",
    "include",
    "service",
    "pipeline",
    "custom",
    "input",
    "filter",
    "output",
    "processor",
    "other"
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

    STATE_CUSTOM,          /* custom plugins */
    STATE_PIPELINE,        /* pipeline groups customs inputs, filters and outputs */

    STATE_PLUGIN_INPUT,    /* input plugins section */
    STATE_PLUGIN_FILTER,   /* filter plugins section */
    STATE_PLUGIN_OUTPUT,   /* output plugins section */

    STATE_PLUGIN_START,
    STATE_PLUGIN_KEY,
    STATE_PLUGIN_VAL,
    STATE_PLUGIN_VAL_LIST,

    STATE_GROUP_KEY,
    STATE_GROUP_VAL,

    STATE_INPUT_PROCESSORS,
    STATE_INPUT_PROCESSOR,

    /* environment variables */
    STATE_ENV,


    STATE_STOP            /* end state */
};

static char *state_names[] = {
    "start",           /* start state */
    "stream",          /* start/end stream */
    "document",        /* start/end document */

    "section",         /* top level */
    "section-key",
    "section-value",

    "service",         /* 'service' section */
    "include",         /* 'includes' section */
    "other",           /* any other unknown section */

    "custom",          /* custom plugins */
    "pipeline",        /* pipeline groups customs inputs, filters and outputs */

    "input",    /* input plugins section */
    "filter",   /* filter plugins section */
    "output",   /* output plugins section */

    "plugin-start",
    "plugin-key",
    "plugin-value",
    "plugin-values",

    "group-key",
    "group-value",

    "processors",
    "processor",
    "processor-map",

    /* environment variables */
    "env",


    "stop"            /* end state */
};

struct file_state {
    /* file */
    flb_sds_t name;                /* file name */
    flb_sds_t path;           /* file root path */

    /* parent file state */
    struct file_state *parent;
};

enum parser_state_allocations {
    HAS_KEY     = (1 << 0),
    HAS_KEYVALS = (1 << 1)
};

struct parser_state {
    /* tokens state */
    enum state state;
    /* nesting level */
    int level;

    /* active section (if any) */
    enum section section;

    /* active section */
    struct flb_cf_section *cf_section;
    /* active group */
    struct flb_cf_group *cf_group;

    /* key value */
    flb_sds_t key;
    /* section key/value list */
    struct cfl_kvlist *keyvals;
    /* pointer to current values in a list. */
    struct cfl_array *values;
    /* are we the owner of the values? */
    int allocation_flags;

    struct file_state *file;

    struct cfl_list _head;
};

struct local_ctx {
    int level;                     /* inclusion level */

    struct cfl_list states;

    struct mk_list includes;

    int service_set;
};

static struct parser_state *state_push(struct local_ctx *, enum state);
static struct parser_state *state_push_withvals(struct local_ctx *,
                                                struct parser_state *,
                                                enum state);
static struct parser_state *state_push_witharr(struct local_ctx *,
                                               struct parser_state *,
                                               enum state);
static struct parser_state *state_push_section(struct local_ctx *, enum state,
                                               enum section);
static struct parser_state *state_push_key(struct local_ctx *, enum state,
                                           const char *key);
static int state_create_section(struct flb_cf *, struct parser_state *, char *);
static int state_create_group(struct flb_cf *, struct parser_state *, char *);
static struct parser_state *state_pop(struct local_ctx *ctx);
static struct parser_state *state_create(struct file_state *parent, struct file_state *file);
static void state_destroy(struct parser_state *s);

/* yaml_* functions return 1 on success and 0 on failure. */
enum status {
    YAML_SUCCESS = 1,
    YAML_FAILURE = 0
};

static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       struct file_state *parent, char *cfg_file);

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
    else if (s->section == SECTION_CUSTOM) {
        s->cf_section = flb_cf_section_create(cf, "customs", 0);
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

static char *state_str(enum state val)
{
    char* ret;
    switch(val) {
    case STATE_START:
        ret = "start";
        break;
    case STATE_STREAM:
        ret = "stream";
        break;
    case STATE_DOCUMENT:
        ret = "document";
        break;
    case STATE_SECTION:
        ret = "section";
        break;
    case STATE_SECTION_KEY:
        ret = "section-key";
        break;
    case STATE_SECTION_VAL:
        ret = "section-val";
        break;
    case STATE_SERVICE:
        ret = "service";
        break;
    case STATE_INCLUDE:
        ret = "include";
        break;
    case STATE_OTHER:
        ret = "other";
        break;
    case STATE_PIPELINE:
        ret = "pipeline";
        break;
    case STATE_PLUGIN_INPUT:
        ret = "plugin-input";
        break;
    case STATE_PLUGIN_FILTER:
        ret = "plugin-filter";
        break;
    case STATE_PLUGIN_OUTPUT:
        ret = "plugin-output";
        break;
    case STATE_CUSTOM:
        ret = "custom";
        break;
    case STATE_PLUGIN_KEY:
        ret = "plugin-key";
        break;
    case STATE_PLUGIN_VAL:
        ret = "plugin-val";
        break;
    case STATE_PLUGIN_VAL_LIST:
        ret = "plugin-val-list";
        break;
    case STATE_GROUP_KEY:
        ret = "group-key";
        break;
    case STATE_GROUP_VAL:
        ret = "group-val";
        break;
    case STATE_INPUT_PROCESSOR:
        ret = "input-processor";
        break;
    case STATE_ENV:
        ret = "env";
        break;
    case STATE_STOP:
        ret = "stop";
        break;

    default:
        ret = "UNKNOWN";
    }
    return ret;
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
              "unexpected event '%s' (%d) in state '%s' (%d).",
              e->str, event->start_mark.line + 1, event->start_mark.column,
              event_type_str(event), event->type, state_str(s->state), s->state);
}

static void yaml_error_definition(struct local_ctx *ctx, struct parser_state *s,
                                  yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "duplicated definition of '%s'",
              s->file->name, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static void yaml_error_plugin_category(struct local_ctx *ctx, struct parser_state *s,
                                       yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "the pipeline component '%s' is not valid. Try one of these values: "
              "customs, inputs, filters or outputs.",
              s->file->name, event->start_mark.line + 1, event->start_mark.column,
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

    if (state->file->path && path[0] != '/') {
        snprintf(tmp, PATH_MAX, "%s/%s", state->file->path, path);
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
            if (read_config(cf, ctx, state->file, buf) < 0) {
                return -1;
            }
        }
    } while (FindNextFileA(h, &data) != 0);

    FindClose(h);
    return 0;
}
#endif

static void print_current_state(struct local_ctx *ctx, struct parser_state *s,
                                yaml_event_t *event)
{
    int i;

    flb_debug("%*s%s->%s", s->level*2, "", state_names[s->state], 
             event_type_str(event));
}

static void print_current_properties(struct parser_state *s)
{
    struct cfl_list *head;
    struct cfl_kvpair *kv;
    struct cfl_variant *var;

    flb_debug("%*s[%s] PROPERTIES:", s->level*2, "", section_names[s->section]);

    cfl_list_foreach(head, &s->keyvals->list) {
        kv = cfl_list_entry(head, struct cfl_kvpair, _head);
        switch (kv->val->type) {
        case CFL_VARIANT_STRING:
            flb_debug("%*s%s: %s", (s->level+2)*2, "", kv->key, kv->val->data.as_string);
            break;
        case CFL_VARIANT_ARRAY:
            flb_debug("%*s%s: [", (s->level+2)*2, "", kv->key);
            for (int i = 0; i < kv->val->data.as_array->entry_count; i++) {
                var = cfl_array_fetch_by_index(kv->val->data.as_array, i);
                flb_debug("%*s%s", (s->level+3)*2, "", var->data.as_string);
            }
            flb_debug("%*s]", (s->level+2)*2, "");
            break;
        }
    }
}

static struct parser_state *get_current_state(struct local_ctx *ctx)
{
    struct parser_state *s;
    s = cfl_list_entry_last(&ctx->states, struct parser_state, _head);
    return s;
}

static int consume_event(struct flb_cf *cf, struct local_ctx *ctx,
                         yaml_event_t *event)
{
    struct parser_state *s;
    int ret;
    char *value;
    struct flb_kv *kv;
    char *last_included = get_last_included_file(ctx);

    s = get_current_state(ctx);
    print_current_state(ctx, s, event);

    switch (s->state) {
    case STATE_START:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            s = state_push(ctx, STATE_STREAM);
            if (s == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_NO_EVENT:
            s->state = STATE_STOP;
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_STREAM:
        switch (event->type) {
        case YAML_DOCUMENT_START_EVENT:
            s = state_push(ctx, STATE_DOCUMENT);
            break;
        case YAML_STREAM_END_EVENT:
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_DOCUMENT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            s = state_push(ctx, STATE_SECTION);
            break;
        case YAML_DOCUMENT_END_EVENT:
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    /*
     * 'includes'
     *  --------
     */
    case STATE_INCLUDE:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            break;
        case YAML_SEQUENCE_END_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_SECTION) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
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
                flb_error("[config] including file '%s' at %s:%zu",
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

    /*
     * 'customs'
     *  --------
     */
    case STATE_CUSTOM:
        switch (event->type) {
        case YAML_SEQUENCE_START_EVENT:
            break;
        case YAML_MAPPING_START_EVENT:
            s = state_push_withvals(ctx, s, STATE_PLUGIN_START);
            add_section_type(cf, s);
            break;
        case YAML_SEQUENCE_END_EVENT:
            state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;
    /* end of 'customs' */

    case STATE_PIPELINE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            if (strcasecmp(value, "inputs") == 0) {
                s = state_push_section(ctx, STATE_PLUGIN_INPUT, SECTION_INPUT);
            }
            else if (strcasecmp(value, "filters") == 0) {
                s = state_push_section(ctx, STATE_PLUGIN_FILTER, SECTION_FILTER);
            }
            else if (strcasecmp(value, "outputs") == 0) {
                s = state_push_section(ctx, STATE_PLUGIN_OUTPUT, SECTION_OUTPUT);
            }
            else {
                yaml_error_plugin_category(ctx, s, event, value);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            if (strcasecmp(value, "env") == 0) {
                s = state_push_section(ctx, STATE_ENV, SECTION_ENV);
            }
            else if (strcasecmp(value, "pipeline") == 0) {
                s = state_push_section(ctx, STATE_PIPELINE, SECTION_PIPELINE);
            }
            else if (strcasecmp(value, "service") == 0) {
                if (ctx->service_set) {
                    yaml_error_definition(ctx, s, event, value);
                    return YAML_FAILURE;
                }
                s = state_push_section(ctx, STATE_SERVICE, SECTION_SERVICE);
                state_create_section(cf, s, value);
                if (!s->cf_section) {
                    flb_error("unable to allocate section: %s", value);
                    return YAML_FAILURE;
                }
                ctx->service_set = 1;
            }
            else if (strcasecmp(value, "customs") == 0) {
                s = state_push_section(ctx, STATE_CUSTOM, SECTION_CUSTOM);
            }
            else if (strcasecmp(value, "includes") == 0) {
                s = state_push_section(ctx, STATE_INCLUDE, SECTION_INCLUDE);
            }
            else {
                /* any other main section definition (e.g: similar to STATE_SERVICE) */
                s = state_push(ctx, STATE_OTHER);
                state_create_section(cf, s, value);
                if (!s->cf_section) {
                    flb_error("unable to allocate section: %s", value);
                    return YAML_FAILURE;
                }
            }
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
            break;
        case YAML_DOCUMENT_END_EVENT:
            s = state_pop(ctx);
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
            state_push(ctx, STATE_SECTION_KEY);
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_SECTION) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;
            s = state_push_key(ctx, STATE_SECTION_VAL, value);
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
            switch (s->state) {
            case STATE_SERVICE:
            case STATE_ENV:
            case STATE_OTHER:
                break;
            default:
                printf("BAD STATE FOR SECTION KEY POP=%s\n", state_names[s->state]);
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;
            /* Check if the incoming k/v pair set a config environment variable */
            if (s->section == SECTION_ENV) {
                kv = flb_cf_env_property_add(cf,
                                             s->key, flb_sds_len(s->key),
                                             value, strlen(value));
                if (kv == NULL) {
                    flb_error("unable to add key value");
                    return YAML_FAILURE;
                }
            }
            else {
                /* register key/value pair as a property */
                if (s->cf_section == NULL) {
                    flb_error("no section to register key value to");
                    return YAML_FAILURE;
                }
                if (flb_cf_section_property_add(cf, s->cf_section->properties,
                                                s->key, flb_sds_len(s->key),
                                                value, strlen(value)) < 0) {
                    flb_error("unable to add property");
                    return YAML_FAILURE;
                }
            }

            s = state_pop(ctx);
            if (s->state != STATE_SECTION_KEY) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
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
            break;
        case YAML_SEQUENCE_END_EVENT:
            s = state_pop(ctx);
            break;
        case YAML_MAPPING_START_EVENT:
            s = state_push_withvals(ctx, s, STATE_PLUGIN_START);
            add_section_type(cf, s);
            break;
        case YAML_SCALAR_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_SECTION) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_SECTION_KEY) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_START:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* Here is where we process all the plugin properties for customs, pipelines
             * and processors.
             */
            s = state_push_key(ctx, STATE_PLUGIN_VAL, (char *) event->data.scalar.value);
            break;
        case YAML_MAPPING_END_EVENT:
            struct cfl_list *head;
            struct cfl_kvpair *kv;
            struct cfl_variant *var;
            struct cfl_array *arr;
            struct cfl_array *carr;

            print_current_properties(s);

            if (s->section == SECTION_PROCESSOR) {
                struct cfl_kvlist *copy;

                if (s->cf_group == NULL) {
                    flb_error("no group for processor properties");
                    return YAML_FAILURE;
                }

                arr = cfl_kvlist_fetch(s->cf_group->properties, s->key);
                if (arr == NULL) {
                    arr = cfl_array_create(1);
                    cfl_array_resizable(arr, CFL_TRUE);
                    cfl_kvlist_insert_array(s->cf_group->properties, s->key, arr);
                }

                copy = cfl_kvlist_create();
                cfl_list_foreach(head, &s->keyvals->list) {
                    kv = cfl_list_entry(head, struct cfl_kvpair, _head);
                    switch (kv->val->type) {
                    case CFL_VARIANT_STRING:
                        cfl_kvlist_insert_string(copy, kv->key, kv->val->data.as_string);
                        break;
                    case CFL_VARIANT_ARRAY:
                        carr = cfl_array_create(kv->val->data.as_array->entry_count);
                        for (int i = 0; i < kv->val->data.as_array->entry_count; i++) {
                            var = cfl_array_fetch_by_index(kv->val->data.as_array, i);
                            switch (var->type) {
                            case CFL_VARIANT_STRING:
                                cfl_array_append_string(carr, var->data.as_string);
                                break;
                            default:
                                flb_error("unable to copy value for property");
                                return YAML_FAILURE;
                            }
                        }
                        cfl_kvlist_insert_array(copy, kv->key, carr);
                        break;
                    default:
                        flb_error("unknown value type for properties: %d", kv->val->type);
                        return YAML_FAILURE;
                    }
                }

                cfl_array_append_kvlist(arr, copy);
                state_pop(ctx);
                break;
            }

            cfl_list_foreach(head, &s->keyvals->list) {
                kv = cfl_list_entry(head, struct cfl_kvpair, _head);
                switch (kv->val->type) {
                case CFL_VARIANT_STRING:
                    var = flb_cf_section_property_add(cf,
                                                    s->cf_section->properties,
                                                    kv->key,
                                                    cfl_sds_len(kv->key),
                                                    kv->val->data.as_string,
                                                    cfl_sds_len(kv->val->data.as_string));
                    if (var == NULL) {
                        flb_error("unable to add variant value property");
                        return YAML_FAILURE;
                    }
                    break;
                case CFL_VARIANT_ARRAY:
                    arr = flb_cf_section_property_add_list(cf, s->cf_section->properties,
                                                           kv->key, cfl_sds_len(kv->key));
                    for (int i = 0; i < kv->val->data.as_array->entry_count; i++) {
                        var = cfl_array_fetch_by_index(kv->val->data.as_array, i);
                        switch (var->type) {
                        case CFL_VARIANT_STRING:
                            cfl_array_append_string(arr, var->data.as_string);
                            break;
                        default:
                            flb_error("unable to copy value for property");
                            return YAML_FAILURE;
                        }
                    }
                    break;
                default:
                    flb_error("unknown value type for properties: %d", kv->val->type);
                    return YAML_FAILURE;
                }
            }
            // if (cfl_kvlist_count(s->cf_section->properties) != cfl_kvlist_count(s->keyvals)) {
            //    flb_error("wrong property count for new section");
            //    return YAML_FAILURE;
            // }
            s = state_pop(ctx);
            break;
        case YAML_SEQUENCE_START_EVENT: /* start a new group */
            if (strcmp(s->key, "processors") == 0) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            if (s->key == NULL) {
                flb_error("no key");
                return YAML_FAILURE;
            }
            state_push_witharr(ctx, s, STATE_PLUGIN_VAL_LIST);
            break;
        case YAML_SEQUENCE_END_EVENT:
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* Here is where we process all the plugin properties for customs, pipelines
             * and processors.
             */
            s = state_push_key(ctx, STATE_PLUGIN_VAL, (char *) event->data.scalar.value);
            break;
        case YAML_MAPPING_START_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_PLUGIN_START) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
            if (s->state != STATE_PLUGIN_START) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* register key/value pair as a property */
            cfl_kvlist_insert_string(s->keyvals, s->key, (char *)event->data.scalar.value);
            s = state_pop(ctx);
            break;
        case YAML_SEQUENCE_START_EVENT: /* start a new group */
            s = state_push_witharr(ctx, s, STATE_PLUGIN_VAL_LIST);
            break;
        case YAML_MAPPING_START_EVENT:
            struct parser_state *g;
            /* Special handling for input processor */
            if (strcmp(s->key, "processors") == 0) {
                s = state_push(ctx, STATE_INPUT_PROCESSORS);
                state_create_group(cf, s, "processors");
                break;
            }

            g = state_push(ctx, STATE_GROUP_KEY);
            /* create group */
            s->values = flb_cf_section_property_add_list(cf,
                                                         s->cf_section->properties,
                                                         s->key, flb_sds_len(s->key));
            if (s->values == NULL) {
                flb_error("no values");
                return YAML_FAILURE;
            }
            g->cf_group = flb_cf_group_create(cf, s->cf_section, s->key, strlen(s->key));
            break;
        case YAML_SEQUENCE_END_EVENT:   /* end of group */
            s = state_pop(ctx);
            if (s->state != STATE_PLUGIN_KEY) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            s = state_pop(ctx);
            if (s->state != STATE_PLUGIN_KEY) {
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            s = state_pop(ctx);
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
                flb_error("unable to add values to list");
                return YAML_FAILURE;
            }
            cfl_array_append_string(s->values, (char *)event->data.scalar.value);
            break;
        case YAML_SEQUENCE_END_EVENT:
            /* register key/value pair as a property */
            cfl_kvlist_insert_array(s->keyvals, s->key, s->values);
            s = state_pop(ctx);
            s = state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_INPUT_PROCESSORS:
        switch(event->type) {
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:
                state_pop(ctx);
                // this is NO BUENO!
                state_pop(ctx);
                break;
            case YAML_SCALAR_EVENT:
                /* Check if we are entering a 'logs', 'metrics' or 'traces' section */
                value = (char *) event->data.scalar.value;
                if (strcasecmp(value, "logs") == 0) {
                    /* logs state */
                    s = state_push_key(ctx, STATE_INPUT_PROCESSOR, "logs");
                }
                else if (strcasecmp(value, "metrics") == 0) {
                    /* metrics state */
                    s = state_push_key(ctx, STATE_INPUT_PROCESSOR, "metrics");
                }
                else if (strcasecmp(value, "traces") == 0) {
                    /* metrics state */
                    s = state_push_key(ctx, STATE_INPUT_PROCESSOR, "traces");
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

    case STATE_INPUT_PROCESSOR:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:
                s = state_pop(ctx);
                break;
            case YAML_MAPPING_START_EVENT:
                s = state_push_withvals(ctx, s, STATE_PLUGIN_START);
                s->section = SECTION_PROCESSOR;
                break;
            case YAML_MAPPING_END_EVENT:
                return YAML_FAILURE;
                break;
            default:
                yaml_error_event(ctx, s, event);
                return YAML_FAILURE;
        };
        break;

    /* groups: a group is a sub-section and here we handle the key/value pairs */
    case STATE_GROUP_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* next state */
            // s->state = STATE_GROUP_VAL;

            /* grab current value (key) */
            value = (char *) event->data.scalar.value;
            s = state_push_key(ctx, STATE_GROUP_VAL, value);
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            state_pop(ctx);
            // This is also the end of the plugin values mapping.
            // So we pop an additional state off the stack.
            state_pop(ctx);
            break;
        default:
            yaml_error_event(ctx, s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_GROUP_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            // s->state = STATE_GROUP_KEY;
            value = (char *) event->data.scalar.value;
            /* add the kv pair to the active group properties */
            flb_cf_section_property_add(cf, s->cf_group->properties,
                                        s->key, flb_sds_len(s->key),
                                        value, strlen(value));
            s = state_pop(ctx);
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

static void file_state_destroy(struct file_state *f)
{
    flb_sds_destroy(f->name);
    flb_sds_destroy(f->path);
    flb_free(f);
}

static struct parser_state *state_start(struct local_ctx *ctx, struct file_state *file)
{
    struct parser_state *s;

    s = state_create(NULL, file);
    cfl_list_add(&s->_head, &ctx->states);

    return s;
}

static struct parser_state *state_push(struct local_ctx *ctx, enum state state)
{
    struct parser_state *l = NULL;
    struct parser_state *s;

    if (cfl_list_size(&ctx->states) <= 0) {
        return NULL;
    }

    l = cfl_list_entry_last(&ctx->states, struct parser_state, _head);
    s = state_create(l->file, l->file);
    s->section = l->section;
    s->keyvals = l->keyvals;
    s->cf_section = l->cf_section;
    s->cf_group = l->cf_group;
    s->values = l->values;
    s->file = l->file;
    s->state = state;
    s->level = l->level + 1;
    s->key = l->key;

    cfl_list_add(&s->_head, &ctx->states);
    return s;
}

static struct parser_state *state_push_section(struct local_ctx *ctx,
                                               enum state state,
                                               enum section section)
{
    struct parser_state *s;

    s = state_push(ctx, state);
    s->section = section;

    return s;
}

static struct parser_state *state_push_key(struct local_ctx *ctx, enum state state,
                                           const char *key)
{
    struct parser_state *s = state_push(ctx, state);
    s->key = flb_sds_create(key);
    s->allocation_flags |= HAS_KEY;
    return s;
}

static struct parser_state *state_push_withvals(struct local_ctx *ctx,
                                                struct parser_state *parent,
                                                enum state state)
{
    struct parser_state *s;

    // if (parent->keyvals != NULL) {
    //    cfl_kvlist_destroy(parent->keyvals);
    // }
    s = state_push(ctx, state);
    s->keyvals = cfl_kvlist_create();
    s->allocation_flags |= HAS_KEYVALS;

    return s;
}

static struct parser_state *state_push_witharr(struct local_ctx *ctx,
                                               struct parser_state *parent,
                                               enum state state)
{
    struct parser_state *s;

    parent->values = cfl_array_create(4);
    if (parent->values == NULL) {
        flb_error("no value");
        return YAML_FAILURE;
    }
    cfl_array_resizable(parent->values, CFL_TRUE);

    s = state_push(ctx, state);

    return s;
}

static int state_create_section(struct flb_cf *cf, struct parser_state *s, char *name)
{
    s->cf_section = flb_cf_section_create(cf, name, 0);
    return 0;
}

static int state_create_group(struct flb_cf *cf, struct parser_state *s, char *name)
{
    s->cf_group = flb_cf_group_create(cf, s->cf_section,
                                    "processors", strlen("processors"));
    if (s->cf_group == NULL) {
        flb_error("unable to create new processors section group");
        return YAML_FAILURE;
    }
    return YAML_SUCCESS;
}

static struct parser_state *state_pop(struct local_ctx *ctx)
{
    struct parser_state *last;

    if (cfl_list_is_empty(&ctx->states)) {
        return NULL;
    }
    last = cfl_list_entry_last(&ctx->states, struct parser_state, _head);
    cfl_list_del(&last->_head);

    if (last->allocation_flags & HAS_KEY) {
        flb_sds_destroy(last->key);
    }
    if (last->allocation_flags & HAS_KEYVALS) {
        cfl_kvlist_destroy(last->keyvals);
    }
    state_destroy(last);

    if (cfl_list_is_empty(&ctx->states)) {
        return NULL;
    }
    return cfl_list_entry_last(&ctx->states, struct parser_state, _head);
}

static void state_destroy(struct parser_state *s)
{
    //if (s->file) {
    //    file_state_destroy(s->file);
    //}
    flb_free(s);
}

static struct parser_state *state_create(struct file_state *parent, struct file_state *file)
{
    int ret;
    char *p;
    struct parser_state *s;

    /* allocate context */
    s = flb_calloc(1, sizeof(struct parser_state));
    if (!s) {
        flb_errno();
        return NULL;
    }

    s->file = file;
#ifndef FLB_HAVE_STATIC_CONF
    if (parent) {
       s->file->parent = parent;
    }

    /* resolve real path for caller file and target file */
    /* check if the file exists */
    /*
    ret = stat(file, &st);
    if (ret == 0) {
        p = get_real_path(file, file_path, PATH_MAX + 1);
        s->file->name = flb_sds_create(file);
        s->file->path = flb_sds_create(file_path);
    }
    else if (errno == ENOENT && parent && parent->path != NULL) {
        snprintf(file_path, PATH_MAX, "%s/%s", parent->path, file);
        s->file->name = flb_sds_create(file_path);
        s->file->path = flb_sds_create(parent->path);
    }
    */
#else
    s->file->name = flb_sds_create("***static***");
    s->file->path = flb_sds_create("***static***");
#endif

    return s;
}

static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       struct file_state *parent, char *cfg_file)
{
    int ret;
    int status;
    int code = 0;
    struct parser_state *state;
    flb_sds_t file = NULL;
    flb_sds_t include_file = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    FILE *fh;
    struct file_state f;

    if (parent && cfg_file[0] != '/') {
        file = flb_sds_create_size(strlen(cfg_file) + strlen(parent->path));
        if (file == NULL) {
            flb_error("unable to create filename");
            return -1;
        }
        flb_sds_printf(&file, "%s/%s", parent->path, cfg_file);
    } else {
        file = flb_sds_create(cfg_file);
    }

    include_file = flb_sds_create(file);
    f.name = basename(file);
    f.path = dirname(file);

    f.parent = parent;

    state = state_start(ctx, &f);
    if (!state) {
        flb_error("unable to push initial include file state: %s", cfg_file);
        return -1;
    }

    /* check if this file has been included before */
    ret = is_file_included(ctx, include_file);
    if (ret) {
        flb_error("[config] file '%s' is already included", cfg_file);
        state_destroy(state);
        return -1;
    }

    flb_debug("============ %s ============", cfg_file);
    fh = fopen(include_file, "r");
    if (!fh) {
        flb_errno();
        state_destroy(state);
        return -1;
    }

    /* add file to the list of included files */
    ret = flb_slist_add(&ctx->includes, include_file);
    if (ret == -1) {
        flb_error("[config] could not register file %s", cfg_file);
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
            flb_error("[config] invalid YAML format in file %s", cfg_file);
            code = -1;
            goto done;
        }
        status = consume_event(cf, ctx, &event);
        if (status == YAML_FAILURE) {
            flb_error("yaml error");
            code = -1;
            goto done;
        }
        yaml_event_delete(&event);
        state = cfl_list_entry_last(&ctx->states, struct parser_state, _head);
    } while (state->state != STATE_STOP);

    flb_debug("==============================");
done:
    if (code == -1) {
        yaml_event_delete(&event);
    }

    yaml_parser_delete(&parser);
    // state_destroy(state);
    state_pop(ctx);

    fclose(fh);
    ctx->level--;

    flb_sds_destroy(include_file);
    flb_sds_destroy(file);

    return code;
}

static int local_init(struct local_ctx *ctx)
{
    /* reset the state */
    memset(ctx, '\0', sizeof(struct local_ctx));
    cfl_list_init(&ctx->states);
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
    ret = local_init(&ctx);
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
