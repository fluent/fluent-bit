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

struct file_state {
    /* file */
    flb_sds_t name;                /* file name */
    flb_sds_t path;           /* file root path */

    /* parent file state */
    struct file_state *parent;
};

struct local_ctx {
    int level;                     /* inclusion level */

    struct cfl_list states;

    struct mk_list includes;

    int service_set;
};

/* yaml_* functions return 1 on success and 0 on failure. */
enum status {
    YAML_SUCCESS = 1,
    YAML_FAILURE = 0
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

/* parser state allocation flags */
#define HAS_KEY     (1 << 0)
#define HAS_KEYVALS (1 << 1)

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


static int read_config(struct flb_cf *cf, struct local_ctx *ctx,
                       struct file_state *parent, char *cfg_file);

static char *state_str(enum state val)
{
    switch (val) {
    case STATE_START:
        return "start";
    case STATE_STREAM:
        return "stream";
    case STATE_DOCUMENT:
        return "document";
    case STATE_SECTION:
        return "section";
    case STATE_SECTION_KEY:
        return "section-key";
    case STATE_SECTION_VAL:
        return "section-value";
    case STATE_SERVICE:
        return "service";
    case STATE_INCLUDE:
        return "include";
    case STATE_OTHER:
        return "other";
    case STATE_CUSTOM:
        return "custom";
    case STATE_PIPELINE:
        return "pipeline";
    case STATE_PLUGIN_INPUT:
        return "input";
    case STATE_PLUGIN_FILTER:
        return "filter";
    case STATE_PLUGIN_OUTPUT:
        return "output";
    case STATE_PLUGIN_START:
        return "plugin-start";
    case STATE_PLUGIN_KEY:
        return "plugin-key";
    case STATE_PLUGIN_VAL:
        return "plugin-value";
    case STATE_PLUGIN_VAL_LIST:
        return "plugin-values";
    case STATE_GROUP_KEY:
        return "group-key";
    case STATE_GROUP_VAL:
        return "group-val";
    case STATE_INPUT_PROCESSORS:
        return "processors";
    case STATE_INPUT_PROCESSOR:
        return "processor";
    case STATE_ENV:
        return "env";
    case STATE_STOP:
        return "stop";
    default:
        return "unknown";
    }
}

static int add_section_type(struct flb_cf *conf, struct parser_state *state)
{
    if (conf == NULL || state == NULL) {
        return -1;
    }

    if (state->section == SECTION_INPUT) {
        state->cf_section = flb_cf_section_create(conf, "INPUT", 0);
    }
    else if (state->section == SECTION_FILTER) {
        state->cf_section = flb_cf_section_create(conf, "FILTER", 0);
    }
    else if (state->section == SECTION_OUTPUT) {
        state->cf_section = flb_cf_section_create(conf, "OUTPUT", 0);
    }
    else if (state->section == SECTION_CUSTOM) {
        state->cf_section = flb_cf_section_create(conf, "customs", 0);
    }

    if (!state->cf_section) {
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

static char *state_get_last(struct local_ctx *ctx)
{
    struct flb_slist_entry *entry;

    entry = mk_list_entry_last(&ctx->includes, struct flb_slist_entry, _head);

    if (entry == NULL) {
        return NULL;
    }
    return entry->str;
}

static void yaml_error_event(struct local_ctx *ctx, struct parser_state *state,
                             yaml_event_t *event)
{
    struct flb_slist_entry *entry;

    if (event == NULL) {
        flb_error("[config] YAML error found but with no state or event");
        return;
    }

    if (state == NULL) {
        flb_error("[config] YAML error found but with no state, line %zu, column %zu: "
                  "unexpected event '%s' (%d).",
                  event->start_mark.line + 1, event->start_mark.column,
                  event_type_str(event), event->type);
        return;
    }

    entry = mk_list_entry_last(&ctx->includes, struct flb_slist_entry, _head);

    if (entry == NULL) {
        flb_error("[config] YAML error found (no file info), line %zu, column %zu: "
                  "unexpected event '%s' (%d) in state '%s' (%d).",
                  event->start_mark.line + 1, event->start_mark.column,
                  event_type_str(event), event->type, state_str(state->state), state->state);
        return;
    }

    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "unexpected event '%s' (%d) in state '%s' (%d).",
              entry->str, event->start_mark.line + 1, event->start_mark.column,
              event_type_str(event), event->type, state_str(state->state), state->state);
}

static void yaml_error_definition(struct local_ctx *ctx, struct parser_state *state,
                                  yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "duplicated definition of '%s'",
              state->file->name, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static void yaml_error_plugin_category(struct local_ctx *ctx, struct parser_state *state,
                                       yaml_event_t *event, char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %zu, column %zu: "
              "the pipeline component '%s' is not valid. Try one of these values: "
              "customs, inputs, filters or outputs.",
              state->file->name, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static int is_file_included(struct local_ctx *ctx, const char *path)
{
    struct mk_list *head;
    struct flb_slist_entry *entry;

    mk_list_foreach(head, &ctx->includes) {
        entry = mk_list_entry(head, struct flb_slist_entry, _head);

        if (strcmp(entry->str, path) == 0) {
            return FLB_TRUE;
        }
    }

    return FLB_FALSE;
}

#ifndef _WIN32
static int read_glob(struct flb_cf *conf, struct local_ctx *ctx,
                     struct parser_state *state, const char *path)
{
    int ret = -1;
    glob_t glb;
    char tmp[PATH_MAX+1];

    const char *glb_path;
    size_t idx;
    int ret_glb = -1;

    if (state->file->path && path[0] != '/') {
        ret = snprintf(tmp, PATH_MAX, "%s/%s", state->file->path, path);

        if (ret > PATH_MAX) {
            return -1;
        }
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

    for (idx = 0; idx < glb.gl_pathc; idx++) {
        ret = read_config(conf, ctx, state->file, glb.gl_pathv[idx]);

        if (ret < 0) {
            break;
        }
    }

    globfree(&glb);
    return ret;
}
#else
static char *dirname(char *path)
{
    char *ptr;


    ptr = strrchr(path, '\\');

    if (ptr == NULL) {
        return path;
    }
    *ptr++='\0';
    return path;
}

static int read_glob(struct flb_cf *conf, struct local_ctx *ctx,
                     struct parser_state *state, const char *path)
{
    char *star, *p0, *p1;
    char pattern[MAX_PATH];
    char buf[MAX_PATH];
    int ret;
    struct stat st;
    HANDLE hnd;
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

    hnd = FindFirstFileA(pattern, &data);

    if (hnd == INVALID_HANDLE_VALUE) {
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
            read_glob(conf, ctx, state, buf); /* recursive */
            continue;
        }

        ret = stat(buf, &st);

        if (ret == 0 && (st.st_mode & S_IFMT) == S_IFREG) {

            if (read_config(conf, ctx, state, buf) < 0) {
                return -1;
            }
        }
    } while (FindNextFileA(hnd, &data) != 0);

    FindClose(hnd);
    return 0;
}
#endif

static void print_current_state(struct local_ctx *ctx, struct parser_state *state,
                                yaml_event_t *event)
{
    flb_debug("%*s%s->%s", state->level*2, "", state_str(state->state),
             event_type_str(event));
}

static void print_current_properties(struct parser_state *state)
{
    struct cfl_list *head;
    struct cfl_kvpair *prop;
    struct cfl_variant *var;
    int idx;

    flb_debug("%*s[%s] PROPERTIES:", state->level*2, "", section_names[state->section]);

    cfl_list_foreach(head, &state->keyvals->list) {
        prop = cfl_list_entry(head, struct cfl_kvpair, _head);
        switch (prop->val->type) {
        case CFL_VARIANT_STRING:
            flb_debug("%*s%s: %s", (state->level+2)*2, "", prop->key, prop->val->data.as_string);
            break;
        case CFL_VARIANT_ARRAY:
            flb_debug("%*s%s: [", (state->level+2)*2, "", prop->key);
            for (idx = 0; idx < prop->val->data.as_array->entry_count; idx++) {
                var = cfl_array_fetch_by_index(prop->val->data.as_array, idx);
                flb_debug("%*s%s", (state->level+3)*2, "", var->data.as_string);
            }
            flb_debug("%*s]", (state->level+2)*2, "");
            break;
        }
    }
}

static struct parser_state *get_current_state(struct local_ctx *ctx)
{
    struct parser_state *state;

    if (cfl_list_size(&ctx->states) <= 0) {
        return NULL;
    }
    state = cfl_list_entry_last(&ctx->states, struct parser_state, _head);
    return state;
}

static enum status state_copy_into_config_group(struct parser_state *state, struct flb_cf_group *cf_group)
{
    struct cfl_list *head;
    struct cfl_kvpair *kvp;
    struct cfl_variant *var;
    struct cfl_variant *varr;
    struct cfl_array *arr;
    struct cfl_array *carr;
    struct cfl_kvlist *copy;
    int idx;

    if (cf_group == NULL) {
        flb_error("no group for processor properties");
        return YAML_FAILURE;
    }

    varr = cfl_kvlist_fetch(cf_group->properties, state->key);

    if (varr == NULL) {
        arr = cfl_array_create(1);

        if (arr == NULL) {
            flb_error("unable to allocate array");
            return YAML_FAILURE;
        }

        cfl_array_resizable(arr, CFL_TRUE);

        if (cfl_kvlist_insert_array(cf_group->properties, state->key, arr) < 0) {
            cfl_array_destroy(arr);
            flb_error("unable to insert into array");
            return YAML_FAILURE;
        }
    }
    else {
        arr = varr->data.as_array;
    }

    copy = cfl_kvlist_create();

    if (copy == NULL) {
        cfl_array_destroy(arr);
        flb_error("unable to allocate kvlist");
        return YAML_FAILURE;
    }

    cfl_list_foreach(head, &state->keyvals->list) {
        kvp = cfl_list_entry(head, struct cfl_kvpair, _head);
        switch (kvp->val->type) {
        case CFL_VARIANT_STRING:

            if (cfl_kvlist_insert_string(copy, kvp->key, kvp->val->data.as_string) < 0) {
                flb_error("unable to allocate kvlist");
                cfl_kvlist_destroy(copy);
                return YAML_FAILURE;
            }
            break;
        case CFL_VARIANT_ARRAY:
            carr = cfl_array_create(kvp->val->data.as_array->entry_count);

            if (carr == NULL) {
                flb_error("unable to allocate array");
                cfl_kvlist_destroy(copy);
                return YAML_FAILURE;
            }

            for (idx = 0; idx < kvp->val->data.as_array->entry_count; idx++) {
                var = cfl_array_fetch_by_index(kvp->val->data.as_array, idx);

                if (var == NULL) {
                    cfl_array_destroy(arr);
                    flb_error("unable to fetch from array by index");
                    return YAML_FAILURE;
                }
                switch (var->type) {
                case CFL_VARIANT_STRING:

                    if (cfl_array_append_string(carr, var->data.as_string) < 0) {
                        flb_error("unable to append string");
                        cfl_kvlist_destroy(copy);
                        cfl_array_destroy(carr);
                        return YAML_FAILURE;
                    }
                    break;
                default:
                    cfl_array_destroy(arr);
                    flb_error("unable to copy value for property");
                    cfl_kvlist_destroy(copy);
                    cfl_array_destroy(carr);
                    return YAML_FAILURE;
                }
            }

            if (cfl_kvlist_insert_array(copy, kvp->key, carr) < 0) {
                cfl_array_destroy(arr);
                flb_error("unabelt to insert into array");
                flb_error("unable to insert array into kvlist");
            }
            break;
        default:
            flb_error("unknown value type for properties: %d", kvp->val->type);
            cfl_kvlist_destroy(copy);
            return YAML_FAILURE;
        }
    }

    if (cfl_array_append_kvlist(arr, copy) < 0) {
        flb_error("unable to insert array into kvlist");
        cfl_kvlist_destroy(copy);
        return YAML_FAILURE;
    }
    return YAML_SUCCESS;
}

static enum status state_copy_into_properties(struct parser_state *state, struct flb_cf *conf, struct cfl_kvlist *properties)
{
    struct cfl_list *head;
    struct cfl_kvpair *kvp;
    struct cfl_variant *var;
    struct cfl_array *arr;
    int idx;

    cfl_list_foreach(head, &state->keyvals->list) {
        kvp = cfl_list_entry(head, struct cfl_kvpair, _head);
        switch (kvp->val->type) {
        case CFL_VARIANT_STRING:
            var = flb_cf_section_property_add(conf,
                                            properties,
                                            kvp->key,
                                            cfl_sds_len(kvp->key),
                                            kvp->val->data.as_string,
                                            cfl_sds_len(kvp->val->data.as_string));

            if (var == NULL) {
                flb_error("unable to add variant value property");
                return YAML_FAILURE;
            }
            break;
        case CFL_VARIANT_ARRAY:
            arr = flb_cf_section_property_add_list(conf, properties,
                                                    kvp->key, cfl_sds_len(kvp->key));

            if (arr == NULL) {
                flb_error("unable to add property list");
                return YAML_FAILURE;
            }
            for (idx = 0; idx < kvp->val->data.as_array->entry_count; idx++) {
                var = cfl_array_fetch_by_index(kvp->val->data.as_array, idx);

                if (var == NULL) {
                    flb_error("unable to retrieve from array by index");
                    return YAML_FAILURE;
                }
                switch (var->type) {
                case CFL_VARIANT_STRING:

                    if (cfl_array_append_string(arr, var->data.as_string) < 0) {
                        flb_error("unable to append string to array");
                        return YAML_FAILURE;
                    }
                    break;
                default:
                    flb_error("unable to copy value for property");
                    return YAML_FAILURE;
                }
            }
            break;
        default:
            flb_error("unknown value type for properties: %d", kvp->val->type);
            return YAML_FAILURE;
        }
    }
    return YAML_SUCCESS;
}

static int consume_event(struct flb_cf *conf, struct local_ctx *ctx,
                         yaml_event_t *event)
{
    struct parser_state *state;
    enum status status;
    int ret;
    char *value;
    struct flb_kv *keyval;
    char *last_included;

    last_included = state_get_last(ctx);

    if (last_included == NULL) {
        last_included = "**unknown**";
    }

    state = get_current_state(ctx);

    if (state == NULL) {
        flb_error("unable to parse yaml: no state");
        return YAML_FAILURE;
    }
    print_current_state(ctx, state, event);

    switch (state->state) {
    case STATE_START:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            state = state_push(ctx, STATE_STREAM);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_NO_EVENT:
            state->state = STATE_STOP;
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_STREAM:
        switch (event->type) {
        case YAML_DOCUMENT_START_EVENT:
            state = state_push(ctx, STATE_DOCUMENT);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_STREAM_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

     case STATE_DOCUMENT:
        switch (event->type) {
        case YAML_MAPPING_START_EVENT:
            state = state_push(ctx, STATE_SECTION);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_DOCUMENT_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
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
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_SECTION) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;
            flb_debug("[config yaml] including: %s", value);

            if (strchr(value, '*') != NULL) {
                ret = read_glob(conf, ctx, state, value);
            }
            else {
                ret = read_config(conf, ctx, state->file, value);
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
            yaml_error_event(ctx, state, event);
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
            state = state_push_withvals(ctx, state, STATE_PLUGIN_START);
            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            if (add_section_type(conf, state) == -1) {
                flb_error("unable to add section type");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;
    /* end of 'customs' */

    case STATE_PIPELINE:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;

            if (strcasecmp(value, "inputs") == 0) {
                state = state_push_section(ctx, STATE_PLUGIN_INPUT, SECTION_INPUT);
            }
            else if (strcasecmp(value, "filters") == 0) {
                state = state_push_section(ctx, STATE_PLUGIN_FILTER, SECTION_FILTER);
            }
            else if (strcasecmp(value, "outputs") == 0) {
                state = state_push_section(ctx, STATE_PLUGIN_OUTPUT, SECTION_OUTPUT);
            }
            else {
                yaml_error_plugin_category(ctx, state, event, value);
                return YAML_FAILURE;
            }

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;

            if (strcasecmp(value, "env") == 0) {
                state = state_push_section(ctx, STATE_ENV, SECTION_ENV);
                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
            }
            else if (strcasecmp(value, "pipeline") == 0) {
                state = state_push_section(ctx, STATE_PIPELINE, SECTION_PIPELINE);
                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
            }
            else if (strcasecmp(value, "service") == 0) {

                if (ctx->service_set) {
                    yaml_error_definition(ctx, state, event, value);
                    return YAML_FAILURE;
                }

                state = state_push_section(ctx, STATE_SERVICE, SECTION_SERVICE);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }

                if (state_create_section(conf, state, value) == -1) {
                    flb_error("unable to allocate section: %s", value);
                    return YAML_FAILURE;
                }
                ctx->service_set = 1;
            }
            else if (strcasecmp(value, "customs") == 0) {
                state = state_push_section(ctx, STATE_CUSTOM, SECTION_CUSTOM);

            if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
            }
            else if (strcasecmp(value, "includes") == 0) {
                state = state_push_section(ctx, STATE_INCLUDE, SECTION_INCLUDE);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
            }
            else {
                /* any other main section definition (e.g: similar to STATE_SERVICE) */
                state = state_push(ctx, STATE_OTHER);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }

                if (state_create_section(conf, state, value) == -1) {
                    flb_error("unable to allocate section: %s", value);
                    return YAML_FAILURE;
                }
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        case YAML_DOCUMENT_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    /* service or others */
    case STATE_ENV:
    case STATE_SERVICE:
    case STATE_OTHER:
        switch(event->type) {
        case YAML_MAPPING_START_EVENT:
            state = state_push(ctx, STATE_SECTION_KEY);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_SECTION) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;
            state = state_push_key(ctx, STATE_SECTION_VAL, value);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);
            switch (state->state) {
            case STATE_SERVICE:
            case STATE_ENV:
            case STATE_OTHER:
                break;
            default:
                printf("BAD STATE FOR SECTION KEY POP=%s\n", state_str(state->state));
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_SECTION_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;

            /* Check if the incoming k/v pair set a config environment variable */
            if (state->section == SECTION_ENV) {
                keyval = flb_cf_env_property_add(conf,
                                                 state->key, flb_sds_len(state->key),
                                                 value, strlen(value));

                if (keyval == NULL) {
                    flb_error("unable to add key value");
                    return YAML_FAILURE;
                }
            }
            else {

                /* register key/value pair as a property */
                if (state->cf_section == NULL) {
                    flb_error("no section to register key value to");
                    return YAML_FAILURE;
                }

                if (flb_cf_section_property_add(conf, state->cf_section->properties,
                                                state->key, flb_sds_len(state->key),
                                                value, strlen(value)) < 0) {
                    flb_error("unable to add property");
                    return YAML_FAILURE;
                }
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_SECTION_KEY) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
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
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            state = state_push_withvals(ctx, state, STATE_PLUGIN_START);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }

            if (add_section_type(conf, state) == -1) {
                flb_error("unable to add section type");
                return YAML_FAILURE;
            }
            break;
        case YAML_SCALAR_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_SECTION) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_SECTION_KEY) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_START:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* Here is where we process all the plugin properties for customs, pipelines
             * and processors.
             */
            state = state_push_key(ctx, STATE_PLUGIN_VAL, (char *) event->data.scalar.value);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            print_current_properties(state);

            if (state->section == SECTION_PROCESSOR) {
                status = state_copy_into_config_group(state, state->cf_group);

                if (status != YAML_SUCCESS) {
                    return status;
                }
            }
            else {
                status = state_copy_into_properties(state, conf, state->cf_section->properties);

                if (status != YAML_SUCCESS) {
                    return status;
                }
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_START_EVENT: /* start a new group */

            if (state->key == NULL) {
                flb_error("no key");
                return YAML_FAILURE;
            }

            if (strcmp(state->key, "processors") == 0) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }

            state = state_push_witharr(ctx, state, STATE_PLUGIN_VAL_LIST);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* Here is where we process all the plugin properties for customs, pipelines
             * and processors.
             */
            state = state_push_key(ctx, STATE_PLUGIN_VAL, (char *) event->data.scalar.value);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_PLUGIN_START) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_PLUGIN_START) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:

            /* register key/value pair as a property */
            if (cfl_kvlist_insert_string(state->keyvals, state->key, (char *)event->data.scalar.value) < 0) {
                flb_error("unable to insert string");
                return YAML_FAILURE;
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_START_EVENT: /* start a new group */
            state = state_push_witharr(ctx, state, STATE_PLUGIN_VAL_LIST);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:

            if (strcmp(state->key, "processors") == 0) {
                state = state_push(ctx, STATE_INPUT_PROCESSORS);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }

                if (state_create_group(conf, state, "processors") == YAML_FAILURE) {
                    return YAML_FAILURE;
                }
                break;
            }

            state = state_push(ctx, STATE_GROUP_KEY);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            /* create group */
            state->values = flb_cf_section_property_add_list(conf,
                                                             state->cf_section->properties,
                                                             state->key, flb_sds_len(state->key));

            if (state->values == NULL) {
                flb_error("no values");
                return YAML_FAILURE;
            }

            state->cf_group = flb_cf_group_create(conf, state->cf_section, state->key, strlen(state->key));

            if (state->cf_group == NULL) {
                flb_error("unable to create group");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:   /* end of group */
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_PLUGIN_KEY) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            if (state->state != STATE_PLUGIN_KEY) {
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_END_EVENT:
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_VAL_LIST:
        switch(event->type) {
        case YAML_SCALAR_EVENT:

            if (state->values == NULL) {
                flb_error("unable to add values to list");
                return YAML_FAILURE;
            }

            if (cfl_array_append_string(state->values, (char *)event->data.scalar.value) < 0) {
                flb_error("unable to add values to list");
                return YAML_FAILURE;
            }
            break;
        case YAML_SEQUENCE_END_EVENT:

            /* register key/value pair as a property */
            if (cfl_kvlist_insert_array(state->keyvals, state->key, state->values) < 0) {
                flb_error("unable to insert key values");
                return YAML_FAILURE;
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_INPUT_PROCESSORS:
        switch(event->type) {
            case YAML_MAPPING_START_EVENT:
                break;
            case YAML_MAPPING_END_EVENT:

                state = state_pop(ctx);

                if (state == NULL) {
                    flb_error("no state left");
                    return YAML_FAILURE;
                }

                state = state_pop(ctx);

                if (state == NULL) {
                    flb_error("no state left");
                    return YAML_FAILURE;
                }
                break;
            case YAML_SCALAR_EVENT:

                /* Check if we are entering a 'logs', 'metrics' or 'traces' section */
                value = (char *) event->data.scalar.value;

                if (strcasecmp(value, "logs") == 0) {
                    /* logs state */
                    state = state_push_key(ctx, STATE_INPUT_PROCESSOR, "logs");
                }
                else if (strcasecmp(value, "metrics") == 0) {
                    /* metrics state */
                    state = state_push_key(ctx, STATE_INPUT_PROCESSOR, "metrics");
                }
                else if (strcasecmp(value, "traces") == 0) {
                    /* metrics state */
                    state = state_push_key(ctx, STATE_INPUT_PROCESSOR, "traces");
                }
                else {
                    flb_error("[config] unknown processor '%s'", value);
                    yaml_error_event(ctx, state, event);
                    return YAML_FAILURE;
                }

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
                break;
            default:
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
        };
        break;

    case STATE_INPUT_PROCESSOR:
        switch(event->type) {
            case YAML_SEQUENCE_START_EVENT:
                break;
            case YAML_SEQUENCE_END_EVENT:

                state = state_pop(ctx);

                if (state == NULL) {
                    flb_error("no state left");
                    return YAML_FAILURE;
                }
                break;
            case YAML_MAPPING_START_EVENT:

                state = state_push_withvals(ctx, state, STATE_PLUGIN_START);

                if (state == NULL) {
                    flb_error("unable to allocate state");
                    return YAML_FAILURE;
                }
                state->section = SECTION_PROCESSOR;
                break;
            case YAML_MAPPING_END_EVENT:
                return YAML_FAILURE;
                break;
            default:
                yaml_error_event(ctx, state, event);
                return YAML_FAILURE;
        };
        break;

    /* groups: a group is a sub-section and here we handle the key/value pairs. */
    case STATE_GROUP_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            /* grab current value (key) */
            value = (char *) event->data.scalar.value;

            state = state_push_key(ctx, STATE_GROUP_VAL, value);

            if (state == NULL) {
                flb_error("unable to allocate state");
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }

            /* This is also the end of the plugin values mapping.
             * So we pop an additional state off the stack.
             */
            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_GROUP_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *) event->data.scalar.value;

            /* add the kv pair to the active group properties */
            if (flb_cf_section_property_add(conf, state->cf_group->properties,
                                            state->key, flb_sds_len(state->key),
                                            value, strlen(value)) == NULL) {
                flb_error("unable to add property");
                return YAML_FAILURE;
            }

            state = state_pop(ctx);

            if (state == NULL) {
                flb_error("no state left");
                return YAML_FAILURE;
            }
            break;
        default:
            yaml_error_event(ctx, state, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_STOP:
        break;
    }

    return YAML_SUCCESS;
}

static struct parser_state *state_start(struct local_ctx *ctx, struct file_state *file)
{
    struct parser_state *state;

    state = state_create(NULL, file);

    if (state != NULL) {
        cfl_list_add(&state->_head, &ctx->states);
    }

    return state;
}

static struct parser_state *state_push(struct local_ctx *ctx, enum state state_num)
{
    struct parser_state *last = NULL;
    struct parser_state *state;

    if (cfl_list_size(&ctx->states) <= 0) {
        return NULL;
    }

    last = cfl_list_entry_last(&ctx->states, struct parser_state, _head);

    if (last == NULL) {
        return NULL;
    }

    state = state_create(last->file, last->file);

    if (state == NULL) {
        return NULL;
    }
    state->section = last->section;
    state->keyvals = last->keyvals;
    state->cf_section = last->cf_section;
    state->cf_group = last->cf_group;
    state->values = last->values;
    state->file = last->file;
    state->state = state_num;
    state->level = last->level + 1;
    state->key = last->key;

    cfl_list_add(&state->_head, &ctx->states);
    return state;
}

static struct parser_state *state_push_section(struct local_ctx *ctx,
                                               enum state state_num,
                                               enum section section)
{
    struct parser_state *state;

    state = state_push(ctx, state_num);

    if (state == NULL) {
        return NULL;
    }
    state->section = section;

    return state;
}

static struct parser_state *state_push_key(struct local_ctx *ctx,
                                           enum state state_num,
                                           const char *key)
{
    struct parser_state *state;
    flb_sds_t skey;

    if (key == NULL) {
        return NULL;
    }

    skey = flb_sds_create(key);

    if (skey == NULL) {
        return NULL;
    }

    state = state_push(ctx, state_num);

    if (state == NULL) {
        flb_sds_destroy(skey);
        return NULL;
    }

    state->key = skey;
    state->allocation_flags |= HAS_KEY;
    return state;
}

static struct parser_state *state_push_withvals(struct local_ctx *ctx,
                                                struct parser_state *parent,
                                                enum state state_num)
{
    struct parser_state *state;
    struct cfl_kvlist *kvlist;

    kvlist = cfl_kvlist_create();

    if (kvlist == NULL) {
        return NULL;
    }

    state = state_push(ctx, state_num);

    if (state == NULL) {
        cfl_kvlist_destroy(kvlist);
        return NULL;
    }

    state->keyvals = kvlist;
    state->allocation_flags |= HAS_KEYVALS;

    return state;
}

static struct parser_state *state_push_witharr(struct local_ctx *ctx,
                                               struct parser_state *parent,
                                               enum state state_num)
{
    struct parser_state *state;

    parent->values = cfl_array_create(4);

    if (parent->values == NULL) {
        flb_error("parent has no values");
        return NULL;
    }

    cfl_array_resizable(parent->values, CFL_TRUE);

    state = state_push(ctx, state_num);

    return state;
}

static int state_create_section(struct flb_cf *conf, struct parser_state *state, char *name)
{

    if (state == NULL || conf == NULL || name == NULL) {
        return -1;
    }

    state->cf_section = flb_cf_section_create(conf, name, 0);

    if (state->cf_section == NULL) {
        return -1;
    }

    return 0;
}

static int state_create_group(struct flb_cf *conf, struct parser_state *state, char *name)
{
    if (state == NULL || conf == NULL || name == NULL) {
        return -1;
    }

    state->cf_group = flb_cf_group_create(conf, state->cf_section,
                                          "processors", strlen("processors"));

    if (state->cf_group == NULL) {
        return -1;
    }

    return YAML_SUCCESS;
}

static struct parser_state *state_pop(struct local_ctx *ctx)
{
    struct parser_state *last;

    if (ctx == NULL) {
        return NULL;
    }

    if (cfl_list_size(&ctx->states) <= 0) {
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

    if (cfl_list_size(&ctx->states) <= 0) {
        return NULL;
    }

    return cfl_list_entry_last(&ctx->states, struct parser_state, _head);
}

static void state_destroy(struct parser_state *s)
{
    flb_free(s);
}

static struct parser_state *state_create(struct file_state *parent, struct file_state *file)
{
    struct parser_state *state;

    /* allocate context */
    state = flb_calloc(1, sizeof(struct parser_state));

    if (!state) {
        flb_errno();
        return NULL;
    }

    state->file = file;
#ifndef FLB_HAVE_STATIC_CONF

    if (parent) {
       state->file->parent = parent;
    }

#else

    s->file->name = flb_sds_create("***static***");
    s->file->path = flb_sds_create("***static***");

#endif

    return state;
}

static int read_config(struct flb_cf *conf, struct local_ctx *ctx,
                       struct file_state *parent, char *cfg_file)
{
    int ret;
    int status;
    int code = 0;
    struct parser_state *state;
    flb_sds_t include_dir = NULL;
    flb_sds_t include_file = NULL;
    yaml_parser_t parser;
    yaml_event_t event;
    FILE *fh;
    struct file_state fstate;

    if (parent && cfg_file[0] != '/') {

        include_dir = flb_sds_create_size(strlen(cfg_file) + strlen(parent->path));

        if (include_dir == NULL) {
            flb_error("unable to create filename");
            return -1;
        }

        if (flb_sds_printf(&include_dir, "%s/%s", parent->path, cfg_file) == NULL) {
            flb_error("unable to create full filename");
            return -1;
        }

    }
    else {

        include_dir = flb_sds_create(cfg_file);

        if (include_dir == NULL) {
            flb_error("unable to create filename");
            return -1;
        }
    }

    include_file = flb_sds_create(include_dir);

    if (include_file == NULL) {
        flb_error("unable to create include filename");
        flb_sds_destroy(include_dir);
        return -1;
    }

    fstate.name = basename(include_dir);
    fstate.path = dirname(include_dir);

    fstate.parent = parent;

    state = state_start(ctx, &fstate);

    if (!state) {
        flb_error("unable to push initial include file state: %s", cfg_file);
        flb_sds_destroy(include_dir);
        flb_sds_destroy(include_file);
        return -1;
    }

    /* check if this file has been included before */
    ret = is_file_included(ctx, include_file);

    if (ret) {
        flb_error("[config] file '%s' is already included", cfg_file);
        flb_sds_destroy(include_dir);
        flb_sds_destroy(include_file);
        state_destroy(state);
        return -1;
    }

    flb_debug("============ %s ============", cfg_file);
    fh = fopen(include_file, "r");

    if (!fh) {
        flb_errno();
        flb_sds_destroy(include_dir);
        flb_sds_destroy(include_file);
        state_destroy(state);
        return -1;
    }

    /* add file to the list of included files */
    ret = flb_slist_add(&ctx->includes, include_file);

    if (ret == -1) {
        flb_error("[config] could not register file %s", cfg_file);
        fclose(fh);
        flb_sds_destroy(include_dir);
        flb_sds_destroy(include_file);
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

        status = consume_event(conf, ctx, &event);

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

    /* free all remaining states */
    if (code == -1) {
        while (state = state_pop(ctx));
    }
    else {
        state = state_pop(ctx);
    }

    fclose(fh);
    ctx->level--;

    flb_sds_destroy(include_file);
    flb_sds_destroy(include_dir);

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

struct flb_cf *flb_cf_yaml_create(struct flb_cf *conf, char *file_path,
                                  char *buf, size_t size)
{
    int ret;
    struct local_ctx ctx;

    if (!conf) {
        conf = flb_cf_create();
        if (!conf) {
            return NULL;
        }

        flb_cf_set_origin_format(conf, FLB_CF_YAML);
    }

    /* initialize the parser state */
    ret = local_init(&ctx);

    if (ret == -1) {
        flb_cf_destroy(conf);
        return NULL;
    }

    /* process the entry poing config file */
    ret = read_config(conf, &ctx, NULL, file_path);

    if (ret == -1) {
        flb_cf_destroy(conf);
        local_exit(&ctx);
        return NULL;
    }

    local_exit(&ctx);
    return conf;
}
