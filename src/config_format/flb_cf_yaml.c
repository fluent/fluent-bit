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
#include <monkey/mk_core.h>

#include <yaml.h>

enum section {
    SECTION_ENV,
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

    STATE_SERVICE,         /* service section */
    STATE_OTHER,           /* service section */

    STATE_PIPELINE,        /* pipeline groups customs inputs, filters and outputs */

    STATE_PLUGIN_INPUT,    /* input plugins section */
    STATE_PLUGIN_FILTER,   /* filter plugins section */
    STATE_PLUGIN_OUTPUT,   /* output plugins section */

    STATE_CUSTOM,                  /* custom plugins */
    STATE_CUSTOM_KEY_VALUE_PAIR,
    STATE_CUSTOM_KEY,
    STATE_CUSTOM_VAL,

    STATE_PLUGIN_TYPE,
    STATE_PLUGIN_KEY_VALUE_PAIR,
    STATE_PLUGIN_KEY,
    STATE_PLUGIN_VAL,

    STATE_GROUP_KEY,
    STATE_GROUP_VAL,

    /* environment variables */
    STATE_ENV,


    STATE_STOP            /* end state */
};

struct parser_state {
    /* file path */
    flb_sds_t file;

    /* tokens state */
    enum state state;

    /* active section (if any) */
    enum section section;

    /* temporary key value pair */
    flb_sds_t key;
    flb_sds_t val;

    /* active section */
    struct flb_cf_section *cf_section;

    /* active group */
    struct flb_cf_group *cf_group;

    int service_set;
};

/* yaml_* functions return 1 on success and 0 on failure. */
enum status {
    YAML_SUCCESS = 1,
    YAML_FAILURE = 0
};

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

static void yaml_error_event(struct parser_state *s, yaml_event_t *event)
{
    flb_error("[config] YAML error found in file \"%s\", line %i, column %i: "
              "unexpected event %d in state %d.",
              s->file, event->start_mark.line + 1, event->start_mark.column,
              event->type, s->state);
}

static void yaml_error_definition(struct parser_state *s, yaml_event_t *event,
                                  char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %i, column %i: "
              "duplicated definition of '%s'",
              s->file, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static void yaml_error_plugin_category(struct parser_state *s, yaml_event_t *event,
                                       char *value)
{
    flb_error("[config] YAML error found in file \"%s\", line %i, column %i: "
              "the pipeline component '%s' is not valid. Try one of these values: "
              "customs, inputs, filters or outputs.",
              s->file, event->start_mark.line + 1, event->start_mark.column,
              value);
}

static int consume_event(struct flb_cf *cf, struct parser_state *s,
                         yaml_event_t *event)
{
    int len;
    int ret;
    char *value;
    struct mk_list *list;
    struct flb_kv *kv;

    switch (s->state) {
    case STATE_START:
        switch (event->type) {
        case YAML_STREAM_START_EVENT:
            s->state = STATE_STREAM;
            break;
        default:
            yaml_error_event(s, event);
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
            yaml_error_event(s, event);
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
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    /*
     * 'customs'
     *  --------
     */
    case STATE_CUSTOM:
        switch (event->type) {
        case YAML_SCALAR_EVENT:
            value = (char *)event->data.scalar.value;
            len = strlen(value);
            if (len == 0) {
                yaml_error_event(s, event);
                return YAML_FAILURE;
            }

            /* create the 'customs' section */
            s->cf_section = flb_cf_section_create(cf, "customs", 0);
            if (!s->cf_section) {
                return YAML_FAILURE;
            }

            /* value is the 'custom plugin name', create a section instance */
            kv = flb_cf_property_add(cf, &s->cf_section->properties,
                                     "name", 4,
                                     value, len);
            if (!kv) {
                return YAML_FAILURE;
            }

            /* next state are key value pairs for the custom plugin*/
            s->state = STATE_CUSTOM_KEY_VALUE_PAIR;
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(s, event);
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
        default:
            yaml_error_event(s, event);
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
            s->state = STATE_CUSTOM;
            break;
        default:
            yaml_error_event(s, event);
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
            flb_cf_property_add(cf, &s->cf_section->properties,
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
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;
    /* end of 'customs' */

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
                yaml_error_plugin_category(s, event, value);
                return YAML_FAILURE;
            }
            break;
        case YAML_MAPPING_START_EVENT:
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(s, event);
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
                if (s->service_set) {
                    yaml_error_definition(s, event, value);
                    return YAML_FAILURE;
                }
                s->state = STATE_SERVICE;
                s->section = SECTION_SERVICE;
                s->service_set = 1;
                s->cf_section = flb_cf_section_create(cf, value, 0);
                if (!s->cf_section) {
                    return YAML_FAILURE;
                }
            }
            else if (strcasecmp(value, "customs") == 0) {
                s->state = STATE_CUSTOM;
                s->section = SECTION_CUSTOM;
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
            yaml_error_event(s, event);
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
            yaml_error_event(s, event);
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
            yaml_error_event(s, event);
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
                list = &cf->env;
            }
            else {
                list = &s->cf_section->properties;
            }
            /* register key/value pair as a property */
            kv = flb_cf_property_add(cf, list,
                                     s->key, flb_sds_len(s->key),
                                     s->val, flb_sds_len(s->val));
            if (!kv) {
                return YAML_FAILURE;
            }
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            break;
        default:
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    /* Plugin types */
    case STATE_PLUGIN_INPUT:
    case STATE_PLUGIN_FILTER:
    case STATE_PLUGIN_OUTPUT:
        switch(event->type) {
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_SECTION_KEY;
            break;
        case YAML_SCALAR_EVENT:
            s->state = STATE_SECTION;
            break;
        default:
            yaml_error_event(s, event);
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

            /* the 'type' is the plugin name, so we add it as a 'name' property */
            value = (char *) event->data.scalar.value;
            len = strlen(value);

            /* register the type: name = abc */
            kv = flb_cf_property_add(cf, &s->cf_section->properties,
                                     "name", 4,
                                     value, len);
            if (!kv) {
                return YAML_FAILURE;
            }

            /* next state are key value pairs */
            s->state = STATE_PLUGIN_KEY_VALUE_PAIR;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_PIPELINE;
            break;
        default:
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_KEY_VALUE_PAIR:
        switch(event->type) {
        case YAML_MAPPING_START_EVENT:
            s->state = STATE_PLUGIN_KEY;
            break;
        case YAML_MAPPING_END_EVENT:
            s->state = STATE_PLUGIN_TYPE;
            break;
        default:
            yaml_error_event(s, event);
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
        default:
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_PLUGIN_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_PLUGIN_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* register key/value pair as a property */
            flb_cf_property_add(cf, &s->cf_section->properties,
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
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_GROUP_KEY:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_GROUP_VAL;
            value = (char *) event->data.scalar.value;
            s->key = flb_sds_create(value);
            break;
        case YAML_MAPPING_END_EVENT:
            s->cf_group = NULL;
            s->state = STATE_PLUGIN_KEY;
            break;
        default:
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_GROUP_VAL:
        switch(event->type) {
        case YAML_SCALAR_EVENT:
            s->state = STATE_GROUP_KEY;
            value = (char *) event->data.scalar.value;
            s->val = flb_sds_create(value);

            /* register key/value pair as a property */
            flb_cf_property_add(cf, &s->cf_group->properties,
                                s->key, flb_sds_len(s->key),
                                s->val, flb_sds_len(s->val));
            flb_sds_destroy(s->key);
            flb_sds_destroy(s->val);
            break;
        default:
            yaml_error_event(s, event);
            return YAML_FAILURE;
        }
        break;

    case STATE_STOP:
        break;
    }

    return YAML_SUCCESS;
}

static int read_config(struct flb_cf *cf, void  *ctx, char *cfg_file)
{
    int code = 0;
    int status;
    struct parser_state state;
    yaml_parser_t parser;
    yaml_event_t event;
    FILE *fh;

    fh = fopen(cfg_file, "r");
    if (!fh) {
        flb_errno();
        return -1;
    }

    memset(&state, '\0', sizeof(state));
    state.file = flb_sds_create(cfg_file);
    if (!state.file) {
        fclose(fh);
        return -1;
    }

    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fh);

    do {
        status = yaml_parser_parse(&parser, &event);
        if (status == YAML_FAILURE) {
            flb_error("[config] invalid YAML format");
            code = -1;
            goto done;
        }
        status = consume_event(cf, &state, &event);
        if (status == YAML_FAILURE) {
            code = -1;
            goto done;
        }
        yaml_event_delete(&event);
    } while (state.state != STATE_STOP);

done:
    if (code == -1) {
        yaml_event_delete(&event);
    }
    flb_sds_destroy(state.file);
    yaml_parser_delete(&parser);
    fclose(fh);

    return code;
}

struct flb_cf *flb_cf_yaml_create(struct flb_cf *cf, char *file_path,
                                  char *buf, size_t size)
{
    int ret;

    if (!cf) {
        cf = flb_cf_create();
        if (!cf) {
            return NULL;
        }
    }

    ret = read_config(cf, NULL, file_path);
    if (ret == -1) {
        flb_cf_destroy(cf);
        return NULL;
    }

    return cf;
}
