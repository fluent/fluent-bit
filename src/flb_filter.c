/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2017 Treasure Data Inc.
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

#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_router.h>

static inline int instance_id(struct flb_filter_plugin *p,
                              struct flb_config *config)
{
    int c = 0;
    struct mk_list *head;
    struct flb_filter_instance *entry;

    mk_list_foreach(head, &config->filters) {
        entry = mk_list_entry(head, struct flb_filter_instance, _head);
        if (entry->p == p) {
            c++;
        }
    }

    return c;
}

static inline int prop_key_check(char *key, char *kv, int k_len)
{
    int len;

    len = strlen(key);
    if (strncasecmp(key, kv, k_len) == 0 && len == k_len) {
        return 0;
    }

    return -1;
}

#define msgpack_pack_append_buffer(user, buf, len) \
    (*(user)->callback)((user)->data, (const char*)buf, len)

/*
 * If a filter plugin returned a new buffer, we need to replace the
 * old buffer comming from the input instance.
 */
static void flb_filter_replace(struct flb_input_instance *i_ins,
                               size_t old_size,
                               void *new_buf, size_t new_size)
{
    i_ins->mp_sbuf.size -= old_size;
    msgpack_sbuffer_write(&i_ins->mp_sbuf, new_buf, new_size);
}

void flb_filter_do(struct flb_input_instance *i_ins,
                   void *data, size_t bytes,
                   char *tag, int tag_len,
                   struct flb_config *config)
{
    int ret;
    void *out_buf;
    size_t out_size;
    struct mk_list *head;
    struct flb_filter_instance *f_ins;

    mk_list_foreach(head, &config->filters) {
        f_ins = mk_list_entry(head, struct flb_filter_instance, _head);
        if (flb_router_match(tag, f_ins->match)) {
            /* Reset filtered buffer */
            out_buf = NULL;
            out_size = 0;

            /* Invoke the filter callback */
            ret = f_ins->p->cb_filter(data, bytes,    /* msgpack raw data */
                                      tag, tag_len,   /* input tag        */
                                      &out_buf,       /* new data         */
                                      &out_size,      /* new data size    */
                                      f_ins,          /* filter instance  */
                                      f_ins->context, /* filter priv data */
                                      config);

            /* Override buffer just if it was modified */
            if (ret == FLB_FILTER_MODIFIED) {
                flb_filter_replace(i_ins,              /* input instance */
                                   bytes,              /* passed data    */
                                   out_buf, out_size); /* new data       */
                /* Release new temporal buffer */
                flb_free(out_buf);

                /* Point back the 'data' pointer to the new address */
                bytes = out_size;
                data  = i_ins->mp_sbuf.data + (i_ins->mp_sbuf.size - out_size);
            }
        }
    }
}

int flb_filter_set_property(struct flb_filter_instance *filter, char *k, char *v)
{
    int len;
    struct flb_config_prop *prop;

    len = strlen(k);

    /* Check if the key is a known/shared property */
    if (prop_key_check("match", k, len) == 0) {
        filter->match = flb_strdup(v);
    }
    else {
        /* Append any remaining configuration key to prop list */
        prop = flb_malloc(sizeof(struct flb_config_prop));
        if (!prop) {
            return -1;
        }

        prop->key = flb_strdup(k);
        prop->val = flb_strdup(v);
        mk_list_add(&prop->_head, &filter->properties);
    }

    return 0;
}

struct flb_filter_instance *flb_filter_new(struct flb_config *config,
                                           char *filter, void *data)
{
    int id;
    struct mk_list *head;
    struct flb_filter_plugin *plugin;
    struct flb_filter_instance *instance = NULL;

    if (!filter) {
        return NULL;
    }

    mk_list_foreach(head, &config->filter_plugins) {
        plugin = mk_list_entry(head, struct flb_filter_plugin, _head);
        if (strcmp(plugin->name, filter) == 0) {
            break;
        }
        plugin = NULL;
    }

    if (!plugin) {
        return NULL;
    }

    instance = flb_malloc(sizeof(struct flb_filter_instance));
    if (!instance) {
        flb_errno();
        return NULL;
    }

    /* Get an ID */
    id =  instance_id(plugin, config);

    /* format name (with instance id) */
    snprintf(instance->name, sizeof(instance->name) - 1,
             "%s.%i", plugin->name, id);

    instance->id    = id;
    instance->p     = plugin;
    instance->data  = data;
    mk_list_init(&instance->properties);
    mk_list_add(&instance->_head, &config->filters);

    return instance;
}

/* Initialize all filter plugins */
void flb_filter_initialize_all(struct flb_config *config)
{
    int ret;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_filter_plugin *p;
    struct flb_filter_instance *in;

    /* Iterate all active filter instance plugins */
    mk_list_foreach_safe(head, tmp, &config->filters) {
        in = mk_list_entry(head, struct flb_filter_instance, _head);
        p = in->p;

        /* Initialize the input */
        if (p->cb_init) {
            ret = p->cb_init(in, config, in->data);
            if (ret != 0) {
                flb_error("Failed initialize filter %s", in->name);
                mk_list_del(&in->_head);
                flb_free(in);
            }
        }
    }
}

void flb_filter_set_context(struct flb_filter_instance *ins, void *context)
{
    ins->context = context;
}
