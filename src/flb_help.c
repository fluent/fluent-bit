/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2015-2024 The Fluent Bit Authors
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
#include <fluent-bit/flb_version.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_help.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_mp.h>
#include <fluent-bit/flb_custom.h>
#include <fluent-bit/flb_input.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_output.h>



static inline void pack_str_s(msgpack_packer *mp_pck, char *str, int size)
{
    int len;

    len = strlen(str);
    msgpack_pack_str(mp_pck, len);

    if (len > 0) {
        msgpack_pack_str_body(mp_pck, str, len);
    }
}

static inline void pack_str(msgpack_packer *mp_pck, char *str)
{
    int size = strlen(str);
    pack_str_s(mp_pck, str, size);
}

int pack_config_map_entry(msgpack_packer *mp_pck, struct flb_config_map *m)
{
    int len;
    struct flb_mp_map_header mh;

    flb_mp_map_header_init(&mh, mp_pck);

    /* name */
    flb_mp_map_header_append(&mh);
    pack_str(mp_pck, "name");
    pack_str(mp_pck, m->name);

    /* description */
    flb_mp_map_header_append(&mh);
    pack_str(mp_pck, "description");
    if (m->desc) {
        pack_str(mp_pck, m->desc);
    }
    else {
        pack_str(mp_pck, "");
    }

    /* default value */
    flb_mp_map_header_append(&mh);
    pack_str(mp_pck, "default");
    if (m->def_value) {
        pack_str(mp_pck, m->def_value);
    }
    else {
        msgpack_pack_nil(mp_pck);
    }

    /* type */
    flb_mp_map_header_append(&mh);
    pack_str(mp_pck, "type");

    if (m->type == FLB_CONFIG_MAP_STR) {
        pack_str(mp_pck, "string");
    }
    else if (m->type == FLB_CONFIG_MAP_DEPRECATED) {
        pack_str(mp_pck, "deprecated");
    }
    else if (m->type == FLB_CONFIG_MAP_INT) {
        pack_str(mp_pck, "integer");
    }
    else if (m->type == FLB_CONFIG_MAP_BOOL) {
        pack_str(mp_pck, "boolean");
    }
    else if(m->type == FLB_CONFIG_MAP_DOUBLE) {
        pack_str(mp_pck, "double");
    }
    else if (m->type == FLB_CONFIG_MAP_SIZE) {
        pack_str(mp_pck, "size");
    }
    else if (m->type == FLB_CONFIG_MAP_TIME) {
        pack_str(mp_pck, "time");
    }
    else if (m->type == FLB_CONFIG_MAP_VARIANT) {
        pack_str(mp_pck, "variant");
    }
    else if (flb_config_map_mult_type(m->type) == FLB_CONFIG_MAP_CLIST) {
        len = flb_config_map_expected_values(m->type);
        if (len == -1) {
            pack_str(mp_pck, "multiple comma delimited strings");
        }
        else {
            char tmp[64];
            snprintf(tmp, sizeof(tmp) - 1,
                     "comma delimited strings (minimum %i)", len);
            pack_str(mp_pck, tmp);
        }
    }
    else if (flb_config_map_mult_type(m->type) == FLB_CONFIG_MAP_SLIST) {
        len = flb_config_map_expected_values(m->type);
        if (len == -1) {
            pack_str(mp_pck, "multiple space delimited strings");
        }
        else {
            char tmp[64];
            snprintf(tmp, sizeof(tmp) - 1,
                     "space delimited strings (minimum %i)", len);
            pack_str(mp_pck, tmp);
        }
    }
    else if (m->type == FLB_CONFIG_MAP_STR_PREFIX) {
        pack_str(mp_pck, "prefixed string");
    }
    else {
        /* this is a developer fault :) */
        fprintf(stderr, "[help] invalid config map type %i\n", m->type);
        exit(EXIT_FAILURE);
    }
    flb_mp_map_header_end(&mh);
    return 0;
}

int flb_help_custom(struct flb_custom_instance *ins, void **out_buf, size_t *out_size)
{
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_mp_map_header mh;
    struct flb_config_map *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 4);

    /* plugin type */
    pack_str(&mp_pck, "type");
    pack_str(&mp_pck, "custom");

    /* plugin name */
    pack_str(&mp_pck, "name");
    pack_str(&mp_pck, ins->p->name);

    /* description */
    pack_str(&mp_pck, "description");
    pack_str(&mp_pck, ins->p->description);

    /* list of properties */
    pack_str(&mp_pck, "properties");
    flb_mp_map_header_init(&mh, &mp_pck);

    /* properties['options']: options exposed by the plugin */
    if (ins->p->config_map) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "options");

        config_map = flb_config_map_create(ins->config, ins->p->config_map);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    flb_mp_map_header_end(&mh);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_help_input(struct flb_input_instance *ins, void **out_buf, size_t *out_size)
{
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_mp_map_header mh;
    struct flb_config_map *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int options_size = 0;
    struct flb_config_map m_input_net_listen = {
        .type =      FLB_CONFIG_MAP_STR,
        .name =      "listen",
        .def_value = "0.0.0.0",
        .desc =      "Listen Address",
    };
    struct flb_config_map m_input_net_host = {
        .type =      FLB_CONFIG_MAP_STR,
        .name =      "host",
        .def_value = "localhost",
        .desc =      "Hostname",
    };
    struct flb_config_map m_input_net_port = {
        .type =      FLB_CONFIG_MAP_INT,
        .name =      "port",
        .def_value = "0",
        .desc =      "Listen Port",
    };


    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 4);

    /* plugin type */
    pack_str(&mp_pck, "type");
    pack_str(&mp_pck, "input");

    /* plugin name */
    pack_str(&mp_pck, "name");
    pack_str(&mp_pck, ins->p->name);

    /* description */
    pack_str(&mp_pck, "description");
    pack_str(&mp_pck, ins->p->description);

    /* list of properties */
    pack_str(&mp_pck, "properties");
    flb_mp_map_header_init(&mh, &mp_pck);

    /* properties['global_options'] */
    flb_mp_map_header_append(&mh);
    pack_str(&mp_pck, "global_options");

    config_map = flb_input_get_global_config_map(ins->config);
    msgpack_pack_array(&mp_pck, mk_list_size(config_map));
    mk_list_foreach(head, config_map) {
        m = mk_list_entry(head, struct flb_config_map, _head);
        pack_config_map_entry(&mp_pck, m);
    }
    flb_config_map_destroy(config_map);

    /* properties['options']: options exposed by the plugin */
    if (ins->p->config_map) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "options");

        config_map = flb_config_map_create(ins->config, ins->p->config_map);
        options_size = mk_list_size(config_map);

        if ((ins->flags & (FLB_INPUT_NET | FLB_INPUT_NET_SERVER)) != 0) {
            options_size += 3;
        }

        msgpack_pack_array(&mp_pck, options_size);

        if ((ins->flags & (FLB_INPUT_NET | FLB_INPUT_NET_SERVER)) != 0) {
            pack_config_map_entry(&mp_pck, &m_input_net_listen);
            pack_config_map_entry(&mp_pck, &m_input_net_host);
            pack_config_map_entry(&mp_pck, &m_input_net_port);
        }

        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    if (ins->p->flags & FLB_INPUT_NET_SERVER) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "networking");

        config_map = flb_downstream_get_config_map(ins->config);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }
    else if (ins->p->flags & FLB_INPUT_NET) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "networking");

        config_map = flb_upstream_get_config_map(ins->config);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    if (ins->p->flags & (FLB_IO_TLS | FLB_IO_OPT_TLS)) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "network_tls");

        config_map = flb_tls_get_config_map(ins->config);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));

        /* Adjust 'tls' default value based on plugin type" */
        m = mk_list_entry_first(config_map, struct flb_config_map, _head);
        if (ins->p->flags & FLB_IO_TLS) {
            m->value.val.boolean = FLB_TRUE;
        }
        else if (ins->p->flags & FLB_IO_OPT_TLS) {
            m->value.val.boolean = FLB_FALSE;
        }
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    flb_mp_map_header_end(&mh);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_help_processor(struct flb_processor_instance *ins, void **out_buf, size_t *out_size)
{
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_mp_map_header mh;
    struct flb_config_map *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 4);
    /* plugin type */
    pack_str(&mp_pck, "type");
    pack_str(&mp_pck, "processor");

    /* plugin name */
    pack_str(&mp_pck, "name");
    pack_str(&mp_pck, ins->p->name);

    /* description */
    pack_str(&mp_pck, "description");
    pack_str(&mp_pck, ins->p->description);

    /* list of properties */
    pack_str(&mp_pck, "properties");
    flb_mp_map_header_init(&mh, &mp_pck);

    /* properties['global_options'] */
    flb_mp_map_header_append(&mh);
    pack_str(&mp_pck, "global_options");

    config_map = flb_processor_get_global_config_map(ins->config);
    msgpack_pack_array(&mp_pck, mk_list_size(config_map));
    mk_list_foreach(head, config_map) {
        m = mk_list_entry(head, struct flb_config_map, _head);
        pack_config_map_entry(&mp_pck, m);
    }
    flb_config_map_destroy(config_map);

    /* properties['options']: options exposed by the plugin */
    if (ins->p->config_map) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "options");

        config_map = flb_config_map_create(ins->config, ins->p->config_map);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    flb_mp_map_header_end(&mh);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_help_filter(struct flb_filter_instance *ins, void **out_buf, size_t *out_size)
{
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_mp_map_header mh;
    struct flb_config_map *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 4);

    /* plugin type */
    pack_str(&mp_pck, "type");
    pack_str(&mp_pck, "filter");

    /* plugin name */
    pack_str(&mp_pck, "name");
    pack_str(&mp_pck, ins->p->name);

    /* description */
    pack_str(&mp_pck, "description");
    pack_str(&mp_pck, ins->p->description);

    /* list of properties */
    pack_str(&mp_pck, "properties");
    flb_mp_map_header_init(&mh, &mp_pck);

    /* properties['global_options'] */
    flb_mp_map_header_append(&mh);
    pack_str(&mp_pck, "global_options");

    config_map = flb_filter_get_global_config_map(ins->config);
    msgpack_pack_array(&mp_pck, mk_list_size(config_map));
    mk_list_foreach(head, config_map) {
        m = mk_list_entry(head, struct flb_config_map, _head);
        pack_config_map_entry(&mp_pck, m);
    }
    flb_config_map_destroy(config_map);

    /* properties['options']: options exposed by the plugin */
    if (ins->p->config_map) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "options");

        config_map = flb_config_map_create(ins->config, ins->p->config_map);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    flb_mp_map_header_end(&mh);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

int flb_help_output(struct flb_output_instance *ins, void **out_buf, size_t *out_size)
{
    struct mk_list *head;
    struct mk_list *config_map;
    struct flb_mp_map_header mh;
    struct flb_config_map *m;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer mp_pck;
    int options_size = 0;
    struct mk_list *tls_config;
    struct flb_config_map m_output_net_host = {
        .type =      FLB_CONFIG_MAP_STR,
        .name =      "host",
        .def_value = "",
        .flags =     0,
        .desc =      "Host Address",
    };
    struct flb_config_map m_output_net_port = {
        .type =      FLB_CONFIG_MAP_INT,
        .name =      "port",
        .def_value = "0",
        .flags =     0,
        .desc =      "host Port",
    };

    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    msgpack_pack_map(&mp_pck, 4);

    /* plugin type */
    pack_str(&mp_pck, "type");
    pack_str(&mp_pck, "output");

    /* plugin name */
    pack_str(&mp_pck, "name");
    pack_str(&mp_pck, ins->p->name);

    /* description */
    pack_str(&mp_pck, "description");
    pack_str(&mp_pck, ins->p->description);

    /* list of properties */
    pack_str(&mp_pck, "properties");
    flb_mp_map_header_init(&mh, &mp_pck);

    /* properties['global_options'] */
    flb_mp_map_header_append(&mh);
    pack_str(&mp_pck, "global_options");

    config_map = flb_output_get_global_config_map(ins->config);
    msgpack_pack_array(&mp_pck, mk_list_size(config_map));
    mk_list_foreach(head, config_map) {
        m = mk_list_entry(head, struct flb_config_map, _head);
        pack_config_map_entry(&mp_pck, m);
    }
    flb_config_map_destroy(config_map);

    /* properties['options']: options exposed by the plugin */
    if (ins->p->config_map) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "options");

        config_map = flb_config_map_create(ins->config, ins->p->config_map);
        options_size = mk_list_size(config_map);

        options_size = mk_list_size(config_map);
        if (ins->flags & FLB_OUTPUT_NET) {
            options_size += 2;
        }
        if (ins->flags & FLB_IO_OPT_TLS) {
            tls_config = flb_tls_get_config_map(ins->config);
            options_size += mk_list_size(tls_config);
        }

        msgpack_pack_array(&mp_pck, options_size);

        if (ins->flags & FLB_OUTPUT_NET) {
            pack_config_map_entry(&mp_pck, &m_output_net_host);
            pack_config_map_entry(&mp_pck, &m_output_net_port);
        }
        if (ins->flags & FLB_IO_OPT_TLS) {
            mk_list_foreach(head, tls_config) {
                m = mk_list_entry(head, struct flb_config_map, _head);
                pack_config_map_entry(&mp_pck, m);
            }
            flb_config_map_destroy(tls_config);
        }

        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    if (ins->p->flags & FLB_OUTPUT_NET) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "networking");

        config_map = flb_upstream_get_config_map(ins->config);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }

    if (ins->p->flags & (FLB_IO_TLS | FLB_IO_OPT_TLS)) {
        flb_mp_map_header_append(&mh);
        pack_str(&mp_pck, "network_tls");

        config_map = flb_tls_get_config_map(ins->config);
        msgpack_pack_array(&mp_pck, mk_list_size(config_map));

        /* Adjust 'tls' default value based on plugin type" */
        m = mk_list_entry_first(config_map, struct flb_config_map, _head);
        if (ins->p->flags & FLB_IO_TLS) {
            m->value.val.boolean = FLB_TRUE;
        }
        else if (ins->p->flags & FLB_IO_OPT_TLS) {
            m->value.val.boolean = FLB_FALSE;
        }
        mk_list_foreach(head, config_map) {
            m = mk_list_entry(head, struct flb_config_map, _head);
            pack_config_map_entry(&mp_pck, m);
        }
        flb_config_map_destroy(config_map);
    }
    flb_mp_map_header_end(&mh);

    *out_buf = mp_sbuf.data;
    *out_size = mp_sbuf.size;

    return 0;
}

static int build_plugin_help(struct flb_config *config, int type, char *name,
                             char **out_buf, size_t *out_size)
{
    void *help_buf = NULL;
    size_t help_size = 0;
    struct flb_custom_instance *c = NULL;
    struct flb_input_instance *i = NULL;
    struct flb_processor_instance *p = NULL;
    struct flb_filter_instance *f = NULL;
    struct flb_output_instance *o = NULL;

    if (type == FLB_HELP_PLUGIN_CUSTOM) {
        c = flb_custom_new(config, name, NULL);
        if (!c) {
            fprintf(stderr, "invalid custom plugin '%s'", name);
            return -1;
        }
        flb_help_custom(c, &help_buf, &help_size);
        flb_custom_instance_destroy(c);
    }
    else if (type == FLB_HELP_PLUGIN_INPUT) {
        i = flb_input_new(config, name, 0, FLB_TRUE);
        if (!i) {
            fprintf(stderr, "invalid input plugin '%s'", name);
            return -1;
        }
        flb_help_input(i, &help_buf, &help_size);
        flb_input_instance_destroy(i);
    }
    else if (type == FLB_HELP_PLUGIN_PROCESSOR) {
        p = flb_processor_instance_create(config, NULL, 0, name, NULL);
        if (!p) {
            fprintf(stderr, "invalid processor plugin '%s'", name);
            return -1;
        }
        flb_help_processor(p, &help_buf, &help_size);
        flb_processor_instance_destroy(p);
    }
    else if (type == FLB_HELP_PLUGIN_FILTER) {
        f = flb_filter_new(config, name, 0);
        if (!f) {
            fprintf(stderr, "invalid filter plugin '%s'", name);
            return -1;
        }
        flb_help_filter(f, &help_buf, &help_size);
        flb_filter_instance_destroy(f);
    }
    else if (type == FLB_HELP_PLUGIN_OUTPUT) {
        o = flb_output_new(config, name, 0, FLB_TRUE);
        if (!o) {
            fprintf(stderr, "invalid output plugin '%s'", name);
            return -1;
        }
        flb_help_output(o, &help_buf, &help_size);
        flb_output_instance_destroy(o);
    }

    *out_buf = help_buf;
    *out_size = help_size;

    return 0;
}

static void pack_map_kv(msgpack_packer *mp_pck, char *key, char *val)
{
    int k_len;
    int v_len;

    k_len = strlen(key);
    v_len = strlen(val);

    msgpack_pack_str(mp_pck, k_len);
    msgpack_pack_str_body(mp_pck, key, k_len);

    msgpack_pack_str(mp_pck, v_len);
    msgpack_pack_str_body(mp_pck, val, v_len);

}

flb_sds_t flb_help_build_json_schema(struct flb_config *config)
{
    int ret;
    char *out_buf;
    flb_sds_t json;
    size_t out_size;
    struct mk_list *head;
    struct flb_custom_plugin *c;
    struct flb_input_plugin *i;
    struct flb_processor_plugin *p;
    struct flb_filter_plugin *f;
    struct flb_output_plugin *o;
    msgpack_sbuffer mp_sbuf;
    msgpack_packer  mp_pck;
    struct flb_mp_map_header mh;

    /* initialize buffer */
    msgpack_sbuffer_init(&mp_sbuf);
    msgpack_packer_init(&mp_pck, &mp_sbuf, msgpack_sbuffer_write);

    /*
     * Root map for entries:
     *
     * - fluent-bit
     * - customs
     * - inputs
     * - processors
     * - filters
     * - outputs
     */
    msgpack_pack_map(&mp_pck, 6);

    /* Fluent Bit */
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "fluent-bit", 10);

    /* fluent-bit['version'], fluent-bit['help_version'] and fluent-bit['os'] */
    msgpack_pack_map(&mp_pck, 3);

    pack_map_kv(&mp_pck, "version",  FLB_VERSION_STR);
    pack_map_kv(&mp_pck, "schema_version",  FLB_HELP_SCHEMA_VERSION);
    pack_map_kv(&mp_pck, "os",  (char *) flb_utils_get_os_name());

    /* customs */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "customs", 7);

    flb_mp_array_header_init(&mh, &mp_pck);
    mk_list_foreach(head, &config->custom_plugins) {
        c = mk_list_entry(head, struct flb_custom_plugin, _head);
        ret = build_plugin_help(config, FLB_HELP_PLUGIN_CUSTOM, c->name,
                                &out_buf, &out_size);
        if (ret == -1) {
            continue;
        }

        flb_mp_array_header_append(&mh);
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
        flb_free(out_buf);
    }
    flb_mp_array_header_end(&mh);


    /* inputs */
    msgpack_pack_str(&mp_pck, 6);
    msgpack_pack_str_body(&mp_pck, "inputs", 6);

    flb_mp_array_header_init(&mh, &mp_pck);
    mk_list_foreach(head, &config->in_plugins) {
        i = mk_list_entry(head, struct flb_input_plugin, _head);
        if (i->flags & FLB_INPUT_PRIVATE){
            continue;
        }
        ret = build_plugin_help(config, FLB_HELP_PLUGIN_INPUT, i->name,
                                &out_buf, &out_size);
        if (ret == -1) {
            continue;
        }
        flb_mp_array_header_append(&mh);
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
        flb_free(out_buf);
    }
    flb_mp_array_header_end(&mh);

    /* processors */
    msgpack_pack_str(&mp_pck, 10);
    msgpack_pack_str_body(&mp_pck, "processors", 10);
    flb_mp_array_header_init(&mh, &mp_pck);
    mk_list_foreach(head, &config->processor_plugins) {
        p = mk_list_entry(head, struct flb_processor_plugin, _head);

        ret = build_plugin_help(config, FLB_HELP_PLUGIN_PROCESSOR, p->name,
                                &out_buf, &out_size);
        if (ret == -1) {
            continue;
        }
        flb_mp_array_header_append(&mh);
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
        flb_free(out_buf);
    }
    flb_mp_array_header_end(&mh);

    /* filters */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "filters", 7);

    flb_mp_array_header_init(&mh, &mp_pck);
    mk_list_foreach(head, &config->filter_plugins) {
        f = mk_list_entry(head, struct flb_filter_plugin, _head);
        ret = build_plugin_help(config, FLB_HELP_PLUGIN_FILTER, f->name,
                                &out_buf, &out_size);
        if (ret == -1) {
            continue;
        }

        flb_mp_array_header_append(&mh);
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
        flb_free(out_buf);
    }
    flb_mp_array_header_end(&mh);

    /* outputs */
    msgpack_pack_str(&mp_pck, 7);
    msgpack_pack_str_body(&mp_pck, "outputs", 7);

    flb_mp_array_header_init(&mh, &mp_pck);
    mk_list_foreach(head, &config->out_plugins) {
        o = mk_list_entry(head, struct flb_output_plugin, _head);
        if (o->flags & FLB_OUTPUT_PRIVATE){
            continue;
        }
        ret = build_plugin_help(config, FLB_HELP_PLUGIN_OUTPUT, o->name,
                                &out_buf, &out_size);
        if (ret == -1) {
            continue;
        }
        flb_mp_array_header_append(&mh);
        msgpack_sbuffer_write(&mp_sbuf, out_buf, out_size);
        flb_free(out_buf);
    }
    flb_mp_array_header_end(&mh);

    json = flb_msgpack_raw_to_json_sds(mp_sbuf.data, mp_sbuf.size, FLB_TRUE);
    msgpack_sbuffer_destroy(&mp_sbuf);

    return json;
}
