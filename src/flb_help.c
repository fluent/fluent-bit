/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019-2021 The Fluent Bit Authors
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

    flb_mp_map_header_end(&mh);
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
