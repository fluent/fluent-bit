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

int flb_filter_set_property(struct flb_filter_instance *filter, char *k, char *v)
{
    struct flb_config_prop *prop;

    /* Append any remaining configuration key to prop list */
    prop = flb_malloc(sizeof(struct flb_config_prop));
    if (!prop) {
        return -1;
    }

    prop->key = flb_strdup(k);
    prop->val = flb_strdup(v);
    mk_list_add(&prop->_head, &filter->properties);

    return 0;
}
