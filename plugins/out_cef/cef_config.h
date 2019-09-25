/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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

#ifndef FLB_OUT_CEF_CONFIG_H
#define FLB_OUT_CEF_CONFIG_H

struct cef_dic {
    char *key;
    char *key_full_name;
    enum cef_type type;
    int size;
};

struct cef_cdic {
    char *label;
    int label_size;
    char *value;
    int value_size;
    enum cef_type type;
};

struct cef_ht_dic {
    enum cef_ftype ftype;
    enum cef_type type;
    flb_sds_t clabel;
    flb_sds_t cvalue;
    flb_sds_t label;
    int value_max_size;
};

struct cef_ht_entry {
    int dic_size;
    struct cef_ht_dic *dic;
    struct flb_hash *child;
};

struct out_cef_config {
    /* Upstream connection to the backend server */
    struct flb_upstream *u;
    flb_sockfd_t fd;

    struct flb_hash *ht_dic;
    int mode;
    int fmt;
};

int cef_settings (struct flb_output_instance *ins,
                  struct out_cef_config *ctx);

void cef_ht_destroy (struct flb_hash *ht);

struct cef_ht_entry *cef_ht_find(struct flb_hash *ht,
                                 char * key, int key_len);

#endif
