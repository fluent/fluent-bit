/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <maxminddb.h>

#ifndef FLB_FILTER_GEOIP2_H
#define FLB_FILTER_GEOIP2_H

struct geoip2_lookup_key {
    char *key;
    int key_len;
    struct mk_list _head;
};

struct geoip2_record {
    char *lookup_key;
    char *key;
    char *val;
    int lookup_key_len;
    int key_len;
    int val_len;
    struct mk_list _head;
};

struct geoip2_ctx {
    MMDB_s *mmdb;
    int lookup_keys_num;
    int records_num;
    struct mk_list lookup_keys;
    struct mk_list records;
};

#endif
