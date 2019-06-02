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

#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_hash.h>
#include <fluent-bit/flb_sds.h>

#include <msgpack.h>

#include "cef.h"
#include "cef_config.h"

#ifndef MSG_DONTWAIT
    #define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

#define PLUGIN_NAME "out_cef"

/*
 * CEF description:
 *
 * https://www.secef.net/wp-content/uploads/sites/10/2017/04/CommonEventFormatv23.pdf
 * https://community.microfocus.com/t5/ArcSight-Connectors/ArcSight-Common-Event-Format-CEF-Implementation-Standard/ta-p/1645557
 * https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf
 *
 */

static char esc_cef_msg[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,'n', 0, 0 ,'r', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0,'\\',0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0,'|', 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0
};

static char esc_cef_ext[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0,'n', 0, 0 ,'r', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 ,'=', 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0,'\\',0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 , 0, 0 , 0 , 0, 0
};

static char esc_json[256] = {
    0, 0, 0 , 0, 0, 0, 0, 0,'b','t','n', 0,'f','r', 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0,'"', 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0,'/',
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0,'\\',0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0 ,
    0, 0, 0 , 0, 0, 0, 0, 0, 0 , 0 , 0 , 0, 0 , 0 , 0, 0
};

static struct {
    char *name;
    int len;
    int value;
} cef_syslog_severity[] =  {
    { "emerg",   5, 0 },
    { "alert",   5, 1 },
    { "crit",    4, 2 },
    { "err",     3, 3 },
    { "warning", 7, 4 },
    { "notice",  6, 5 },
    { "info",    4, 6 },
    { "debug",   5, 7 },
    { NULL,      0,-1 }
};

static struct {
    char *name;
    int len;
    int value;
} cef_syslog_facility[] = {
    { "kern",     4, 0  },
    { "user",     4, 1  },
    { "mail",     4, 2  },
    { "daemon",   6, 3  },
    { "auth",     4, 4  },
    { "syslog",   6, 5  },
    { "lpr",      3, 6  },
    { "news",     4, 7  },
    { "uucp",     4, 8  },
    { "cron",     4, 9  },
    { "authpriv", 8, 10 },
    { "ftp",      3, 11 },
    { "ntp",      3, 12 },
    { "security", 8, 13 },
    { "console",  7, 14 },
    { "local0",   6, 16 },
    { "local1",   6, 17 },
    { "local2",   6, 18 },
    { "local3",   6, 19 },
    { "local4",   6, 20 },
    { "local5",   6, 21 },
    { "local6",   6, 22 },
    { "local7",   6, 23 },
    { NULL,       0,-1  },
};

static char *cef_hostname;
static int cef_hostname_len;

static flb_sds_t cef_set_ext (flb_sds_t *ext, struct cef_ht_dic *dic,
                                 char *val, int val_len)
{
    flb_sds_t tmp;

    if (dic->clabel) {
        tmp = flb_sds_cat(*ext, dic->clabel, flb_sds_len(dic->clabel));
        if (!tmp) return NULL;
        *ext = tmp;

        tmp = flb_sds_cat(*ext, "=", 1);
        if (!tmp) return NULL;
        *ext = tmp;

        tmp = flb_sds_cat(*ext, dic->label, flb_sds_len(dic->label));
        if (!tmp) return NULL;
        *ext = tmp;

        tmp = flb_sds_cat(*ext, " ", 1);
        if (!tmp) return NULL;
        *ext = tmp;

        tmp = flb_sds_cat_utf8(ext, dic->cvalue, flb_sds_len(dic->cvalue),
                               esc_cef_ext, sizeof(esc_cef_ext));
        if (!tmp) return NULL;
        *ext = tmp;
    }
    else {
        tmp = flb_sds_cat(*ext, dic->label, flb_sds_len(dic->label));
        if (!tmp) return NULL;
        *ext = tmp;
    }

    tmp = flb_sds_cat(*ext, "=", 1);
    if (!tmp) return NULL;
    *ext = tmp;

    if ((dic->value_max_size > 0) && (val_len > dic->value_max_size)) {
        val_len = dic->value_max_size;
    }

    tmp = flb_sds_cat_utf8(ext, val, val_len, esc_cef_ext, sizeof(esc_cef_ext));
    if (!tmp) return NULL;
    *ext = tmp;

    return *ext;
}

static int cef_set(struct cef_ht_dic *dic, int dic_size,
                   struct cef_msg *msg, char *val, int val_len)
{
    flb_sds_t tmp;
    int n;

    for (n=0; n < dic_size; n++) {
        switch (dic[n].ftype) {
        case CEF_SYSLOG_HOST:
            if (!msg->host) {
                msg->host = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_SYSLOG_FACILITY:
            if (msg->syslog_facility == -1) {
                if ((val_len == 1) && (val[0] >= '0' && val[0] <= '9')) {
                    msg->syslog_facility = val[0]-'0';
                }
                else if ((val_len == 2) &&
                         (val[0] >= '0' && val[0] <= '2') &&
                         (val[1] >= '0' && val[1] <= '9')) {
                    msg->syslog_facility = (val[0]-'0')*10;
                    msg->syslog_facility += (val[1]-'0');
                    if (!((msg->syslog_facility >= 0) &&
                          (msg->syslog_facility <=23))) {
                         flb_warn("[out_cef] invalid facility: '%.*s'",
                                   val_len, val);
                         msg->syslog_facility= -1;
                    }
                }
                else {
                    int i;
                    for (i=0; cef_syslog_facility[i].name != NULL; i++) {
                        if ((cef_syslog_facility[i].len == val_len) &&
                            (!strncasecmp(cef_syslog_facility[i].name, val, val_len))) {
                            msg->syslog_facility = cef_syslog_facility[i].value;
                        }
                    }
                    if (!cef_syslog_facility[i].name) {
                         flb_warn("[out_cef] invalid facility: '%.*s'",
                                   val_len, val);
                    }
                }
            }
            break;
        case CEF_SYSLOG_SEVERITY:
            if (msg->syslog_severity == -1) {
                if ((val_len == 1) && (val[0] >= '0' && val[0] <= '7')) {
                    msg->syslog_severity = val[0]-'0';
                }
                else {
                    int i;
                    for (i=0; cef_syslog_severity[i].name != NULL; i++) {
                        if ((cef_syslog_severity[i].len == val_len) &&
                            (!strncasecmp(cef_syslog_severity[i].name, val, val_len))) {
                            msg->syslog_severity = cef_syslog_severity[i].value;
                        }
                    }
                    if (!cef_syslog_severity[i].name) {
                         flb_warn("[out_cef] invalid severity: '%.*s'",
                                   val_len, val);
                    }
                }

            }
            break;
        case CEF_HDR_DEV_VENDOR:
            if (!msg->dev_vendor) {
                msg->dev_vendor = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_HDR_DEV_PRODUCT:
            if (!msg->dev_product) {
                msg->dev_product = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_HDR_DEV_VERSION:
            if (!msg->dev_version) {
                msg->dev_version = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_HDR_DEV_EVENT_CID:
                if (!msg->dev_event_cid) {
                msg->dev_event_cid = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_HDR_SEVERITY:
            if (!msg->severity) {
                if ((val_len == 1) && (val[0] >= '0' && val[0] <= '9')) {
                     msg->severity = flb_sds_create_len(val, val_len);
                }
                else if ((val_len == 2) && (val[0] == '1') && (val[1] == '0')) {
                    msg->syslog_facility = (val[0]-'0')*10;
                    msg->syslog_facility += (val[1]-'0');
                    if (!((msg->syslog_facility >= 0) &&
                         (msg->syslog_facility <=23))) {
                        msg->severity = flb_sds_create_len(val, val_len);
                    }
                }
                else if ((val_len == 3) && !strncasecmp("Low", val, val_len)) {
                    msg->severity = flb_sds_create_len("0", 1);
                }
                else if ((val_len == 4) && !strncasecmp("High", val, val_len)) {
                    msg->severity = flb_sds_create_len("4", 1);
                }
                else if ((val_len == 5) && !strncasecmp("Medium", val, val_len)) {
                    msg->severity = flb_sds_create_len("7", 1);
                }
                else if ((val_len == 9) && !strncasecmp("Very-High", val, val_len)) {
                    msg->severity = flb_sds_create_len("9", 1);
                }
                else {
                    flb_warn("[out_cef] invalid facility: '%.*s'",
                             val_len, val);
                }
            }
            break;
        case CEF_HDR_NAME:
            if (!msg->name) {
                msg->name = flb_sds_create_len(val, val_len);
            }
            break;
        case CEF_CUSTOM_IPV6:
        case CEF_CUSTOM_FLOAT:
        case CEF_CUSTOM_NUMBER:
        case CEF_CUSTOM_STRING:
        case CEF_CUSTOM_DATE:
        case CEF_FLEX_DATE:
        case CEF_FLEX_STRING:
        case CEF_EXTENSION:
        case CEF_CUSTOM_EXTENSION:
            if (msg->ext_cnt > 0) {
                tmp = flb_sds_cat(msg->ext, " ", 1);
                if (!tmp) return -1;
                msg->ext = tmp;
            }

            tmp = cef_set_ext (&(msg->ext), &dic[n], val, val_len);
            if (!tmp) return -1;
            msg->ext = tmp;

            msg->ext_cnt++;

            break;
        }
    }
    return 0;
}

static flb_sds_t msgpack_cef_json(flb_sds_t *s, msgpack_object *o)
{
    int i;
    int loop;
    flb_sds_t tmp;

    switch(o->type) {
    case MSGPACK_OBJECT_NIL:
        tmp = flb_sds_cat(*s, "null", 4);
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_BOOLEAN:
        if (o->via.boolean) {
            tmp = flb_sds_cat(*s, "true", 4);
        }
        else {
            tmp = flb_sds_cat(*s, "false", 5);
        }
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_POSITIVE_INTEGER:
        tmp = flb_sds_printf(s, "%lu", (unsigned long)o->via.u64);
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_NEGATIVE_INTEGER:
        tmp = flb_sds_printf(s, "%ld", (signed long)o->via.i64);
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_FLOAT32:
    case MSGPACK_OBJECT_FLOAT64:
        tmp = flb_sds_printf(s, "%f", o->via.f64);
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_STR:
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        tmp = flb_sds_cat_utf8(s, (char *)o->via.str.ptr,
                                   o->via.str.size, esc_json, sizeof(esc_json));
        if (!tmp) return NULL;
        *s = tmp;
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        break;

    case MSGPACK_OBJECT_BIN:
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        tmp = flb_sds_cat_utf8(s, (char *)o->via.bin.ptr,
                                    o->via.bin.size, esc_json, sizeof(esc_json));
        if (!tmp) return NULL;
        *s = tmp;
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        break;
    case MSGPACK_OBJECT_EXT:
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        {
            static const char int2hex[] = "0123456789abcdef";
            int i;
            char temp[5];
            char *val = (char *)o->via.ext.ptr;
            for(i=0; i < o->via.ext.size; i++) {
                char c = (char)val[i];
                temp[0] = '\\';
                temp[1] = 'x';
                temp[2] = int2hex[ (unsigned char) ((c & 0xf0) >> 4)];
                temp[3] = int2hex[ (unsigned char) (c & 0x0f)];
                temp[4] = '\0';
                tmp = flb_sds_cat(*s, temp, 4);
                if (!tmp) return NULL;
                *s = tmp;
            }
        }
        tmp = flb_sds_cat(*s, "\"", 1);
        if (!tmp) return NULL;
        *s = tmp;
        break;
    case MSGPACK_OBJECT_ARRAY:
        loop = o->via.array.size;
        tmp = flb_sds_cat(*s, "[", 1);
        if (!tmp) return NULL;
        *s = tmp;
        if (loop != 0) {
            msgpack_object* p = o->via.array.ptr;
            for (i=0; i<loop; i++) {
                if (i > 0) {
                     tmp = flb_sds_cat(*s, ", ", 2);
                     if (!tmp) return NULL;
                     *s = tmp;
                }
                tmp = msgpack_cef_json(s, p+i);
                if (!tmp) return NULL;
                *s = tmp;
            }
        }
        tmp = flb_sds_cat(*s, "]", 1);
        if (!tmp) return NULL;
        *s = tmp;
        break;
   case MSGPACK_OBJECT_MAP:
        loop = o->via.map.size;
        tmp = flb_sds_cat(*s, "{", 1);
        if (!tmp) return NULL;
        *s = tmp;
        if (loop != 0) {
            msgpack_object_kv *p = o->via.map.ptr;
            for (i = 0; i < loop; i++) {
                msgpack_object *k = &((p+i)->key);
                msgpack_object *v = &((p+i)->val);
                if (i > 0) {
                     tmp = flb_sds_cat(*s, ", ", 2);
                     if (!tmp) return NULL;
                     *s = tmp;
                }
                tmp = msgpack_cef_json(s, k);
                if (!tmp) return NULL;
                *s = tmp;
                tmp = flb_sds_cat(*s, ":", 1);
                if (!tmp) return NULL;
                *s = tmp;
                tmp = msgpack_cef_json(s, v);
                if (!tmp) return NULL;
                *s = tmp;
            }
        }
        tmp = flb_sds_cat(*s, "}", 1);
        if (!tmp) return NULL;
        *s = tmp;
        break;
   }

   return *s;
}

static int msgpack_to_cef_map (struct cef_ht *ht,
                                     struct cef_msg *msg,
                                     msgpack_object *o)
{
    struct cef_ht_entry *entry = NULL;
    flb_sds_t tmp;
    int i;
    int loop;
    int ret;

    loop = o->via.map.size;
    if (loop != 0) {
        msgpack_object_kv *p = o->via.map.ptr;

        for (i = 0; i < loop; i++) {
            char *key = NULL;
            int key_len;
            char *val = NULL;
            int val_len;

            msgpack_object *k = &p[i].key;
            msgpack_object *v = &p[i].val;

            if (k->type != MSGPACK_OBJECT_BIN &&
                k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key = (char *) k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = (char *) k->via.bin.ptr;
                key_len = k->via.bin.size;
            }

            if (!key) {
                continue;
            }

            entry = cef_ht_find(ht, key, key_len);
            if (!entry) {
                continue;
            }

            if (v->type == MSGPACK_OBJECT_MAP) {
                if (entry->child) {
                    msgpack_to_cef_map(entry->child, msg, v);
                }
                else if (entry->dic_size) {
                   flb_sds_t map = flb_sds_create_size(256);
                   if (!map) {
                       return -1;
                   }
                   tmp = msgpack_cef_json(&map, v);
                   if (!tmp) {
                       flb_sds_destroy(map);
                       return -1;
                   }
                   map = tmp;

                   ret = cef_set(entry->dic, entry->dic_size,
                                 msg, map, flb_sds_len(map));
                   flb_sds_destroy(map);
                   if (ret < 0) {
                       return -1;
                   }
                }
            }
            else if (v->type == MSGPACK_OBJECT_ARRAY) {
                if (entry->dic_size) {
                   flb_sds_t array = flb_sds_create_size(256);
                   if (!array) {
                       return -1;
                   }
                   tmp = msgpack_cef_json(&array, v);
                   if (!tmp) {
                       flb_sds_destroy(array);
                       return -1;
                   }
                   array = tmp;

                   ret = cef_set(entry->dic, entry->dic_size,
                                 msg, array, flb_sds_len(array));
                   flb_sds_destroy(array);
                   if (ret < 0) {
                       return -1;
                   }
                }
            }
            else {
                char temp[48] = {0};

                if (v->type == MSGPACK_OBJECT_NIL) {
                    val = "null";
                    val_len = 4;
                    continue;
                }
                else if (v->type == MSGPACK_OBJECT_BOOLEAN) {
                    val = v->via.boolean ? "true" : "false";
                    val_len = v->via.boolean ? 4 : 5;
                }
                else if (v->type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%" PRIu64, v->via.u64);
                }
                else if (v->type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%" PRId64, v->via.i64);
                }
                else if (v->type == MSGPACK_OBJECT_FLOAT) {
                    val = temp;
                    val_len = snprintf(temp, sizeof(temp) - 1,
                                       "%f", v->via.f64);
                }
                else if (v->type == MSGPACK_OBJECT_STR) {
                    /* String value */
                    val     = (char *) v->via.str.ptr;
                    val_len = v->via.str.size;
                }
                else if (v->type == MSGPACK_OBJECT_BIN) {
                    /* Bin value */
                    val     = (char *) v->via.bin.ptr;
                    val_len = v->via.bin.size;
                }
                else if (v->type == MSGPACK_OBJECT_EXT) {
                    val     = (char *)o->via.ext.ptr;
                    val_len = o->via.ext.size;
                }

                if (!val) {
                    continue;
                }

                ret = cef_set(entry->dic, entry->dic_size, msg, val, val_len);
                if (ret < 0) {
                    return -1;
                }
            }
        }
    }

    return 0;
}

static flb_sds_t cef_cat_prefix (struct out_cef_config *ctx,
                                 struct cef_msg *msg,
                                 struct flb_time *tms,
                                 flb_sds_t *s)
{
    flb_sds_t tmp;
    int ret;

    if (ctx->fmt == FLB_CEF_FMT_SYSLOG) {
        struct tm tm;
        char time_formatted[64];
        int severity = 6; /* INFO */
        int facility = 1; /* USER */
        unsigned int pri;

        if (msg->syslog_facility >= 0) {
            facility = msg->syslog_facility;
        }

        if (msg->syslog_severity >= 0) {
            severity = msg->syslog_severity;
        }

        pri = (facility << 3) + severity;

        tmp = flb_sds_printf(s, "<%i>", pri);
        if (!tmp) return NULL;
        *s = tmp;

        gmtime_r(&tms->tm.tv_sec, &tm);

        ret = strftime(time_formatted, sizeof(time_formatted) - 1,
                       "%b %d %H:%M:%S ", &tm);
        if (ret <= 0) return NULL;

        tmp = flb_sds_cat(*s, time_formatted, ret);
        if (!tmp) return NULL;
        *s = tmp;

        if (msg->host)
        {
            tmp = flb_sds_cat(*s, msg->host, flb_sds_len(msg->host));
            if (!tmp) return NULL;
            *s = tmp;
        }
        else {
            tmp = flb_sds_cat(*s, cef_hostname, cef_hostname_len);
            if (!tmp) return NULL;
            *s = tmp;
        }
        tmp = flb_sds_cat(*s, " ", 1);
        if (!tmp) return NULL;
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, "CEF:0|", 6);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->dev_vendor)
    {
        tmp = flb_sds_cat_utf8(s, msg->dev_vendor, flb_sds_len(msg->dev_vendor),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->dev_product)
    {
        tmp = flb_sds_cat_utf8(s, msg->dev_product, flb_sds_len(msg->dev_product),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->dev_version)
    {
        tmp = flb_sds_cat_utf8(s, msg->dev_version, flb_sds_len(msg->dev_version),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->dev_event_cid)
    {
        tmp = flb_sds_cat_utf8(s, msg->dev_event_cid, flb_sds_len(msg->dev_event_cid),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }
    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->name)
    {
        tmp = flb_sds_cat_utf8(s, msg->name, flb_sds_len(msg->name),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    if (msg->severity)
    {
        tmp = flb_sds_cat_utf8(s, msg->severity, flb_sds_len(msg->severity),
                               esc_cef_msg, sizeof(esc_cef_msg));
        if (!tmp) return NULL;
        *s = tmp;
    }
    tmp = flb_sds_cat(*s, "|", 1);
    if (!tmp) return NULL;
    *s = tmp;

    return *s;
}

static void cef_msg_free(struct cef_msg *msg)
{
    if (msg == NULL) return;

    flb_sds_destroy(msg->ext);
    flb_sds_destroy(msg->host);
    flb_sds_destroy(msg->dev_vendor);
    flb_sds_destroy(msg->dev_product);
    flb_sds_destroy(msg->dev_version);
    flb_sds_destroy(msg->dev_event_cid);
    flb_sds_destroy(msg->name);
    flb_sds_destroy(msg->severity);
}

static flb_sds_t msgpack_to_cef (struct out_cef_config *ctx, flb_sds_t *s,
                                 msgpack_object *o, struct flb_time *tms)
{
    struct cef_msg msg;
    flb_sds_t tmp;
    int ret;

    memset(&msg, 0, sizeof(msg));
    msg.syslog_facility = -1;
    msg.syslog_severity = -1;

    msg.ext = flb_sds_create_size(flb_sds_alloc(*s));
    if (msg.ext == NULL) {
        return NULL;
    }

    ret = msgpack_to_cef_map(ctx->ht_dic, &msg, o);
    if (ret < 0) {
        cef_msg_free(&msg);
        return NULL;
    }

    tmp = cef_cat_prefix (ctx, &msg, tms, s);
    if (!tmp) {
        cef_msg_free(&msg);
        return NULL;
    }
    *s = tmp;

    tmp = flb_sds_cat(*s, msg.ext, flb_sds_len(msg.ext));
    if (!tmp) {
        cef_msg_free(&msg);
        return NULL;
    }
    *s = tmp;

    if (ctx->mode != FLB_CEF_UDP) {
        tmp = flb_sds_cat(*s, "\n", 1);
        if (!tmp) {
            cef_msg_free(&msg);
            return NULL;
        }
        *s = tmp;
    }

    cef_msg_free(&msg);
    return *s;
}

void cb_cef_flush(const void *data, size_t bytes,
                  const char *tag, int tag_len,
                  struct flb_input_instance *i_ins,
                  void *out_context,
                  struct flb_config *config)
{
    struct out_cef_config *ctx = out_context;
    flb_sds_t s;
    flb_sds_t tmp;
    msgpack_unpacked result;
    size_t off = 0;
    size_t prev_off = 0;
    size_t size = 0;
    size_t bytes_sent;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    struct flb_upstream_conn *u_conn;
    int ret;

    if (ctx->mode != FLB_CEF_UDP) {
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_error("[out_cef] no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    msgpack_unpacked_init(&result);

    while (msgpack_unpack_next(&result, data, bytes, &off)) {
        size = off - prev_off;
        prev_off = off;
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map = root.via.array.ptr[1];

        size = (size * 1.4);
        s = flb_sds_create_size(size);
        if (s == NULL) {
            msgpack_unpacked_destroy(&result);
            FLB_OUTPUT_RETURN(FLB_ERROR);
        }

        tmp = msgpack_to_cef(ctx, &s, &map, &tm);
        if (tmp != NULL) {
            s = tmp;
            if (ctx->mode == FLB_CEF_UDP) {
                ret = send(ctx->fd, s, flb_sds_len(s),
                           MSG_DONTWAIT | MSG_NOSIGNAL);
                if (ret == -1) {
                   flb_errno();
                   msgpack_unpacked_destroy(&result);
                   flb_sds_destroy(s);
                   FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
            else {
                ret = flb_io_net_write(u_conn,
                                       s, flb_sds_len(s), &bytes_sent);
                if (ret == -1) {
                    flb_errno();
                    flb_upstream_conn_release(u_conn);
                    msgpack_unpacked_destroy(&result);
                    flb_sds_destroy(s);
                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
        }
        else {
            flb_error("[out_cef] error encoding to CEF");
        }

        flb_sds_destroy(s);
    }

    msgpack_unpacked_destroy(&result);

    if (ctx->mode != FLB_CEF_UDP) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

int cb_cef_init(struct flb_output_instance *ins, struct flb_config *config,
                 void *data)
{
    struct out_cef_config *ctx = NULL;
    int ret;
    char *tmp;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct out_cef_config));
    if (!ctx) {
        flb_errno();
        return -1;
    }

    ret = cef_settings(ins, ctx);
    if (ret < 0) {
        cef_ht_destroy(ctx->ht_dic);
        flb_free(ctx);
        return -1;
    }

    ctx->fd = -1;
    if (ctx->mode == FLB_CEF_UDP) {
        ctx->fd = flb_net_udp_connect(ins->host.name, ins->host.port);
        if (ctx->fd < 0) {
            cef_ht_destroy(ctx->ht_dic);
            flb_free(ctx);
            return -1;
        }
    }
    else {
        int io_flags = FLB_IO_TCP;

        if (ctx->mode == FLB_CEF_TLS) {
            io_flags = FLB_IO_TLS;
        }

        if (ins->host.ipv6 == FLB_TRUE) {
            io_flags |= FLB_IO_IPV6;
        }

        ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                             io_flags, (void *) &ins->tls);
        if (!(ctx->u)) {
            cef_ht_destroy(ctx->ht_dic);
            flb_free(ctx);
            return -1;
        }
    }

    tmp = getenv("HOSTNAME");
    if (!tmp) {
        char hostname[256];
        gethostname(hostname, 256);
        cef_hostname = flb_strdup(hostname);
        cef_hostname_len = strlen(cef_hostname);
    }
    else {
        cef_hostname = flb_strdup(tmp);
        cef_hostname_len = strlen(cef_hostname);
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);
    return 0;
}

int cb_cef_exit(void *data, struct flb_config *config)
{
    struct out_cef_config *ctx = data;

    if (ctx == NULL) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->fd >= 0) {
        close(ctx->fd);
    }

    if (ctx->ht_dic) {
        cef_ht_destroy(ctx->ht_dic);
    }

    flb_free(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_cef_plugin = {
    .name           = "cef",
    .description    = "CEF Output",
    .cb_init        = cb_cef_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_cef_flush,
    .cb_exit        = cb_cef_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
