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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>

#include "syslog_conf.h"

#ifndef MSG_DONTWAIT
    #define MSG_DONTWAIT 0
#endif

#ifndef MSG_NOSIGNAL
    #define MSG_NOSIGNAL 0
#endif

#define RFC5424_MAXSIZE 2048
#define RFC3164_MAXSIZE 1024

struct syslog_msg {
    int severity;
    int facility;
    flb_sds_t hostname;
    flb_sds_t appname;
    flb_sds_t procid;
    flb_sds_t msgid;
    flb_sds_t sd;
    flb_sds_t message;
};

static const char *rfc3164_mon[] = {"Jan", "Feb", "Mar", "Apr",
                                    "May", "Jun", "Jul", "Aug",
                                    "Sep", "Oct", "Nov", "Dec"};

static struct {
    char *name;
    int len;
    int value;
} syslog_severity[] =  {
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
} syslog_facility[] = {
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

/* '"', '\' ']' */
static char rfc5424_sp_value[256] = {
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0,'"', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0,'\\',']', 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0,
    0, 0, 0 , 0, 0, 0, 0, 0, 0, 0, 0, 0, 0  , 0 , 0, 0
};

/* '=', ' ', ']', '"' */
static char rfc5424_sp_name[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static flb_sds_t syslog_rfc5424(flb_sds_t *s, struct flb_time *tms,
                                struct syslog_msg *msg)
{
    struct tm tm;
    flb_sds_t tmp;
    uint8_t prival;

    prival =  (msg->facility << 3) + msg->severity;

    if (gmtime_r(&(tms->tm.tv_sec), &tm) == NULL) {
        return NULL;
    }
    tmp = flb_sds_printf(s, "<%i>%i %d-%02d-%02dT%02d:%02d:%02d.%06"PRIu64"Z ",
                            prival, 1, tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                            tm.tm_hour, tm.tm_min, tm.tm_sec,
                            (uint64_t) tms->tm.tv_nsec/1000);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->hostname) {
        int len = flb_sds_len(msg->hostname);
        tmp = flb_sds_cat(*s, msg->hostname, len > 255 ? 255 : len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "-" , 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, " ", 1);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->appname) {
        int len = flb_sds_len(msg->appname);
        tmp = flb_sds_cat(*s, msg->appname, len > 48 ? 48 : len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "-" , 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, " ", 1);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->procid) {
        int len = flb_sds_len(msg->procid);
        tmp = flb_sds_cat(*s, msg->procid, len > 128 ? 128 : len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "-" , 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, " ", 1);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->msgid) {
        int len = flb_sds_len(msg->msgid);
        tmp = flb_sds_cat(*s, msg->msgid, len > 32 ? 32 : len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "-" , 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    tmp = flb_sds_cat(*s, " ", 1);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->sd) {
        tmp = flb_sds_cat(*s, msg->sd, flb_sds_len(msg->sd));
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }
    else {
        tmp = flb_sds_cat(*s, "-" , 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    if (msg->message) {
        int len = flb_sds_len(msg->message);
        tmp = flb_sds_cat(*s, " \xef\xbb\xbf", 4);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
        tmp = flb_sds_cat(*s, msg->message, len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    return *s;
}

static flb_sds_t syslog_rfc3164 (flb_sds_t *s, struct flb_time *tms,
                                 struct syslog_msg *msg)
{
    struct tm tm;
    flb_sds_t tmp;
    uint8_t prival;

    prival =  (msg->facility << 3) + msg->severity;

    if (gmtime_r(&(tms->tm.tv_sec), &tm) == NULL) {
        return NULL;
    }

    tmp = flb_sds_printf(s, "<%i>%s %2d %02d:%02d:%02d ", prival,
                            rfc3164_mon[tm.tm_mon], tm.tm_mday,
                            tm.tm_hour, tm.tm_min, tm.tm_sec);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    if (msg->hostname) {
        tmp = flb_sds_cat(*s, msg->hostname, flb_sds_len(msg->hostname));
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
        tmp = flb_sds_cat(*s, " ", 1);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    if (msg->appname) {
        tmp = flb_sds_cat(*s, msg->appname, flb_sds_len(msg->appname));
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
        if (msg->procid) {
            tmp = flb_sds_cat(*s, "[" , 1);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;
            tmp = flb_sds_cat(*s, msg->procid, flb_sds_len(msg->procid));
            if (!tmp) {
                return NULL;
            }
            *s = tmp;
            tmp = flb_sds_cat(*s, "]" , 1);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;
        }
        tmp = flb_sds_cat(*s, ": " , 2);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    if (msg->message) {
        tmp = flb_sds_cat(*s, msg->message, flb_sds_len(msg->message));
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
    }

    return *s;
}

static flb_sds_t msgpack_to_sd(flb_sds_t *s, const char *sd, int sd_len,
                               msgpack_object *o)
{
    flb_sds_t tmp;
    int i;
    int loop;
    int n, start_len, end_len;

    if (*s == NULL) {
        *s = flb_sds_create_size(512);
        if (*s == NULL) {
            return NULL;
        }
    }

    tmp = flb_sds_cat(*s, "[" , 1);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    start_len = flb_sds_len(*s);
    tmp = flb_sds_cat(*s, sd, sd_len > 32 ? 32 : sd_len);
    if (!tmp) {
        return NULL;
    }
    *s = tmp;

    end_len = flb_sds_len(*s);
    for(n=start_len; n < end_len; n++) {
        if (!rfc5424_sp_name[(unsigned char)(*s)[n]]) {
            (*s)[n] = '_';
        }
    }

    loop = o->via.map.size;
    if (loop != 0) {
        msgpack_object_kv *p = o->via.map.ptr;
        for (i = 0; i < loop; i++) {
            char temp[48] = {0};
            const char *key = NULL;
            int key_len;
            const char *val = NULL;
            int val_len;

            msgpack_object *k = &p[i].key;
            msgpack_object *v = &p[i].val;

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR) {
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key = k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = k->via.bin.ptr;
                key_len = k->via.bin.size;
            }

            if (v->type == MSGPACK_OBJECT_BOOLEAN) {
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
                val     = v->via.str.ptr;
                val_len = v->via.str.size;
            }
            else if (v->type == MSGPACK_OBJECT_BIN) {
                /* Bin value */
                val     = v->via.bin.ptr;
                val_len = v->via.bin.size;
            }

            if (!val || !key) {
                continue;
            }

            tmp = flb_sds_cat(*s, " " , 1);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;

            start_len = flb_sds_len(*s);
            tmp = flb_sds_cat(*s, key, key_len > 32 ? 32 : key_len);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;

            end_len = flb_sds_len(*s);
            for(n=start_len; n < end_len; n++) {
                if (!rfc5424_sp_name[(unsigned char)(*s)[n]]) {
                    (*s)[n] = '_';
                }
            }

            tmp = flb_sds_cat(*s, "=\"" , 2);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;

            tmp = flb_sds_cat_esc(*s, val , val_len,
                                  rfc5424_sp_value, sizeof(rfc5424_sp_value));
            if (!tmp) {
                return NULL;
            }
            *s = tmp;

            tmp = flb_sds_cat(*s, "\"" , 1);
            if (!tmp) {
                return NULL;
            }
            *s = tmp;
        }
    }

    tmp = flb_sds_cat(*s, "]" , 1);
    if (!tmp) return NULL;
    *s = tmp;

    return *s;
}

static int msgpack_to_syslog(struct flb_syslog *ctx, msgpack_object *o,
                             struct syslog_msg *msg)
{
    int i,n;
    int loop;

    if (o == NULL) {
        return -1;
    }

    loop = o->via.map.size;
    if (loop != 0) {
        msgpack_object_kv *p = o->via.map.ptr;

        for (i = 0; i < loop; i++) {
            char temp[48] = {0};
            const char *key = NULL;
            int key_len;
            const char *val = NULL;
            int val_len;

            msgpack_object *k = &p[i].key;
            msgpack_object *v = &p[i].val;

            if (k->type != MSGPACK_OBJECT_BIN && k->type != MSGPACK_OBJECT_STR){
                continue;
            }

            if (k->type == MSGPACK_OBJECT_STR) {
                key = k->via.str.ptr;
                key_len = k->via.str.size;
            }
            else {
                key = k->via.bin.ptr;
                key_len = k->via.bin.size;
            }

            if (v->type == MSGPACK_OBJECT_MAP) {
                if (ctx->nsd > 0) {
                    for (n = 0 ; n < ctx->nsd ; n++) {
                        if ((key_len == flb_sds_len(ctx->sd_key[n])) &&
                            !strncmp(key, ctx->sd_key[n], flb_sds_len(ctx->sd_key[n]))) {
                            msgpack_to_sd (&(msg->sd), key, key_len, v);
                            break;
                        }
                    }
                }
                continue;
            }

            if (v->type == MSGPACK_OBJECT_BOOLEAN) {
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
                val     = v->via.str.ptr;
                val_len = v->via.str.size;
            }
            else if (v->type == MSGPACK_OBJECT_BIN) {
                /* Bin value */
                val     = v->via.bin.ptr;
                val_len = v->via.bin.size;
            }

            if (!val || !key) {
              continue;
            }

            if ((ctx->severity_key != NULL) &&
                (key_len == flb_sds_len(ctx->severity_key)) &&
                !strncmp(key, ctx->severity_key, flb_sds_len(ctx->severity_key))) {
                if (msg->severity == -1) {
                    if ((val_len == 1) && (val[0] >= '0' && val[0] <= '7')) {
                        msg->severity = val[0]-'0';
                    }
                    else {
                        int i;
                        for (i=0; syslog_severity[i].name != NULL; i++) {
                            if ((syslog_severity[i].len == val_len) &&
                                (!strncasecmp(syslog_severity[i].name, val, val_len))) {
                                msg->severity = syslog_severity[i].value;
                            }
                        }
                        if (!syslog_severity[i].name) {
                            flb_plg_warn(ctx->ins, "invalid severity: '%.*s'",
                                         val_len, val);
                        }
                    }
                }
            }
            else if ((ctx->facility_key != NULL) &&
                     (key_len == flb_sds_len(ctx->facility_key)) &&
                     !strncmp(key, ctx->facility_key, flb_sds_len(ctx->facility_key))) {
                if (msg->facility == -1) {
                    if ((val_len == 1) && (val[0] >= '0' && val[0] <= '9')) {
                        msg->facility = val[0]-'0';
                    }
                    else if ((val_len == 2) &&
                             (val[0] >= '0' && val[0] <= '2') &&
                             (val[1] >= '0' && val[1] <= '9')) {
                        msg->facility = (val[0]-'0')*10;
                        msg->facility += (val[1]-'0');
                        if (!((msg->facility >= 0) &&
                              (msg->facility <=23))) {
                            flb_plg_warn(ctx->ins, "invalid facility: '%.*s'",
                                         val_len, val);
                            msg->facility= -1;
                        }
                    }
                    else {
                        int i;
                        for (i=0; syslog_facility[i].name != NULL; i++) {
                            if ((syslog_facility[i].len == val_len) &&
                                (!strncasecmp(syslog_facility[i].name, val, val_len))) {
                                msg->facility = syslog_facility[i].value;
                            }
                        }
                        if (!syslog_facility[i].name) {
                            flb_plg_warn(ctx->ins, "invalid facility: '%.*s'",
                                         val_len, val);
                        }
                    }
                }
            }
            else if ((ctx->hostname_key != NULL) &&
                     (key_len == flb_sds_len(ctx->hostname_key)) &&
                     !strncmp(key, ctx->hostname_key, flb_sds_len(ctx->hostname_key))) {
                if (!msg->hostname) {
                   msg->hostname = flb_sds_create_len(val, val_len);
                }
            }
            else if ((ctx->appname_key != NULL) &&
                     (key_len == flb_sds_len(ctx->appname_key)) &&
                     !strncmp(key, ctx->appname_key, flb_sds_len(ctx->appname_key))) {
                if (!msg->appname) {
                   msg->appname = flb_sds_create_len(val, val_len);
                }
            }
            else if ((ctx->procid_key != NULL) &&
                     (key_len == flb_sds_len(ctx->procid_key)) &&
                     !strncmp(key, ctx->procid_key, flb_sds_len(ctx->procid_key))) {
                if (!msg->procid) {
                   msg->procid = flb_sds_create_len(val, val_len);
                }
            }
            else if ((ctx->msgid_key != NULL) &&
                     (key_len == flb_sds_len(ctx->msgid_key)) &&
                     !strncmp(key, ctx->msgid_key, flb_sds_len(ctx->msgid_key))) {
                if (!msg->msgid) {
                   msg->msgid = flb_sds_create_len(val, val_len);
                }
            }
            else if ((ctx->message_key != NULL) &&
                     (key_len == flb_sds_len(ctx->message_key)) &&
                     !strncmp(key, ctx->message_key, flb_sds_len(ctx->message_key))) {
                if (!msg->message) {
                   msg->message = flb_sds_create_len(val, val_len);
                }
            }
        }
    }

    return 0;
}

static flb_sds_t syslog_format(struct flb_syslog *ctx, msgpack_object *o,
                               flb_sds_t *s, struct flb_time *tm)
{
    struct syslog_msg msg;
    flb_sds_t tmp;
    flb_sds_t ret_sds;
    int ret;

    msg.severity = -1;
    msg.facility = -1;
    msg.hostname = NULL;
    msg.appname = NULL;
    msg.procid = NULL;
    msg.msgid = NULL;
    msg.sd = NULL;
    msg.message = NULL;

    ret = msgpack_to_syslog(ctx, o, &msg);
    if (!ret) {
        if (msg.severity < 0) {
            msg.severity = 6;
        }

        if (msg.facility  < 0) {
            msg.facility = 1;
        }

        if (ctx->format == FLB_SYSLOG_RFC3164) {
            tmp = syslog_rfc3164(s, tm, &msg);
        }
        else {
            tmp = syslog_rfc5424(s, tm, &msg);
        }

        if (!tmp) {
            ret_sds = NULL;
            goto clean;
        }
        *s = tmp;

        if (flb_sds_len(*s) > ctx->maxsize) {
            flb_sds_len_set(*s, ctx->maxsize);
        }

        if (ctx->mode != FLB_SYSLOG_UDP) {
            tmp = flb_sds_cat(*s, "\n", 1);
            if (!tmp) {
                ret_sds = NULL;
                goto clean;
            }
            *s = tmp;
        }
    }
    else {
        ret_sds = NULL;
        goto clean;
    }

    ret_sds = *s;
clean:
    flb_sds_destroy(msg.hostname);
    flb_sds_destroy(msg.appname);
    flb_sds_destroy(msg.procid);
    flb_sds_destroy(msg.msgid);
    flb_sds_destroy(msg.sd);
    flb_sds_destroy(msg.message);

    return ret_sds;
}

static void cb_syslog_flush(const void *data, size_t bytes,
                   const char *tag, int tag_len,
                   struct flb_input_instance *i_ins,
                   void *out_context,
                   struct flb_config *config)
{
    struct flb_syslog *ctx = out_context;
    flb_sds_t s;
    flb_sds_t tmp;
    msgpack_unpacked result;
    size_t off = 0;
    size_t bytes_sent;
    msgpack_object root;
    msgpack_object map;
    msgpack_object *obj;
    struct flb_time tm;
    struct flb_upstream_conn *u_conn;
    int ret;

    if (ctx->mode != FLB_SYSLOG_UDP) {
        u_conn = flb_upstream_conn_get(ctx->u);
        if (!u_conn) {
            flb_plg_error(ctx->ins, "no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    msgpack_unpacked_init(&result);

    s = flb_sds_create_size(ctx->maxsize);
    if (s == NULL) {
        msgpack_unpacked_destroy(&result);
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    while (msgpack_unpack_next(&result, data, bytes, &off) == MSGPACK_UNPACK_SUCCESS) {
        if (result.data.type != MSGPACK_OBJECT_ARRAY) {
            continue;
        }

        root = result.data;
        if (root.via.array.size != 2) {
            continue;
        }

        flb_time_pop_from_msgpack(&tm, &result, &obj);
        map = root.via.array.ptr[1];

        flb_sds_len_set(s, 0);

        tmp = syslog_format(ctx, &map, &s, &tm);
        if (tmp != NULL) {
            s = tmp;
            if (ctx->mode == FLB_SYSLOG_UDP) {
                ret = send(ctx->fd, s, flb_sds_len(s), MSG_DONTWAIT | MSG_NOSIGNAL);
                if (ret == -1) {
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
            flb_plg_error(ctx->ins, "error formating message");
        }
    }

    flb_sds_destroy(s);

    msgpack_unpacked_destroy(&result);

    if (ctx->mode != FLB_SYSLOG_UDP) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_syslog_init(struct flb_output_instance *ins, struct flb_config *config,
                          void *data)
{
    struct flb_syslog *ctx = NULL;

    /* Set default network configuration */
    flb_output_net_default("127.0.0.1", 514, ins);

    /* Create config context */
    ctx = flb_syslog_config_create(ins, config);
    if (ctx == NULL) {
        flb_plg_error(ins, "error configuring plugin");
        return -1;
    }

    if (ctx->maxsize < 0) {
        if (ctx->format == FLB_SYSLOG_RFC3164) {
            ctx->maxsize = RFC3164_MAXSIZE;
        }
        else {
            ctx->maxsize = RFC5424_MAXSIZE;
        }
    }

    ctx->fd = -1;
    if (ctx->mode == FLB_SYSLOG_UDP) {
        ctx->fd = flb_net_udp_connect(ins->host.name, ins->host.port);
        if (ctx->fd < 0) {
            flb_syslog_config_destroy(ctx);
            return -1;
        }
    }
    else {
        int io_flags = FLB_IO_TCP;

        if (ctx->mode == FLB_SYSLOG_TLS) {
            io_flags = FLB_IO_TLS;
        }

        if (ins->host.ipv6 == FLB_TRUE) {
            io_flags |= FLB_IO_IPV6;
        }

        ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                             io_flags, (void *) &ins->tls);
        if (!(ctx->u)) {
            flb_syslog_config_destroy(ctx);
            return -1;
        }
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    flb_plg_info(ctx->ins, "setup done for %s:%i",
                 ins->host.name, ins->host.port);
    return 0;
}

static int cb_syslog_exit(void *data, struct flb_config *config)
{
    struct flb_syslog *ctx = data;

    if (ctx == NULL) {
        return 0;
    }

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->fd > 0) {
        close(ctx->fd);
    }

    flb_syslog_config_destroy(ctx);

    return 0;
}

/* Plugin reference */
struct flb_output_plugin out_syslog_plugin = {
    .name           = "syslog",
    .description    = "Syslog",
    .cb_init        = cb_syslog_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_syslog_flush,
    .cb_exit        = cb_syslog_exit,
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
