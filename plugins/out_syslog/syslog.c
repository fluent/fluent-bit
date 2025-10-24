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

#include <fluent-bit/flb_output_plugin.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_network.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_kv.h>
#include <fluent-bit/flb_pack.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_log_event_decoder.h>
#include <fluent-bit/flb_record_accessor.h>
#include <fluent-bit/flb_ra_key.h>

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
    int len;
    struct tm tm;
    flb_sds_t tmp;
    uint8_t prival;

    if (msg->message && msg->message[0] == '<') {
        len = flb_sds_len(msg->message);
        tmp = flb_sds_cat(*s, msg->message, len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
        return *s;
    }

    prival = (msg->facility << 3) + msg->severity;

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
        len = flb_sds_len(msg->hostname);
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
        len = flb_sds_len(msg->appname);
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
        len = flb_sds_len(msg->procid);
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
        len = flb_sds_len(msg->msgid);
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
        len = flb_sds_len(msg->message);
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
    int len;
    struct tm tm;
    flb_sds_t tmp;
    uint8_t prival;

    if (msg->message && msg->message[0] == '<') {
        len = flb_sds_len(msg->message);
        tmp = flb_sds_cat(*s, msg->message, len);
        if (!tmp) {
            return NULL;
        }
        *s = tmp;
        return *s;
    }

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

static flb_sds_t msgpack_to_sd(struct flb_syslog *ctx,
                               flb_sds_t *s, const char *sd, int sd_len,
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
    if (ctx->allow_longer_sd_id != FLB_TRUE && sd_len > 32) {
        /*
         * RFC5424 defines
         *   SD-NAME         = 1*32PRINTUSASCII
         *                     ; except '=', SP, ']', %d34 (")
         *
         * https://www.rfc-editor.org/rfc/rfc5424#section-6
         */
        sd_len = 32;
    }
    tmp = flb_sds_cat(*s, sd, sd_len);
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
            int key_len = 0;
            const char *val = NULL;
            int val_len = 0;

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
            if (ctx->allow_longer_sd_id != FLB_TRUE && key_len > 32 ) {
                /*
                 * RFC5424 defines
                 *   PARAM-NAME      = SD-NAME
                 *   SD-NAME         = 1*32PRINTUSASCII
                 *                     ; except '=', SP, ']', %d34 (")
                 *
                 * https://www.rfc-editor.org/rfc/rfc5424#section-6
                 */
                key_len = 32;
            }
            tmp = flb_sds_cat(*s, key, key_len);
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

/* Use val array to return its string value unless its a string and return its pointer */
static void extract_value_from_ra_result(struct flb_ra_value *rval, char** val,
                                         int val_size, int *val_len) {
    if (rval->o.type == MSGPACK_OBJECT_BOOLEAN) {
        *val = rval->o.via.boolean ? "true" : "false";
        *val_len = rval->o.via.boolean ? 4 : 5;
    }
    else if (rval->o.type == MSGPACK_OBJECT_POSITIVE_INTEGER) {
        *val_len = snprintf(*val, val_size,
                            "%" PRIu64, rval->o.via.u64);
    }
    else if (rval->o.type == MSGPACK_OBJECT_NEGATIVE_INTEGER) {
        *val_len = snprintf(*val, val_size,
                            "%" PRId64, rval->o.via.i64);
    }
    else if (rval->o.type == MSGPACK_OBJECT_FLOAT) {
        *val_len = snprintf(*val, val_size,
                            "%f", rval->o.via.f64);
    }
    else if (rval->o.type == MSGPACK_OBJECT_STR) {
        /* String value */
        *val     = rval->o.via.str.ptr;
        *val_len = rval->o.via.str.size;
    }
    else if (rval->o.type == MSGPACK_OBJECT_BIN) {
        /* Bin value */
        *val     = rval->o.via.bin.ptr;
        *val_len = rval->o.via.bin.size;
    }
    else {
        *val = NULL;
        *val_len = 0;
    }
}

static int msgpack_to_syslog(struct flb_syslog *ctx, msgpack_object *o,
                             struct syslog_msg *msg)
{
    int i;
    struct mk_list *head;
    struct mk_list *tmp;
    struct flb_syslog_sd_key *sd_key_item;
    struct flb_ra_value *rval = NULL;
    char *val = NULL;
    int val_len = 0;
    char temp[48] = {0};

    if (o == NULL) {
        return -1;
    }

    if (ctx->ra_severity_key != NULL) {
        if (msg->severity == -1) {
            rval = flb_ra_get_value_object(ctx->ra_severity_key, *o);
            if (rval) {
                val = temp;
                extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
                if (val != NULL) {
                    if ((val_len == 1) && (val[0] >= '0' && val[0] <= '7')) {
                        msg->severity = val[0]-'0';
                    }
                    else {
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
                flb_ra_key_value_destroy(rval);
            }
        }
    }
    if (ctx->ra_facility_key != NULL) {
        if (msg->facility == -1) {
            rval = flb_ra_get_value_object(ctx->ra_facility_key, *o);
            if (rval) {
                val = temp;
                extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
                if (val != NULL) {
                    if ((val_len == 1) && (val[0] >= '0' && val[0] <= '9')) {
                        msg->facility = val[0]-'0';
                    }
                    else if ((val_len == 2) &&
                             (val[0] >= '0' && val[0] <= '2') &&
                             (val[1] >= '0' && val[1] <= '9')) {
                        msg->facility = (val[0]-'0')*10;
                        msg->facility += (val[1]-'0');
                        if (!((msg->facility >= 0) && (msg->facility <=23))) {
                            flb_plg_warn(ctx->ins, "invalid facility: '%.*s'",
                                         val_len, val);
                            msg->facility= -1;
                        }
                    }
                    else {
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
                flb_ra_key_value_destroy(rval);
            }
        }
    }

    if (ctx->ra_hostname_key != NULL) {
        rval = flb_ra_get_value_object(ctx->ra_hostname_key, *o);
        if (rval) {
            val = temp;
            extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
            if (!msg->hostname && val != NULL) {
                msg->hostname = flb_sds_create_len(val, val_len);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    if (ctx->ra_appname_key != NULL) {
        rval = flb_ra_get_value_object(ctx->ra_appname_key, *o);
        if (rval) {
            val = temp;
            extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
            if (!msg->appname && val != NULL) {
                msg->appname = flb_sds_create_len(val, val_len);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    if (ctx->ra_procid_key != NULL) {
        rval = flb_ra_get_value_object(ctx->ra_procid_key, *o);
        if (rval) {
            val = temp;
            extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
            if (!msg->procid && val != NULL) {
                msg->procid = flb_sds_create_len(val, val_len);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    if (ctx->ra_msgid_key != NULL) {
        rval = flb_ra_get_value_object(ctx->ra_msgid_key, *o);
        if (rval) {
            val = temp;
            extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
            if (!msg->msgid && val != NULL) {
                msg->msgid = flb_sds_create_len(val, val_len);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    if (ctx->ra_message_key != NULL) {
        rval = flb_ra_get_value_object(ctx->ra_message_key, *o);
        if (rval) {
            val = temp;
            extract_value_from_ra_result(rval, &val, sizeof(temp) - 1, &val_len);
            if (!msg->message && val != NULL) {
                msg->message = flb_sds_create_len(val, val_len);
            }
            flb_ra_key_value_destroy(rval);
        }
    }

    if (ctx->ra_sd_keys != NULL) {
        mk_list_foreach_safe(head, tmp, ctx->ra_sd_keys) {
            sd_key_item = mk_list_entry(head, struct flb_syslog_sd_key, _head);
            rval = flb_ra_get_value_object(sd_key_item->ra_sd_key, *o);
            if (rval) {
                if (rval->o.type == MSGPACK_OBJECT_MAP) {
                    msgpack_to_sd(ctx, &(msg->sd), sd_key_item->key_normalized,
                        flb_sds_len(sd_key_item->key_normalized), &rval->o);
                }
                flb_ra_key_value_destroy(rval);
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
            msg.severity = ctx->severity_preset;
        }
        if (msg.facility  < 0) {
            msg.facility = ctx->facility_preset;
        }
        if (msg.hostname == NULL && ctx->hostname_preset) {
            msg.hostname = flb_sds_create(ctx->hostname_preset);
        }
        if (msg.appname == NULL && ctx->appname_preset) {
            msg.appname = flb_sds_create(ctx->appname_preset);
        }
        if (msg.procid == NULL && ctx->procid_preset) {
            msg.procid = flb_sds_create(ctx->procid_preset);
        }
        if (msg.msgid == NULL && ctx->msgid_preset) {
            msg.msgid = flb_sds_create(ctx->msgid_preset);
        }

        if (ctx->parsed_format == FLB_SYSLOG_RFC3164) {
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

        if (ctx->parsed_mode != FLB_SYSLOG_UDP) {
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

static void cb_syslog_flush(struct flb_event_chunk *event_chunk,
                            struct flb_output_flush *out_flush,
                            struct flb_input_instance *i_ins,
                            void *out_context,
                            struct flb_config *config)
{
    struct flb_syslog *ctx = out_context;
    flb_sds_t s;
    flb_sds_t tmp;
    size_t bytes_sent;
    msgpack_object map;
    struct flb_connection *u_conn = NULL;
    int ret;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;

    if (ctx->parsed_mode != FLB_SYSLOG_UDP) {
        u_conn = flb_upstream_conn_get(ctx->u);

        if (!u_conn) {
            flb_plg_error(ctx->ins, "no upstream connections available");
            FLB_OUTPUT_RETURN(FLB_RETRY);
        }
    }

    s = flb_sds_create_size(ctx->maxsize);
    if (s == NULL) {
        FLB_OUTPUT_RETURN(FLB_ERROR);
    }

    ret = flb_log_event_decoder_init(&log_decoder,
                                     (char *) event_chunk->data,
                                     event_chunk->size);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(s);

        FLB_OUTPUT_RETURN(FLB_RETRY);
    }

    while ((ret = flb_log_event_decoder_next(
                    &log_decoder,
                    &log_event)) == FLB_EVENT_DECODER_SUCCESS) {
        map = *log_event.body;

        flb_sds_len_set(s, 0);

        tmp = syslog_format(ctx, &map, &s, &log_event.timestamp);
        if (tmp != NULL) {
            s = tmp;
            if (ctx->parsed_mode == FLB_SYSLOG_UDP) {
                ret = send(ctx->fd, s, flb_sds_len(s), MSG_DONTWAIT | MSG_NOSIGNAL);
                if (ret == -1) {
                    flb_log_event_decoder_destroy(&log_decoder);
                    flb_sds_destroy(s);

                    FLB_OUTPUT_RETURN(FLB_RETRY);
                }
            }
            else {
                ret = flb_io_net_write(u_conn,
                                       s, flb_sds_len(s), &bytes_sent);
                if (ret == -1) {
                    flb_errno();
                    flb_log_event_decoder_destroy(&log_decoder);
                    flb_upstream_conn_release(u_conn);
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
    flb_log_event_decoder_destroy(&log_decoder);

    if (ctx->parsed_mode != FLB_SYSLOG_UDP) {
        flb_upstream_conn_release(u_conn);
    }

    FLB_OUTPUT_RETURN(FLB_OK);
}

static int cb_syslog_init(struct flb_output_instance *ins, struct flb_config *config,
                          void *data)
{
    int io_flags;
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
        if (ctx->parsed_format == FLB_SYSLOG_RFC3164) {
            ctx->maxsize = RFC3164_MAXSIZE;
        }
        else {
            ctx->maxsize = RFC5424_MAXSIZE;
        }
    }

    ctx->fd = -1;
    if (ctx->parsed_mode == FLB_SYSLOG_UDP) {
        ctx->fd = flb_net_udp_connect(ins->host.name, ins->host.port,
                                      ins->net_setup.source_address);
        if (ctx->fd < 0) {
            flb_syslog_config_destroy(ctx);
            return -1;
        }
    }
    else {

        /* use TLS ? */
        if (ins->use_tls == FLB_TRUE) {
            io_flags = FLB_IO_TLS;
        }
        else {
            io_flags = FLB_IO_TCP;
        }

        if (ins->host.ipv6 == FLB_TRUE) {
            io_flags |= FLB_IO_IPV6;
        }

        ctx->u = flb_upstream_create(config, ins->host.name, ins->host.port,
                                             io_flags, ins->tls);
        if (!(ctx->u)) {
            flb_syslog_config_destroy(ctx);
            return -1;
        }
        flb_output_upstream_set(ctx->u, ins);
    }

    /* Set the plugin context */
    flb_output_set_context(ins, ctx);

    flb_plg_info(ctx->ins, "setup done for %s:%i (TLS=%s)",
                 ins->host.name, ins->host.port,
                 ins->use_tls ? "on" : "off");
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


/* for testing */
static int cb_syslog_format_test(struct flb_config *config,
                                 struct flb_input_instance *ins,
                                 void *plugin_context,
                                 void *flush_ctx,
                                 int event_type,
                                 const char *tag, int tag_len,
                                 const void *data, size_t bytes,
                                 void **out_data, size_t *out_size)
{
    struct flb_syslog *ctx = plugin_context;
    flb_sds_t tmp;
    flb_sds_t s;
    msgpack_object map;
    struct flb_log_event_decoder log_decoder;
    struct flb_log_event log_event;
    int ret;

    s = flb_sds_create_size(ctx->maxsize);
    if (s == NULL) {
        flb_error("flb_sds_create_size failed");
        return -1;
    }

    ret = flb_log_event_decoder_init(&log_decoder, (char *) data, bytes);

    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_plg_error(ctx->ins,
                      "Log event decoder initialization error : %d", ret);

        flb_sds_destroy(s);

        return -1;
    }

    flb_log_event_decoder_next(&log_decoder, &log_event);
    ret = flb_log_event_decoder_get_last_result(&log_decoder);
    if (ret != FLB_EVENT_DECODER_SUCCESS) {
        flb_error("msgpack_unpack_next failed");

        flb_log_event_decoder_destroy(&log_decoder);

        return -1;
    }

    map = *log_event.body;
    flb_sds_len_set(s, 0);
    tmp = syslog_format(ctx, &map, &s, &log_event.timestamp);

    flb_log_event_decoder_destroy(&log_decoder);

    if (tmp == NULL) {
        flb_error("syslog_fromat returns NULL");
        return -1;
    }

    *out_data = tmp;
    *out_size = flb_sds_len(tmp);

    return 0;
}

/* Configuration properties map */
static struct flb_config_map config_map[] = {
    {
     FLB_CONFIG_MAP_STR, "mode", "udp",
     0, FLB_TRUE, offsetof(struct flb_syslog, mode),
     "Set the desired transport type, the available options are tcp and udp. If you need to "
     "use a TLS secure channel, choose 'tcp' mode here and enable the 'tls' option separately."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_format", "rfc5424",
     0, FLB_TRUE, offsetof(struct flb_syslog, format),
     "Specify the Syslog protocol format to use, the available options are rfc3164 "
     "and rfc5424."
    },

    {
     FLB_CONFIG_MAP_SIZE, "syslog_maxsize", "0",
     0, FLB_TRUE, offsetof(struct flb_syslog, maxsize),
     "Set the maximum size allowed per message. The value must be only integers "
     "representing the number of bytes allowed. If no value is provided, the "
     "default size is set depending of the protocol version specified by "
     "syslog_format , rfc3164 sets max size to 1024 bytes, while rfc5424 sets "
     "the size to 2048 bytes."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_severity_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, severity_key),
     "Specify the name of the key from the original record that contains the Syslog "
     "severity number. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_INT, "syslog_severity_preset", "6",
     0, FLB_TRUE, offsetof(struct flb_syslog, severity_preset),
     "Specify the preset severity number. It must be 0-7. "
     " This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_facility_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, facility_key),
     "Specify the name of the key from the original record that contains the Syslog "
     "facility number. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_INT, "syslog_facility_preset", "1",
     0, FLB_TRUE, offsetof(struct flb_syslog, facility_preset),
     "Specify the preset facility number. It must be 0-23. "
     " This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_hostname_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, hostname_key),
     "Specify the key name from the original record that contains the hostname that "
     "generated the message. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_hostname_preset", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, hostname_preset),
     "Specify the preset hostname. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_appname_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, appname_key),
     "Specify the key name from the original record that contains the application "
     "name that generated the message. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_appname_preset", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, appname_preset),
     "Specify the preset appname. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_procid_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, procid_key),
     "Specify the key name from the original record that contains the Process ID "
     "that generated the message. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_procid_preset", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, procid_preset),
     "Specify the preset procid.  This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_msgid_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, msgid_key),
     "Specify the key name from the original record that contains the Message ID "
     "associated to the message. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_msgid_preset", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, msgid_preset),
     "Specify the preset msgid. This configuration is optional."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_sd_key", NULL,
     FLB_CONFIG_MAP_MULT, FLB_TRUE, offsetof(struct flb_syslog, sd_keys),
     "Specify the key name from the original record that contains the "
     "Structured Data (SD) content. If set, the value of the key must be a map."
     "This option can be set multiple times."
    },

    {
     FLB_CONFIG_MAP_STR, "syslog_message_key", NULL,
     0, FLB_TRUE, offsetof(struct flb_syslog, message_key),
     "Specify the key name that contains the message to deliver. Note that if "
     "this property is mandatory, otherwise the message will be empty."
    },

    {
     FLB_CONFIG_MAP_BOOL, "allow_longer_sd_id", "false",
     0, FLB_TRUE, offsetof(struct flb_syslog, allow_longer_sd_id),
     "If true, Fluent-bit allows SD-ID that is longer than 32 characters. "
     "Such long SD-ID violates RFC 5424."
    },

    /* EOF */
    {0}
};

/* Plugin reference */
struct flb_output_plugin out_syslog_plugin = {
    .name           = "syslog",
    .description    = "Syslog",
    .cb_init        = cb_syslog_init,
    .cb_pre_run     = NULL,
    .cb_flush       = cb_syslog_flush,
    .cb_exit        = cb_syslog_exit,

    /* Configuration */
    .config_map     = config_map,

    /* for testing */
    .test_formatter.callback = cb_syslog_format_test,

    /* Plugin flags */
    .flags          = FLB_OUTPUT_NET | FLB_IO_OPT_TLS,
};
