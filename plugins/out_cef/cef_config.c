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
#include <fluent-bit/flb_sds.h>

#include "cef.h"
#include "cef_config.h"

static struct cef_dic cef_dic_dft[] = {
{"act",                         "deviceAction",                CEF_STR, 63  },
{"app",                         "applicationProtocol",         CEF_STR, 31  },
{"cat",                         "deviceEventCategory",         CEF_STR, 1023},
{"cnt",                         "baseEventCount",              CEF_INT, 0   },
{"destinationDnsDomain",        "destinationDnsDomain",        CEF_STR, 255 },
{"destinationServiceName",      "destinationServiceName",      CEF_STR, 1023},
{"destinationTranslatedAddress","destinationTranslatedAddress",CEF_IPV4,0   },
{"destinationTranslatedPort",   "destinationTranslatedPort",   CEF_INT, 0   },
{"deviceDirection",             "deviceDirection",             CEF_INT, 0   },
{"deviceDnsDomain",             "deviceDnsDomain",             CEF_STR, 255 },
{"deviceExternalId",            "deviceExternalId",            CEF_STR, 255 },
{"deviceFacility",              "deviceFacility",              CEF_STR, 1023},
{"deviceInboundInterface",      "deviceInboundInterface",      CEF_STR, 128 },
{"deviceNtDomain",              "deviceNtDomain",              CEF_STR, 255 },
{"deviceOutboundInterface",     "deviceOutboundInterface",     CEF_STR, 128 },
{"devicePayloadId",             "devicePayloadId",             CEF_STR, 128 },
{"deviceProcessName",           "deviceProcessName",           CEF_STR, 1023},
{"deviceTranslatedAddress",     "deviceTranslatedAddress",     CEF_IPV4,0   },
{"dhost",                       "destinationHostName",         CEF_STR, 1023},
{"dmac",                        "destinationMacAddress",       CEF_MAC, 0   },
{"dntdom",                      "destinationNtDomain",         CEF_STR, 255 },
{"dpid",                        "destinationProcessId",        CEF_INT, 0   },
{"dpriv",                       "destinationUserPrivileges",   CEF_STR, 1023},
{"dproc",                       "destinationProcessName",      CEF_STR, 1023},
{"dpt",                         "destinationPort",             CEF_INT, 0   },
{"dst",                         "destinationAddress",          CEF_IPV4,0   },
{"dtz",                         "deviceTimeZone",              CEF_STR, 255 },
{"duid",                        "destinationUserId",           CEF_STR, 1023},
{"duser",                       "destinationUserName",         CEF_STR, 1023},
{"dvc",                         "deviceAddress",               CEF_IPV4,0   },
{"dvchost",                     "deviceHostName",              CEF_STR, 100 },
{"dvcmac",                      "deviceMacAddress",            CEF_MAC, 0   },
{"dvcpid",                      "deviceProcessId",             CEF_INT, 0   },
{"end",                         "endTime",                     CEF_TIME,0   },
{"externalId",                  "externalId",                  CEF_STR, 40  },
{"fileCreateTime",              "fileCreateTime",              CEF_TIME,0   },
{"fileHash",                    "fileHash",                    CEF_STR, 255 },
{"fileId",                      "fileId",                      CEF_STR, 1023},
{"fileModificationTime",        "fileModificationTime",        CEF_TIME,0   },
{"filePath",                    "filePath",                    CEF_STR, 1023},
{"filePermission",              "filePermission",              CEF_STR, 1023},
{"fileType",                    "fileType",                    CEF_STR, 1023},
{"fname",                       "filename",                    CEF_STR, 1023},
{"fsize",                       "fileSize",                    CEF_INT, 0   },
{"in",                          "bytesIn",                     CEF_INT, 0   },
{"msg",                         "message",                     CEF_STR, 1023},
{"oldFileCreateTime",           "oldFileCreateTime",           CEF_TIME,0   },
{"oldFileHash",                 "oldFileHash",                 CEF_STR, 255 },
{"oldFileId",                   "oldFileId",                   CEF_STR, 1023},
{"oldFileModificationTime",     "oldFileModificationTime",     CEF_TIME,0   },
{"oldFileName",                 "oldFileName",                 CEF_STR, 1023},
{"oldFilePath",                 "oldFilePath",                 CEF_STR, 1023},
{"oldFilePermission",           "oldFilePermission",           CEF_STR, 1023},
{"oldFileSize",                 "oldFileSize",                 CEF_INT, 0   },
{"oldFileType",                 "oldFileType",                 CEF_STR, 1023},
{"out",                         "bytesOut",                    CEF_INT, 0   },
{"outcome",                     "eventOutcome",                CEF_STR, 63  },
{"proto",                       "transportProtocol",           CEF_STR, 31  },
{"reason",                      "Reason",                      CEF_STR, 1023},
{"request",                     "requestUrl",                  CEF_STR, 1023},
{"requestClientApplication",    "requestClientApplication",    CEF_STR, 1023},
{"requestContext",              "requestContext",              CEF_STR, 2048},
{"requestCookies",              "requestCookies",              CEF_STR, 1023},
{"requestMethod",               "requestMethod",               CEF_STR, 1023},
{"rt",                          "deviceReceiptTime",           CEF_TIME,0   },
{"shost",                       "sourceHostName",              CEF_STR, 1023},
{"smac",                        "sourceMacAddress",            CEF_MAC, 0   },
{"sntdom",                      "sourceNtDomain",              CEF_STR, 255 },
{"sourceDnsDomain",             "sourceDnsDomain",             CEF_STR, 255 },
{"sourceServiceName",           "sourceServiceName",           CEF_STR, 1023},
{"sourceTranslatedAddress",     "sourceTranslatedAddress",     CEF_IPV4,0   },
{"sourceTranslatedPort",        "sourceTranslatedPort",        CEF_INT, 0   },
{"spid",                        "sourceProcessId",             CEF_INT, 0   },
{"spriv",                       "sourceUserPrivileges",        CEF_STR, 1023},
{"sproc",                       "sourceProcessName",           CEF_STR, 1023},
{"spt",                         "sourcePort",                  CEF_INT, 0   },
{"src",                         "sourceAddress",               CEF_IPV4,0   },
{"start",                       "startTime",                   CEF_TIME,0   },
{"suid",                        "sourceUserId",                CEF_STR, 1023},
{"suser",                       "sourceUserName",              CEF_STR, 1023},
{"type",                        "type",                        CEF_INT, 0   },
{NULL,                          NULL,                          0,       0   }
};

static struct cef_cdic cef_cdic_ipv6 =
    { "c6a%dLabel",              1023, "c6a%d",                0, CEF_IPV6 };
static struct cef_cdic cef_cdic_fp =
    { "cfp%dLabel",              1023, "cfp%d",                0, CEF_FLOAT};
static struct cef_cdic cef_cdic_number =
    { "cn%dLabel",               1023, "cn%d",                 0, CEF_LONG };
static struct cef_cdic cef_cdic_string =
    { "cs%dLabel",               1023, "cs%d",              4000, CEF_STR  };
static struct cef_cdic cef_cdic_date =
    { "deviceCustomDate%dLabel", 1023, "deviceCustomDate%d",   0, CEF_TIME };
static struct cef_cdic cef_cdic_flex_date =
    { "flexDate%dLabel",          128, "flexDate%d",           0, CEF_TIME };
static struct cef_cdic cef_cdic_flex_str =
    { "flexString%dLabel",        128, "flexString%d",      1023, CEF_STR  };


static int cef_ht_add (struct cef_ht *ht, flb_sds_t key,
                       struct cef_ht_dic *dic, int dic_size,
                       struct cef_ht *child);

/*
 * This hash generation function is taken originally from Redis source code:
 *
 *  https://github.com/antirez/redis/blob/unstable/src/dict.c#L109
 *
 * ----
 * MurmurHash2, by Austin Appleby
 * Note - This code makes a few assumptions about how your machine behaves -
 * 1. We can read a 4-byte value from any address without crashing
 * 2. sizeof(int) == 4
 *
 * And it has a few limitations -
 *
 * 1. It will not work incrementally.
 * 2. It will not produce the same results on little-endian and big-endian
 *    machines.
 */
static unsigned int cef_ht_hash(const void *key, int len)
{
    /* 'm' and 'r' are mixing constants generated offline.
       They're not really 'magic', they just happen to work well.  */
    uint32_t seed = 5381;
    const uint32_t m = 0x5bd1e995;
    const int r = 24;

    /* Initialize the hash to a 'random' value */
    uint32_t h = seed ^ len;

    /* Mix 4 bytes at a time into the hash */
    const unsigned char *data = (const unsigned char *)key;

    while(len >= 4) {
        uint32_t k = *(uint32_t*) data;

        k *= m;
        k ^= k >> r;
        k *= m;

        h *= m;
        h ^= k;

        data += 4;
        len -= 4;
    }

    /* Handle the last few bytes of the input array  */
    switch(len) {
    case 3: h ^= data[2] << 16;
    case 2: h ^= data[1] << 8;
    case 1: h ^= data[0]; h *= m;
    };

    /* Do a few final mixes of the hash to ensure the last few
     * bytes are well-incorporated. */
    h ^= h >> 13;
    h *= m;
    h ^= h >> 15;

    return (unsigned int) h;
}

void cef_ht_destroy (struct cef_ht *ht)
{
    int i, n;

    if (!ht) {
        return;
    }

    if (ht->tbl) {
        for (i=0; i < ht->size; i++) {
            if (ht->tbl[i].hash != 0) {
                if (ht->tbl[i].key) {
                    flb_sds_destroy(ht->tbl[i].key);
                }
                if (ht->tbl[i].dic) {
                    for(n=0; n < ht->tbl[i].dic_size; n++) {
                        if (ht->tbl[i].dic[n].clabel) {
                            flb_sds_destroy(ht->tbl[i].dic[n].clabel);
                        }
                        if (ht->tbl[i].dic[n].cvalue) {
                            flb_sds_destroy(ht->tbl[i].dic[n].cvalue);
                        }
                        if (ht->tbl[i].dic[n].label) {
                            flb_sds_destroy(ht->tbl[i].dic[n].label);
                        }
                    }
                    flb_free(ht->tbl[i].dic);
                }
                if (ht->tbl[i].child) {
                    cef_ht_destroy(ht->tbl[i].child);
                }
            }
        }
        flb_free(ht->tbl);
    }

    flb_free(ht);
}

static struct cef_ht *cef_ht_create (int size)
{
    struct cef_ht *ht;

    ht = flb_calloc(1, sizeof(struct cef_ht));
    if (!ht) {
        flb_errno();
        return NULL;
    }

    ht->size = size;

    ht->tbl = flb_calloc(size, sizeof(struct cef_ht_entry));
    if (!ht->tbl) {
        flb_errno();
        flb_free(ht);
        return NULL;
    }

    return ht;
}

static int cef_ht_rehash (struct cef_ht *ht)
{
    unsigned int nsize;
    struct cef_ht nht;
    struct cef_ht_entry *ntbl;
    int n;

    if (!ht) {
       return -1;
    }

    nsize = ht->used * 2;
    if (nsize <= ht->size) {
        return 0;
    }

    ntbl = flb_calloc(nsize, sizeof(struct cef_ht_entry));
    if (!ntbl) {
        flb_errno();
        return -1;
    }

    nht.size = nsize;
    nht.used = 0;
    nht.tbl = ntbl;

    for (n=0; n < ht->size; n++) {
        if (ht->tbl[n].hash != 0) {
            cef_ht_add(&nht, ht->tbl[n].key, ht->tbl[n].dic,
                                 ht->tbl[n].dic_size, ht->tbl[n].child);
        }
    }

    ht->size = nsize;
    ht->used = nht.used;
    flb_free(ht->tbl);
    ht->tbl = ntbl;
    return 0;
}

struct cef_ht_entry *cef_ht_find(struct cef_ht *ht,
                                         char *key, int key_len)
{
    unsigned int hash;
    unsigned int pos;

    if (!ht) {
        return NULL;
    }

    if (!key) {
        return NULL;
    }

    hash = cef_ht_hash(key, key_len);
    pos = hash % ht->size;
    while (1) {
        if (ht->tbl[pos].hash == 0) {
            return NULL;
        }

        if ((ht->tbl[pos].hash == hash ) &&
            (strncmp(key, ht->tbl[pos].key, key_len) == 0)) {
            return &(ht->tbl[pos]);
        }
        pos = (pos+1) % ht->size;
    }
    return NULL;
}

static int cef_ht_add (struct cef_ht *ht, flb_sds_t key,
                           struct cef_ht_dic *dic, int dic_size,
                           struct cef_ht *child)
{
    unsigned int hash;
    unsigned int pos;
    int dib;

    if (!ht) {
       return -1;
    }

    if (!key) {
       return -1;
    }

    hash = cef_ht_hash(key,flb_sds_len(key));
    pos = hash % ht->size;
    dib = 0;
    while (1) {
        if (ht->tbl[pos].hash == 0) {
            ht->tbl[pos].hash = hash;
            ht->tbl[pos].dib = dib;
            ht->tbl[pos].key = key;
            ht->tbl[pos].dic_size = dic_size;
            ht->tbl[pos].dic = dic;
            ht->tbl[pos].child = child;
            ht->used++;
            break;
        }
        if (ht->tbl[pos].dib < dib) {
            flb_sds_t c_key = ht->tbl[pos].key;
            struct cef_ht_dic *c_dic = ht->tbl[pos].dic;
            int c_dic_size = ht->tbl[pos].dic_size;
            struct cef_ht *c_child = ht->tbl[pos].child;

            ht->tbl[pos].hash = hash;
            ht->tbl[pos].dib = dib;
            ht->tbl[pos].key = key;
            ht->tbl[pos].dic_size = dic_size;
            ht->tbl[pos].dic = dic;
            ht->tbl[pos].child = child;

            cef_ht_add(ht, c_key, c_dic, c_dic_size, c_child);
            break;
        }
        dib++;
        pos = (pos + 1) % ht->size;
    }

    if ((ht->used * 3)  > (ht->size *2)) {
        cef_ht_rehash(ht);
    }

    return 0;
}

static int cef_append_dic (struct cef_ht *ht, enum cef_ftype ftype,
                           enum cef_type type,
                           char *clabel, int clabel_len,
                           char *cvalue, int cvalue_len,
                           char *label, int label_len,
                           int value_max_size, char *path)
{
    char *c, *start;
    int ret;

    while (*path == '.') {
        path++;
    }

    c = start = path;
    while (*c != '\0') {
        if (*c == '.') {
            if ((c-start) > 0) {
                struct cef_ht_entry  *entry;
                entry = cef_ht_find(ht, start, (int)(c-start));
                if (entry == NULL) {
                    struct cef_ht *cht;
                    flb_sds_t key = flb_sds_create_len(start, (int)(c-start));

                    cef_ht_add (ht, key, NULL, 0, NULL);
                    entry = cef_ht_find(ht, start, (int)(c-start));
                    if (entry == NULL) {
                        return -1;
                    }

                    cht = cef_ht_create(16);
                    if (cht == NULL) {
                        return -1;
                    }

                    entry->child = cht;
                }

                ret = cef_append_dic(entry->child, ftype, type,
                                     clabel, clabel_len,
                                     cvalue, cvalue_len,
                                     label, label_len,
                                     value_max_size, c);
                if (ret < 0) {
                    return -1;
                }

                return 0;
             }
             start = c;
        }
        c++;
    }

    if (*c == '\0' && (c-start) > 0) {
        struct cef_ht_entry  *entry;
        struct cef_ht_dic *dic;
        int n;

        entry = cef_ht_find(ht, start, (int)(c-start));
        if (entry == NULL) {
            flb_sds_t key = flb_sds_create_len(start, (int)(c-start));

            cef_ht_add (ht, key, NULL, 0, NULL);
            entry = cef_ht_find(ht, start, (int)(c-start));
            if (entry == NULL) {

            }
        }

        dic = realloc(entry->dic,
                      sizeof(struct cef_ht_dic)*(entry->dic_size + 1));
        if (!dic) {
            return -1;
        }
        entry->dic = dic;

        n = entry->dic_size;
        entry->dic_size++;

        dic[n].ftype =  ftype;
        dic[n].type = type;
        if (clabel) {
            dic[n].clabel = flb_sds_create_len(clabel, clabel_len);
        }
        else {
            dic[n].clabel = NULL;
        }
        if (cvalue) {
            dic[n].cvalue = flb_sds_create_len(cvalue, cvalue_len);
        }
        else {
            dic[n].cvalue = NULL;
        }
        if (label) {
            dic[n].label = flb_sds_create_len(label, label_len);
        }
        else {
            dic[n].label = NULL;
        }
        dic[n].value_max_size = value_max_size;
    }

    return 0;
}

static int cef_config (struct cef_ht *ht,
                       enum cef_ftype ftype,
                       char *key, int cnt, char *path)
{
    char clabel[64] = {0};
    int clabel_len;
    char cvalue[64] = {0};
    int cvalue_len;
    int label_len;

    struct cef_cdic *cef_cdic = NULL;
    int ret;
    int n;

    /* ltrim */
    while (*path == ' ') path++;

    switch (ftype) {
    case CEF_SYSLOG_HOST:
    case CEF_SYSLOG_FACILITY:
    case CEF_SYSLOG_SEVERITY:
    case CEF_HDR_DEV_VENDOR:
    case CEF_HDR_DEV_PRODUCT:
    case CEF_HDR_DEV_VERSION:
    case CEF_HDR_DEV_EVENT_CID:
    case CEF_HDR_SEVERITY:
    case CEF_HDR_NAME:
        ret = cef_append_dic(ht, ftype, CEF_STR,
                             NULL, 0, NULL, 0, NULL, 0, 0, path);
        if (ret < 0) {
            return -1;
        }
        break;
    case CEF_CUSTOM_IPV6:
    case CEF_CUSTOM_FLOAT:
    case CEF_CUSTOM_NUMBER:
    case CEF_CUSTOM_STRING:
    case CEF_CUSTOM_DATE:
    case CEF_FLEX_DATE:
    case CEF_FLEX_STRING:
        if (ftype == CEF_CUSTOM_IPV6) {
            cef_cdic = &cef_cdic_ipv6;
        }
        else if (ftype == CEF_CUSTOM_FLOAT) {
            cef_cdic = &cef_cdic_fp;
        }
        else if (ftype == CEF_CUSTOM_NUMBER) {
            cef_cdic = &cef_cdic_number;
        }
        else if (ftype == CEF_CUSTOM_STRING) {
            cef_cdic = &cef_cdic_string;
        }
        else if (ftype == CEF_CUSTOM_DATE) {
            cef_cdic = &cef_cdic_date;
        }
        else if (ftype == CEF_FLEX_DATE) {
            cef_cdic = &cef_cdic_flex_date;
        }
        else if (ftype == CEF_FLEX_STRING) {
            cef_cdic = &cef_cdic_flex_str;
        }

        clabel_len = snprintf(clabel, sizeof(clabel) - 1,
                              cef_cdic->label, cnt);

        label_len = strlen(key);
        if ((cef_cdic->label_size > 0) &&
            (label_len > cef_cdic->label_size )) {
            label_len = cef_cdic->label_size;
        }

        cvalue_len = snprintf(cvalue, sizeof(cvalue) - 1,
                              cef_cdic->value, cnt);

        ret = cef_append_dic(ht, ftype, cef_cdic->type,
                       clabel, clabel_len,
                       cvalue, cvalue_len,
                       key, label_len,
                       cef_cdic->value_size,
                       path);
        if (ret < 0) {
            return -1;
        }

        break;
    case CEF_EXTENSION:
        for (n=0; cef_dic_dft[n].key != NULL; n++) {
            if ((strcasecmp(cef_dic_dft[n].key, key) == 0) ||
                (strcasecmp(cef_dic_dft[n].key_full_name, key) == 0) ) {

                ret = cef_append_dic(ht, ftype, cef_dic_dft[n].type,
                                    NULL, 0, NULL, 0,
                                    cef_dic_dft[n].key, strlen(cef_dic_dft[n].key),
                                    cef_dic_dft[n].size,
                                    path);
                if (ret < 0) {
                    return -1;
                }
                break;
            }
        }
        if (cef_dic_dft[n].key == NULL) {
            flb_error("[out_cef] key %s: Not Found", key);
            return -1;
        }
        break;
    case CEF_CUSTOM_EXTENSION:
        ret = cef_append_dic(ht, ftype, CEF_STR,
                            NULL, 0, NULL, 0, key, strlen(key), 0, path);
        if (ret < 0) {
            return -1;
        }
        break;
    }

    return 0;
}

int cef_settings (struct flb_output_instance *ins,
                  struct out_cef_config *ctx)
{
    struct mk_list *head;
    struct flb_config_prop *prop;
    int ret;
    int i;
    const char *tmp;

    struct {
        char *key;
        int type;
        int nargs;
        int max;
        int cnt;
    } cef_cfg_keys[] = {
        { "cef_extension_key",                 CEF_EXTENSION,        2, 0, 0},
        { "cef_custom_extension_key",          CEF_CUSTOM_EXTENSION, 2, 0, 0},
        { "cef_deviceCustomIPv6Address_key",   CEF_CUSTOM_IPV6,      2, 4, 0},
        { "cef_deviceCustomFloatingPoint_key", CEF_CUSTOM_FLOAT,     2, 4, 0},
        { "cef_deviceCustomNumber_key",        CEF_CUSTOM_NUMBER,    2, 3, 0},
        { "cef_deviceCustomString_key",        CEF_CUSTOM_STRING,    2, 6, 0},
        { "cef_deviceCustomDate_key",          CEF_CUSTOM_DATE,      2, 2, 0},
        { "cef_flex_date_key",                 CEF_FLEX_DATE,        2, 1, 0},
        { "cef_flex_string_key",               CEF_FLEX_STRING,      2, 2, 0},
        { "cef_header_deviceVendor_key",       CEF_HDR_DEV_VENDOR,   1, 1, 0},
        { "cef_header_deviceProduct_key",      CEF_HDR_DEV_PRODUCT,  1, 1, 0},
        { "cef_header_deviceVersion_key",      CEF_HDR_DEV_VERSION,  1, 1, 0},
        { "cef_header_deviceEventClassId_key", CEF_HDR_DEV_EVENT_CID,1, 1, 0},
        { "cef_header_severity_key",           CEF_HDR_SEVERITY,     1, 1, 0},
        { "cef_header_name_key",               CEF_HDR_NAME,         1, 1, 0},
        { "cef_syslog_host_key",               CEF_SYSLOG_HOST,      1, 1, 0},
        { "cef_syslog_facility_key",           CEF_SYSLOG_FACILITY,  1, 1, 0},
        { "cef_syslog_severity_key",           CEF_SYSLOG_SEVERITY,  1, 1, 0},
        { NULL,                                0,                    0, 0, 0}
    };

    /* Set default network configuration */
    if (!ins->host.name) {
        ins->host.name = flb_strdup("127.0.0.1");
    }
    if (ins->host.port == 0) {
        ins->host.port = 514;
    }

    ctx->fmt = FLB_CEF_FMT_SYSLOG;

    /* Config Mode */
    tmp = flb_output_get_property("mode", ins);
    if (tmp) {
        if (!strcasecmp(tmp, "tcp")) {
            ctx->mode = FLB_CEF_TCP;
        }
        else if (!strcasecmp(tmp, "tls")) {
            ctx->mode = FLB_CEF_TLS;
        }
        else if (!strcasecmp(tmp, "udp")) {
            ctx->mode = FLB_CEF_UDP;
        }
        else {
            flb_error("[out_cef] Unknown cef mode %s", tmp);
            return -1;
        }
    }
    else {
        ctx->mode = FLB_CEF_UDP;
    }

    ctx->ht_dic = cef_ht_create(32);
    if (!ctx->ht_dic) {
        flb_error("[out_cef] Error creating hash for dict");
        return -1;
    }

    /* iterate all properties */
    mk_list_foreach(head, &ins->properties) {
        prop = mk_list_entry(head, struct flb_config_prop, _head);

        if (strncasecmp(prop->key, "cef_", 4) != 0) {
            continue;
        }

        for (i=0; cef_cfg_keys[i].key != NULL; i++) {
            if (strcasecmp(prop->key, cef_cfg_keys[i].key) == 0) {
                struct mk_list *split;
                struct flb_split_entry *entry;
                struct flb_split_entry *first;
                char *key = NULL;
                char *value = NULL;

                cef_cfg_keys[i].cnt++;
                if ((cef_cfg_keys[i].max > 0) &&
                    (cef_cfg_keys[i].cnt > cef_cfg_keys[i].max)) {
                    flb_error("[out_cef] max number of intances of '%s'",
                              prop->key);
                    return -1;
                }

                if (cef_cfg_keys[i].nargs == 2) {
                    split = flb_utils_split(prop->val, ' ', 1);
                    if (mk_list_size(split) != 2) {
                        flb_error("[out_cef] invalid %s parameters, "
                                  "expects 'KEY VALUE'", prop->key);
                        flb_utils_split_free(split);
                        return -1;
                    }

                    first = mk_list_entry_first(split,
                                                struct flb_split_entry,
                                                _head);
                    key = flb_strndup(first->value, first->len);

                    entry = mk_list_entry_next(&first->_head, struct flb_split_entry,
                                               _head, split);
                    value = flb_strndup(entry->value, entry->len);

                    flb_utils_split_free(split);
                }
                else {
                    value = prop->val;
                }

                ret = cef_config(ctx->ht_dic,
                                 cef_cfg_keys[i].type,
                                 key,
                                 cef_cfg_keys[i].cnt,
                                 value);

                if (cef_cfg_keys[i].nargs == 2) {
                    flb_free(key);
                    flb_free(value);
                }

                if (ret < 0) {
                    flb_error("[out_cef] error config '%s' ", prop->key);
                    return -1;
                }
                break;
            }
        }

        if (cef_cfg_keys[i].key == NULL) {
           if (strcasecmp(prop->key, "cef_format") == 0) {
               if (strcasecmp(prop->val, "raw") == 0) {
                   ctx->fmt = FLB_CEF_FMT_RAW;
               }
               else if (strcasecmp(prop->val, "syslog") == 0) {
                   ctx->fmt = FLB_CEF_FMT_SYSLOG;
               }
               else {
                   flb_error("[out_cef] Unknown cef format '%s'", prop->val);
                   return -1;
               }
           }
           else {
               flb_error("[out_cef] Unknown cef option '%s'", prop->key);
               return -1;
           }
        }
    }

    return 0;
}


