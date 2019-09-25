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
#include <fluent-bit/flb_hash.h>

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


static void cef_ht_dic_free (struct cef_ht_dic *dic)
{
    if (dic->clabel) {
        flb_sds_destroy(dic->clabel);
    }
    if (dic->cvalue) {
        flb_sds_destroy(dic->cvalue);
    }
    if (dic->label) {
        flb_sds_destroy(dic->label);
    }
}

void cef_ht_destroy (struct flb_hash *ht)
{
    int i,n;
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_hash_entry *entry;
    struct flb_hash_table *table;
    struct cef_ht_entry *centry;

    if (!ht)
        return;

    for (i = 0; i < ht->size; i++) {
        table = &ht->table[i];
        if (table->count > 0) {
            mk_list_foreach_safe(head, tmp, &table->chains) {
                entry = mk_list_entry(head, struct flb_hash_entry, _head);
                if (entry->val != NULL) {
                    centry = (struct cef_ht_entry *)entry->val;
                    if (centry->dic) {
                        for (n=0; n < centry->dic_size ; n++) {
                            cef_ht_dic_free(&(centry->dic[n]));
                        }
                        flb_free(centry->dic);
                    }
                    if (centry->child) {
                        cef_ht_destroy(centry->child);
                    }
                }
            }
        }
    }
    flb_hash_destroy(ht);
}

static struct flb_hash *cef_ht_create (int size)
{
    return flb_hash_create(FLB_HASH_EVICT_NONE, size, 0);
}

struct cef_ht_entry *cef_ht_find(struct flb_hash *ht, char *key, int key_len)
{
    struct cef_ht_entry *entry;
    size_t entry_size;
    int id;

    id = flb_hash_get(ht, key, key_len, (const char **)&entry, &entry_size);
    if (id < 0) {
        return NULL;
    }

    return entry;
}

static int cef_ht_add (struct flb_hash *ht, const char *key, int key_len,
                           struct cef_ht_dic *dic, int dic_size,
                           struct flb_hash *child)
{
    struct cef_ht_entry entry;
    int id;

    if (!ht) {
       return -1;
    }

    entry.dic_size = dic_size;
    entry.dic = dic;
    entry.child = child;

    id = flb_hash_add(ht, key, key_len,
                      (const char *)&entry, sizeof(struct cef_ht_entry));

    return id;
}

static int cef_append_dic (struct flb_hash *ht, enum cef_ftype ftype,
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
                    struct flb_hash *cht;
                    cef_ht_add (ht, start, (int)(c-start), NULL, 0, NULL);
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
            cef_ht_add (ht, start, (int)(c-start) , NULL, 0, NULL);
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

static int cef_config (struct flb_hash *ht,
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


