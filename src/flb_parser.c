/* -*- Mode: C; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

/*  Fluent Bit
 *  ==========
 *  Copyright (C) 2019      The Fluent Bit Authors
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
#include <fluent-bit/flb_log.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_parser.h>
#include <fluent-bit/flb_parser_decoder.h>
#include <fluent-bit/flb_time.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_config.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <limits.h>
#include <string.h>

static inline uint32_t digits10(uint64_t v) {
    if (v < 10) return 1;
    if (v < 100) return 2;
    if (v < 1000) return 3;
    if (v < 1000000000000UL) {
        if (v < 100000000UL) {
            if (v < 1000000) {
                if (v < 10000) return 4;
                return 5 + (v >= 100000);
            }
            return 7 + (v >= 10000000UL);
        }
        if (v < 10000000000UL) {
            return 9 + (v >= 1000000000UL);
        }
        return 11 + (v >= 100000000000UL);
    }
    return 12 + digits10(v / 1000000000000UL);
}

static unsigned u64_to_str(uint64_t value, char* dst) {
    static const char digits[201] =
        "0001020304050607080910111213141516171819"
        "2021222324252627282930313233343536373839"
        "4041424344454647484950515253545556575859"
        "6061626364656667686970717273747576777879"
        "8081828384858687888990919293949596979899";
    uint32_t const length = digits10(value);
    uint32_t next = length - 1;
    while (value >= 100) {
        int const i = (value % 100) * 2;
        value /= 100;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
        next -= 2;
    }

    /* Handle last 1-2 digits */
    if (value < 10) {
        dst[next] = '0' + (uint32_t) value;
    } else {
        int i = (uint32_t) value * 2;
        dst[next] = digits[i + 1];
        dst[next - 1] = digits[i];
    }
    return length;
}

int flb_parser_regex_do(struct flb_parser *parser,
                        char *buf, size_t length,
                        void **out_buf, size_t *out_size,
                        struct flb_time *out_time);

int flb_parser_json_do(struct flb_parser *parser,
                       char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time);

int flb_parser_ltsv_do(struct flb_parser *parser,
                       char *buf, size_t length,
                       void **out_buf, size_t *out_size,
                       struct flb_time *out_time);

int flb_parser_logfmt_do(struct flb_parser *parser,
                         char *buf, size_t length,
                         void **out_buf, size_t *out_size,
                         struct flb_time *out_time);

struct flb_parser *flb_parser_create(char *name, char *format,
                                     char *p_regex,
                                     char *time_fmt, char *time_key,
                                     char *time_offset,
                                     int time_keep,
                                     struct flb_parser_types *types,
                                     int types_len,
                                     struct mk_list *decoders,
                                     struct flb_config *config)
{
    int ret;
    int len;
    int diff = 0;
    int size;
    char *tmp;
    struct mk_list *head;
    struct flb_parser *p;
    struct flb_regex *regex;

    /* Iterate current parsers and make sure the new one don't exists */
    mk_list_foreach(head, &config->parsers) {
        p = mk_list_entry(head, struct flb_parser, _head);
        if (strcmp(p->name, name) == 0) {
            flb_error("[parser] parser named '%s' already exists, skip.",
                      name);
            return NULL;
        }
    }

    /* Allocate context */
    p = flb_calloc(1, sizeof(struct flb_parser));
    if (!p) {
        flb_errno();
        return NULL;
    }
    p->decoders = decoders;

    /* Format lookup */
    if (strcasecmp(format, "regex") == 0) {
        p->type = FLB_PARSER_REGEX;
    }
    else if (strcasecmp(format, "json") == 0) {
        p->type = FLB_PARSER_JSON;
    }
    else if (strcmp(format, "ltsv") == 0) {
        p->type = FLB_PARSER_LTSV;
    }
    else if (strcmp(format, "logfmt") == 0) {
        p->type = FLB_PARSER_LOGFMT;
    }
    else {
        flb_error("[parser:%s] Invalid format %s", name, format);
        flb_free(p);
        return NULL;
    }

    if (p->type == FLB_PARSER_REGEX) {
        if (!p_regex) {
            flb_error("[parser:%s] Invalid regex pattern", name);
            flb_free(p);
            return NULL;
        }

        regex = flb_regex_create((unsigned char *) p_regex);
        if (!regex) {
            flb_error("[parser:%s] Invalid regex pattern %s", name, p_regex);
            flb_free(p);
            return NULL;
        }
        p->regex = regex;
        p->p_regex = flb_strdup(p_regex);
    }

    p->name = flb_strdup(name);

    if (time_fmt) {
        p->time_fmt = flb_strdup(time_fmt);

        /* Check if the format is considering the year */
        if (strstr(p->time_fmt, "%Y") || strstr(p->time_fmt, "%y")) {
            p->time_with_year = FLB_TRUE;
        }
        else {
            size = strlen(p->time_fmt);
            p->time_with_year = FLB_FALSE;
            p->time_fmt_year = flb_malloc(size + 4);
            if (!p->time_fmt_year) {
                flb_errno();
                flb_parser_destroy(p);
                return NULL;
            }

            /* Append the year at the beginning */
            tmp = p->time_fmt_year;
            *tmp++ = '%';
            *tmp++ = 'Y';
            *tmp++ = ' ';

            memcpy(tmp, p->time_fmt, size);
            tmp += size;
            *tmp++ = '\0';
        }

        /* Check if the format contains a timezone (%z) */
        if (strstr(p->time_fmt, "%z") || strstr(p->time_fmt, "%Z") ||
            strstr(p->time_fmt, "%SZ") || strstr(p->time_fmt, "%S.%LZ")) {
#ifdef FLB_HAVE_GMTOFF
            p->time_with_tz = FLB_TRUE;
#else
            flb_error("[parser] timezone offset not supported");
            flb_error("[parser] you cannot use %%z/%%Z on this platform");
            flb_free(p);
            return NULL;
#endif
        }

        /*
         * Check if the format expect fractional seconds
         *
         * Since strptime(3) does not support fractional seconds, this
         * requires a workaround/hack in our parser. This is a known
         * issue and addressed in different ways in other languages.
         *
         * The following links are a good reference:
         *
         * - http://stackoverflow.com/questions/7114690/how-to-parse-syslog-timestamp
         * - http://code.activestate.com/lists/python-list/521885/
         */
        if (p->time_with_year == FLB_TRUE) {
            tmp = strstr(p->time_fmt, "%S.%L");
        }
        else {
            tmp = strstr(p->time_fmt_year, "%s.%L");

            if (tmp == NULL) {
                tmp = strstr(p->time_fmt_year, "%S.%L");
            }
        }
        if (tmp) {
            tmp[2] = '\0';
            p->time_frac_secs = (tmp + 5);
        }
        else {
            /* same as above but with comma seperator */
            if (p->time_with_year == FLB_TRUE) {
                tmp = strstr(p->time_fmt, "%S,%L");
            }
            else {
                tmp = strstr(p->time_fmt_year, "%s,%L");

                if (tmp == NULL) {
                    tmp = strstr(p->time_fmt_year, "%S,%L");
                }
            }
            if (tmp) {
                tmp[2] = '\0';
                p->time_frac_secs = (tmp + 5);
            }
            else {
                p->time_frac_secs = NULL;
            }
        }

        /* Optional fixed timezone offset */
        if (time_offset) {
            diff = 0;
            len = strlen(time_offset);
            ret = flb_parser_tzone_offset(time_offset, len, &diff);
            if (ret == -1) {
                flb_free(p);
                return NULL;
            }
            p->time_offset = diff;
        }
    }

    if (time_key) {
        p->time_key = flb_strdup(time_key);
    }

    p->time_keep = time_keep;
    p->types = types;
    p->types_len = types_len;

    mk_list_add(&p->_head, &config->parsers);

    return p;
}

void flb_parser_destroy(struct flb_parser *parser)
{
    int i = 0;
    if (parser->type == FLB_PARSER_REGEX) {
        flb_regex_destroy(parser->regex);
        flb_free(parser->p_regex);
    }

    flb_free(parser->name);
    if (parser->time_fmt) {
        flb_free(parser->time_fmt);
    }
    if (parser->time_fmt_year) {
        flb_free(parser->time_fmt_year);
    }
    if (parser->time_key) {
        flb_free(parser->time_key);
    }
    if (parser->types_len != 0) {
        for (i=0; i<parser->types_len; i++){
            flb_free(parser->types[i].key);
        }
        flb_free(parser->types);
    }

    if (parser->decoders) {
        flb_parser_decoder_list_destroy(parser->decoders);
    }

    mk_list_del(&parser->_head);
    flb_free(parser);
}

void flb_parser_exit(struct flb_config *config)
{
    struct mk_list *tmp;
    struct mk_list *head;
    struct flb_parser *parser;

    mk_list_foreach_safe(head, tmp, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        flb_parser_destroy(parser);
    }
}

static int proc_types_str(char *types_str, struct flb_parser_types **types)
{
    int i = 0;
    int types_num = 0;
    char *type_str = NULL;
    struct mk_list *split;
    struct mk_list *head;
    struct flb_split_entry *sentry;

    split = flb_utils_split(types_str, ' ', 256);
    types_num = mk_list_size(split);
    *types = flb_malloc(sizeof(struct flb_parser_types) * types_num);

    for(i=0; i<types_num; i++){
        (*types)[i].key = NULL;
        (*types)[i].type = FLB_PARSER_TYPE_STRING;
    }
    i = 0;
    mk_list_foreach(head ,split) {
        sentry = mk_list_entry(head, struct flb_split_entry ,_head);
        type_str = strchr(sentry->value ,':');

        if (type_str == NULL) {
            i++;
            continue;
        }
        *type_str = '\0'; /* for strdup */
        (*types)[i].key = flb_strdup(sentry->value);
        (*types)[i].key_len = strlen(sentry->value);
        *types_str = ':';

        type_str++;
        if (!strcasecmp(type_str, "integer")) {
            (*types)[i].type = FLB_PARSER_TYPE_INT;
        }
        else if(!strcasecmp(type_str, "bool")) {
            (*types)[i].type = FLB_PARSER_TYPE_BOOL;
        }
        else if(!strcasecmp(type_str, "float")){
            (*types)[i].type = FLB_PARSER_TYPE_FLOAT;
        }
        else if(!strcasecmp(type_str, "hex")){
            (*types)[i].type = FLB_PARSER_TYPE_HEX;
        }
        else {
            (*types)[i].type = FLB_PARSER_TYPE_STRING;
        }
        i++;
    }
    flb_utils_split_free(split);

    return i;
}

/* Load parsers from a configuration file */
int flb_parser_conf_file(char *file, struct flb_config *config)
{
    int ret;
    char tmp[PATH_MAX + 1];
    char *cfg = NULL;
    char *name;
    char *format;
    char *regex;
    char *time_fmt;
    char *time_key;
    char *time_offset;
    char *types_str;
    char *str;
    int time_keep;
    int types_len;
    struct mk_rconf *fconf;
    struct mk_rconf_section *section;
    struct mk_list *head;
    struct stat st;
    struct flb_parser_types *types;
    struct mk_list *decoders;

#ifndef FLB_HAVE_STATIC_CONF
    ret = stat(file, &st);
    if (ret == -1 && errno == ENOENT) {
        /* Try to resolve the real path (if exists) */
        if (file[0] == '/') {
            flb_utils_error(FLB_ERR_CFG_PARSER_FILE);
            return -1;
        }

        if (config->conf_path) {
            snprintf(tmp, PATH_MAX, "%s%s", config->conf_path, file);
            cfg = tmp;
        }
    }
    else {
        cfg = file;
    }

    fconf = mk_rconf_open(cfg);
#else
    fconf = flb_config_static_open(file);
#endif

    if (!fconf) {
        return -1;
    }

    /* Read all [PARSER] sections */
    mk_list_foreach(head, &fconf->sections) {
        name = NULL;
        format = NULL;
        regex = NULL;
        time_fmt = NULL;
        time_key = NULL;
        time_offset = NULL;
        types_str = NULL;

        section = mk_list_entry(head, struct mk_rconf_section, _head);
        if (strcasecmp(section->name, "PARSER") != 0) {
            continue;
        }

        /* Name */
        name = mk_rconf_section_get_key(section, "Name", MK_RCONF_STR);
        if (!name) {
            flb_error("[parser] no parser 'name' found in file '%s'", cfg);
            goto fconf_error;
        }

        /* Format */
        format = mk_rconf_section_get_key(section, "Format", MK_RCONF_STR);
        if (!format) {
            flb_error("[parser] no parser 'format' found for '%s' in file '%s'", name, cfg);
            goto fconf_error;
        }

        /* Regex (if format is regex) */
        regex = mk_rconf_section_get_key(section, "Regex", MK_RCONF_STR);
        if (!regex && strcmp(format, "regex") == 0) {
            flb_error("[parser] no parser 'regex' found for '%s' in file '%s", name, cfg);
            goto fconf_error;
        }

        /* Time_Format */
        time_fmt = mk_rconf_section_get_key(section, "Time_Format",
                                            MK_RCONF_STR);

        /* Time_Key */
        time_key = mk_rconf_section_get_key(section, "Time_Key",
                                            MK_RCONF_STR);

        /* Time_Keep */
        str = mk_rconf_section_get_key(section, "Time_Keep",
                                       MK_RCONF_STR);
        if (str) {
            time_keep = flb_utils_bool(str);
            flb_free(str);
        }
        else {
            time_keep = FLB_FALSE;
        }

        /* Time_Offset (UTC offset) */
        time_offset = mk_rconf_section_get_key(section, "Time_Offset",
                                               MK_RCONF_STR);

        /* Types */
        types_str = mk_rconf_section_get_key(section, "Types",
                                            MK_RCONF_STR);
        if (types_str != NULL) {
            types_len = proc_types_str(types_str, &types);
        }
        else {
            types_len = 0;
        }

        /* Decoders */
        decoders = flb_parser_decoder_list_create(section);

        /* Create the parser context */
        if (!flb_parser_create(name, format, regex,
                               time_fmt, time_key, time_offset, time_keep,
                               types, types_len, decoders, config)) {
            goto fconf_error;
        }

        flb_debug("[parser] new parser registered: %s", name);

        flb_free(name);
        flb_free(format);

        if (regex) {
            flb_free(regex);
        }
        if (time_fmt) {
            flb_free(time_fmt);
        }
        if (time_key) {
            flb_free(time_key);
        }
        if (time_offset) {
            flb_free(time_offset);
        }
        if (types_str) {
            flb_free(types_str);
        }

        decoders = NULL;
    }

    mk_rconf_free(fconf);
    return 0;

 fconf_error:
    flb_free(name);
    flb_free(format);
    if (regex) {
        flb_free(regex);
    }
    if (time_fmt) {
        flb_free(time_fmt);
    }
    if (time_key) {
        flb_free(time_key);
    }
    if (types_str) {
        flb_free(types_str);
    }
    if (decoders) {
        flb_parser_decoder_list_destroy(decoders);
    }
    mk_rconf_free(fconf);
    return -1;
}

struct flb_parser *flb_parser_get(char *name, struct flb_config *config)
{
    struct mk_list *head;
    struct flb_parser *parser;


    mk_list_foreach(head, &config->parsers) {
        parser = mk_list_entry(head, struct flb_parser, _head);
        if (strcmp(parser->name, name) == 0) {
            return parser;
        }
    }

    return NULL;
}

int flb_parser_do(struct flb_parser *parser, char *buf, size_t length,
                  void **out_buf, size_t *out_size, struct flb_time *out_time)
{

    if (parser->type == FLB_PARSER_REGEX) {
        return flb_parser_regex_do(parser, buf, length,
                                   out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_JSON) {
        return flb_parser_json_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_LTSV) {
        return flb_parser_ltsv_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }
    else if (parser->type == FLB_PARSER_LOGFMT) {
        return flb_parser_logfmt_do(parser, buf, length,
                                  out_buf, out_size, out_time);
    }

    return -1;
}

/* Given a timezone string, return it numeric offset */
int flb_parser_tzone_offset(char *str, int len, int *tmdiff)
{
    int neg;
    long hour;
    long min;
    char *end;
    char *p = str;

    /* Check timezones */
    if (*p == 'Z') {
        /* This is UTC, no changes required */
        *tmdiff = 0;
        return 0;
    }

    /* Unexpected timezone string */
    if (*p != '+' && *p != '-') {
        *tmdiff = 0;
        return -1;
    }

    /* Negative value ? */
    neg = (*p++ == '-');

    /* Locate end */
    end = str + len;

    /* Gather hours and minutes */
    hour = ((p[0] - '0') * 10) + (p[1] - '0');
    if (end - p == 5 && p[2] == ':') {
        min = ((p[3] - '0') * 10) + (p[4] - '0');
    }
    else {
        min = ((p[2] - '0') * 10) + (p[3] - '0');
    }

    if (hour < 0 || hour > 59 || min < 0 || min > 59) {
        return -1;
    }

    *tmdiff = ((hour * 3600) + (min * 60));
    if (neg) {
        *tmdiff = -*tmdiff;
    }

    return 0;
}

int flb_parser_time_lookup(char *time_str, size_t tsize,
                           time_t now,
                           struct flb_parser *parser,
                           struct tm *tm, double *ns)
{
    int ret;
    int slen;
    time_t time_now;
    double tmfrac = 0;
    char *p = NULL;
    char *fmt;
    int time_len = tsize;
    char *time_ptr = time_str;
    char tmp[64];
    char fs_tmp[32];
    struct tm tmy;

    *ns = 0;

    if (tsize > sizeof(tmp) - 1) {
        flb_error("[parser] time string length is too long");
        return -1;
    }

    /*
     * Some records coming from old Syslog messages do not contain the
     * year, so it's required to ingest this information in the value
     * to be parsed.
     */
    if (parser->time_with_year == FLB_FALSE) {
        /* Given time string is too long */
        if (time_len + 6 >= sizeof(tmp)) {
            return -1;
        }

        /*
         * This is not the most elegant way but for now it let
         * get the work done.
         */
        if (now <= 0) {
            time_now = time(NULL);
        }
        else {
            time_now = now;
        }

        gmtime_r(&time_now, &tmy);
        uint64_t t = tmy.tm_year + 1900;

        fmt = tmp;
        u64_to_str(t, fmt);
        fmt += 4;
        *fmt++ = ' ';

        memcpy(fmt, time_ptr, time_len);
        fmt += time_len;
        *fmt++ = '\0';

        time_ptr = tmp;
        time_len = strlen(tmp);
        p = strptime(time_ptr, parser->time_fmt_year, tm);
    }
    else {
        p = strptime(time_ptr, parser->time_fmt, tm);
    }

    if (p != NULL) {
        /* Check if we have fractional seconds */
        if (parser->time_frac_secs && (*p == '.' || *p == ',')) {
            /*
             * Further parser routines needs a null byte, for fractional seconds
             * we make a safe copy of the content.
             */
            slen = time_len - (p - time_ptr);
            if (slen > 31) {
                slen = 31;
            }
            memcpy(fs_tmp, p, slen);
            fs_tmp[slen] = '\0';

            /* Parse fractional seconds */
            ret = flb_parser_frac(fs_tmp, slen, &tmfrac, &time_ptr);
            if (ret == -1) {
                flb_warn("[parser] Error parsing time string");
                return -1;
            }
            *ns = tmfrac;

            p = strptime(time_ptr, parser->time_frac_secs, tm);

            if (p == NULL) {
                return -1;
            }
        }

#ifdef FLB_HAVE_GMTOFF
        if (parser->time_with_tz == FLB_FALSE) {
            tm->tm_gmtoff = parser->time_offset;
        }
#endif

        return 0;
    }

    return -1;
}

int flb_parser_frac(char *str, int len, double *frac, char **end)
{
    int ret = 0;
    char *p;
    double d;
    char *pstr;

    /* Fractional seconds */
    /* Normalize the fractional seperator to be '.' since that's what strtod()
     * expects in standard C locale */
    if (*str == ',') {
        pstr = flb_strdup(str);
        pstr[0] = '.';
    }
    else {
        pstr = str;
    }

    d = strtod(pstr, &p);
    if ((d == 0 && p == pstr) || !p) {
        ret = -1;
        goto free_and_return;
    }
    *frac = d;
    *end = str + (p - pstr);

free_and_return:
    if (pstr != str) {
        flb_free(pstr);
    }
    return ret;
}

int flb_parser_typecast(char *key, int key_len,
                        char *val, int val_len,
                        msgpack_packer *pck,
                        struct flb_parser_types *types,
                        int types_len)
{
    int i;
    int error = FLB_FALSE;
    char tmp_char;
    int casted = FLB_FALSE;

    for(i=0; i<types_len; i++){
        if (types[i].key != NULL
            && key_len == types[i].key_len &&
            !strncmp(key, types[i].key, key_len)) {

            casted = FLB_TRUE;

            msgpack_pack_str(pck, key_len);
            msgpack_pack_str_body(pck, key, key_len);

            switch (types[i].type) {
            case FLB_PARSER_TYPE_INT:
                {
                    long long lval;

                    /* msgpack char is not null terminated.
                       So backup and fill null char,
                       convert int,
                       rewind char.
                     */
                    tmp_char = val[val_len];
                    val[val_len] = '\0';
                    lval = atoll(val);
                    val[val_len] = tmp_char;
                    msgpack_pack_int64(pck, lval);
                }
                break;
            case FLB_PARSER_TYPE_HEX:
                {
                    unsigned long long lval;
                    tmp_char = val[val_len];
                    val[val_len] = '\0';
                    lval = strtoull(val, NULL, 16);
                    val[val_len] = tmp_char;
                    msgpack_pack_uint64(pck, lval);
                }
                break;

            case FLB_PARSER_TYPE_FLOAT:
                {
                    double dval;
                    tmp_char = val[val_len];
                    val[val_len] = '\0';
                    dval = atof(val);
                    val[val_len] = tmp_char;
                    msgpack_pack_double(pck, dval);
                }
                break;
            case FLB_PARSER_TYPE_BOOL:
                if (!strncasecmp(val, "true", 4)) {
                    msgpack_pack_true(pck);
                }
                else if(!strncasecmp(val, "false", 5)){
                    msgpack_pack_false(pck);
                }
                else {
                    error = FLB_TRUE;
                }
                break;
            case FLB_PARSER_TYPE_STRING:
                msgpack_pack_str(pck, val_len);
                msgpack_pack_str_body(pck, val, val_len);
                break;
            default:
                error = FLB_TRUE;
            }
            if (error == FLB_TRUE) {
                flb_warn("[PARSER] key=%s cast error. save as string.", key);
                msgpack_pack_str(pck, val_len);
                msgpack_pack_str_body(pck, val, val_len);
            }
            break;
        }
    }

    if (casted == FLB_FALSE) {
        msgpack_pack_str(pck, key_len);
        msgpack_pack_str_body(pck, key, key_len);
        msgpack_pack_str(pck, val_len);
        msgpack_pack_str_body(pck, val, val_len);
    }
    return 0;
}
