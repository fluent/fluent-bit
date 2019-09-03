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
#include <fluent-bit/flb_output.h>
#include <fluent-bit/flb_utils.h>
#include <fluent-bit/flb_sds.h>
#include <fluent-bit/flb_pack.h>

#include "syslog.h"
#include "syslog_conf.h"

const char *HUNDRED[] = {
        "00", "01", "02", "03", "04", "05", "06", "07", "08", "09",
        "10", "11", "12", "13", "14", "15", "16", "17", "18", "19",
        "20", "21", "22", "23", "24", "25", "26", "27", "28", "29",
        "30", "31", "32", "33", "34", "35", "36", "37", "38", "39",
        "40", "41", "42", "43", "44", "45", "46", "47", "48", "49",
        "50", "51", "52", "53", "54", "55", "56", "57", "58", "59",
        "60", "61", "62", "63", "64", "65", "66", "67", "68", "69",
        "70", "71", "72", "73", "74", "75", "76", "77", "78", "79",
        "80", "81", "82", "83", "84", "85", "86", "87", "88", "89",
        "90", "91", "92", "93", "94", "95", "96", "97", "98", "99"
};

size_t                        /* O - Length of string */
strlcpy(char *dst,            /* O - Destination string */
        const char *src,      /* I - Source string */
        size_t size)          /* I - Size of destination string buffer */
{
  size_t    srclen;           /* Length of source string */

 /* Figure out how much room is needed... */
  size --;
  srclen = strlen(src);
 /* Copy the appropriate amount... */

  if (srclen > size)
    srclen = size;

  memcpy(dst, src, srclen);
  dst[srclen] = '\0';

  return (srclen);
}

int
_render_message(struct logger_tl *tl, const char *msg) {
    int n = strlcpy(tl->message, msg, tl->max_message);

    return tl->message - tl->msg_start + n;
}

void _prerender_size(struct logger_tl *tl) {
    memset(tl->buf, '0', MAX_LEN_LEN - 1);
    tl->buf[MAX_LEN_LEN - 1] = ' ';
    tl->msg_start = tl->buf + MAX_LEN_LEN;
}


void _skip_size(struct logger_tl *tl) {
    tl->msg_start = tl->buf;
}

int _prerender_pri(struct logger_tl *tl, int pri) {
    char *start = tl->msg_start;
    char *o;
    /* int n = snprintf(start, BUFFER_SIZE, "<%d>1 ", pri);  */
    int n = snprintf(start, BUFFER_SIZE, "<%d>", pri);
    if (n < 0 || n > BUFFER_SIZE)
        perror("snprintf");
    o = tl->timestamp;
    tl->timestamp = start + n;
    tl->max_timestamp = BUFFER_SIZE - n;
    return o != tl->timestamp;
}

int _skip_pri(struct logger_tl *tl, int pri) {
    char *start = tl->msg_start;
    char *o = tl->timestamp;
    tl->timestamp = start;
    tl->max_timestamp = BUFFER_SIZE;
    return o != tl->timestamp;
}


char *_render_size(struct logger_tl *tl, int msg_len) {
    int n = msg_len, r = 0;
    char *p = tl->msg_start - 1;
    const char *c;
    if (n == 0) {
        *(--p) = '0';
    }
    while (n >= 10) {
        r = n % 100;
        n = n / 100;
        c = HUNDRED[r];
        *(--p) = c[1];
        *(--p) = c[0];
    }
    if (n > 0) {
        c = HUNDRED[n];
        *(--p) = c[1];
    }
    return p;
}


int _render_timestamp(struct logger_tl *tl) {
    const time_t clock = time(NULL);
    struct tm result;
    char *o;
    size_t n;
    if (tl->last_clock == clock)
        return 0;

    gmtime_r(&clock, &result);

    tl->last_clock = clock;
    /* n = strftime(tl->timestamp, tl->max_timestamp, "%Y-%m-%dT%H:%M:%S%z ", &result); */
    n = strftime(tl->timestamp, tl->max_timestamp, "%b %d %H:%M:%S ", &result);
    if (n == 0)
        perror("strftime");
    o = tl->meta;
    tl->meta = tl->timestamp + n;
    tl->max_meta = tl->max_timestamp - n;
    return o != tl->meta;
}

int _render_meta(struct logger *logger, struct logger_tl *tl) {
    int n = strlcpy(tl->meta,  logger->meta, tl->max_meta);
    char *o;
    if (n > tl->max_meta)
        perror("strlcpy");
    o = tl->message;
    tl->message = tl->meta + n;
    tl->max_message = tl->max_meta - n;
    return o != tl->message;
}

int _render_string_field(char *c, int r, char *v) {
    int n;
    if (v == NULL)
        v = "-";
    n = snprintf(c, r, "%s ", v);
    if (n < 0 || n > r)
        perror("snprintf");
    return n;
}

void flb_outsyslog_delete(struct logger *log)
{
	free(log);
}

void flb_outsyslogConfig_delete(struct logger_config *config)
{
	free(config);
}


void flb_alloc_outsyslog_tl(struct logger *logger)
{
	struct logger_tl *tl ;
    tl = malloc(sizeof(struct logger_tl));
    memset(tl, 0, sizeof(struct logger_tl));
    switch (logger->config.framing) {
        case LGR_FRAMING_SYSLOG_NL:
        case LGR_FRAMING_SYSLOG:
        case LGR_FRAMING_NL:
            _skip_size(tl);
            break;
        case LGR_FRAMING_SYSLOG_OC:
            _prerender_size(tl);
            break;
        }

    switch (logger->config.framing) {
        case LGR_FRAMING_SYSLOG_NL:
        case LGR_FRAMING_SYSLOG:
        case LGR_FRAMING_SYSLOG_OC:
            _prerender_pri(tl, logger->pri);
            break;
        case LGR_FRAMING_NL:
            _skip_pri(tl, logger->pri);
            break;
        }

    _render_timestamp(tl);
    _render_meta(logger, tl);

    logger->tl = tl;

    return;
}

struct logger *flb_out_syslog_metadata_create()
{
	struct logger *plogger = malloc(sizeof(struct logger));

	struct logger_config *config = &(plogger->config);
	
	config->facility = LGR_FAC_LOCAL6;
	config->severity = LGR_SEV_ALERT;
	config->protocol = LGR_TCP;
	config->framing  = LGR_FRAMING_SYSLOG_NL;
	config->fields	  = NULL;
	

    plogger->pri = (config->facility << 3) | config->severity;

    if (config->fields != NULL && config->fields[0] != NULL) {
        char *c = plogger->meta;
        char **s;
        int n = 0;
        int r = 64;
        for (s = config->fields; *s != NULL; s++) {
            n = _render_string_field(c, r, *s);
            r -= n;
            c += n;
        }
    }
    else {
        plogger->meta[0]=0;
    }
	return plogger;
	
}

struct flb_out_syslog *flb_syslog_conf_create(struct flb_output_instance *ins,
                                        struct flb_config *config)
{
    int ret;
    int io_flags = 0;
    const char *tmp;
    struct flb_upstream *upstream;
    struct flb_out_syslog *ctx = NULL;

    /* Allocate plugin context */
    ctx = flb_calloc(1, sizeof(struct flb_out_syslog));
    if (!ctx) {
        flb_errno();
        return NULL;
    }

    /* Set default network configuration if not set */
    flb_output_net_default("127.0.0.1", 5140, ins);

    /* Check if SSL/TLS is enabled */
#ifdef FLB_HAVE_TLS
    if (ins->use_tls == FLB_TRUE) {
        io_flags = FLB_IO_TLS;
    }
    else {
        io_flags = FLB_IO_TCP;
    }
#else
    io_flags = FLB_IO_TCP;
#endif

    if (ins->host.ipv6 == FLB_TRUE) {
        io_flags |= FLB_IO_IPV6;
    }

    /* Upstream context */
    upstream = flb_upstream_create(config,
                                   ins->host.name,
                                   ins->host.port,
                                   io_flags, (void *) &ins->tls);
    if (!upstream) {
        flb_error("[out_tcp] could not create upstream context");
        flb_free(ctx);
        return NULL;
    }
    ctx->u = upstream;

    /* Output format */
    ctx->out_format = FLB_PACK_JSON_FORMAT_NONE;
    tmp = flb_output_get_property("format", ins);
    if (tmp) {
        ret = flb_pack_to_json_format_type(tmp);
        if (ret == -1) {
            flb_error("[out_syslog] unrecognized 'format' option '%s'. "
                      "Using 'msgpack'", tmp);
        }
        else {
            ctx->out_format = ret;
        }
    }

    /* Date format for JSON output */
    ctx->json_date_format = FLB_PACK_JSON_DATE_DOUBLE;
    tmp = flb_output_get_property("json_date_format", ins);
    if (tmp) {
        ret = flb_pack_to_json_date_type(tmp);
        if (ret == -1) {
            flb_error("[out_syslog] unrecognized 'json_date_format' option '%s'. "
                      "Using 'double'", tmp);
        }
        else {
            ctx->json_date_format = ret;
        }
    }

    /* Date key for JSON output */
    tmp = flb_output_get_property("json_date_key", ins);
    if (tmp) {
        ctx->json_date_key = flb_sds_create(tmp);
    }
    else {
        ctx->json_date_key = flb_sds_create("date");
    }
    ctx->host = ins->host.name;
    ctx->port = ins->host.port;

	tmp = flb_output_get_property("host", ins);
	if(tmp) {
		ctx->host = flb_strdup(tmp);
	}
	else {
		ctx->host = "127.0.0.1";
	}
	
	tmp = flb_output_get_property("port", ins);
	if(tmp) {
		ctx->port = atoi(flb_strdup(tmp));
	}
	else {
		ctx->port = 5140;
	}

	/* we could extend this part to k8s related things.
 	 * for instance, we may add pod, worker node, master node, 
 	 * and some other k8s specific components here.*/
	
	tmp = flb_output_get_property("process", ins);
	if(tmp) {
		ctx->prcName = flb_strdup(tmp);
	}
	else {
		ctx->prcName = "fluent-bit";
	}

	tmp = flb_output_get_property("pid", ins);
	if(tmp) {
		ctx->pid = flb_strdup(tmp);
	}
	else {
		ctx->pid = "31415";
	}
	
	struct logger *tmpLog = flb_out_syslog_metadata_create();
	flb_alloc_outsyslog_tl(tmpLog);
	ctx->l = tmpLog;
    return ctx;
}

void flb_syslog_conf_destroy(struct flb_out_syslog *ctx)
{
    if (!ctx) {
        return;
    }

	if(ctx->l) {
		if(ctx->l->tl) {
			free(ctx->l->tl);
		}
		flb_outsyslog_delete(ctx->l);
	}

    if (ctx->u) {
        flb_upstream_destroy(ctx->u);
    }

    if (ctx->json_date_key) {
        flb_sds_destroy(ctx->json_date_key);
    }

    flb_free(ctx);
    ctx = NULL;
}

int flb_out_syslog_render_message(struct flb_out_syslog *ctx, char *json)
{
	int ret = -1;
	 /*Add hostname and process first*/
    char hostname[32];
    if(gethostname(hostname, sizeof(hostname)))
    {
        return ret;
    }

    char *processName = ctx->prcName;
	char *pid         = ctx->pid;
    char *outMessage = (char *)malloc(strlen(hostname) + 1 + strlen(processName)  + 1 + strlen(pid) + 3 + strlen(json));
    memset(outMessage, 0, sizeof(*outMessage));
    strcat(outMessage, hostname);
    strcat(outMessage, " ");
    strcat(outMessage, processName);
    strcat(outMessage, "[");
	strcat(outMessage, pid);
    strcat(outMessage, "]: ");
    strcat(outMessage, json);

    int len;
    if (_render_timestamp(ctx->l->tl))
       _render_meta(ctx->l, ctx->l->tl);
    len = _render_message(ctx->l->tl, outMessage);
    ctx->l->tl->msg_start[len] = '\n';
    free(outMessage);
	ctx->rMessage = ctx->l->tl->msg_start;
	ret = len + 1;
	return ret;
}
