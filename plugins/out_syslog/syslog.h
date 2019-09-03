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

#ifndef FLB_OUT_SYSLOG_H
#define FLB_OUT_SYSLOG_H
#define LGR_MAX_MESSAGE 2048
#define MAX_LEN_LEN 8
#define BUFFER_SIZE (LGR_MAX_MESSAGE + MAX_LEN_LEN)


enum logger_framing {
    LGR_FRAMING_NL = 0,
    LGR_FRAMING_SYSLOG = 1,
    LGR_FRAMING_SYSLOG_OC = 2,
    LGR_FRAMING_SYSLOG_NL = 3
};

enum logger_protocol {
    LGR_UDP,
    LGR_TCP,
    LGR_UNIX_DGRAM,
    LGR_UNIX_STREAM,
    LGR_STDOUT,
    LGR_STDERR,
    LGR_FILE
};

enum logger_severity {
    LGR_SEV_EMERG=0,
    LGR_SEV_ALERT=1,
    LGR_SEV_CRIT=2,
    LGR_SEV_ERR=3,
    LGR_SEV_WARNING=4,
    LGR_SEV_NOTICE=5,
    LGR_SEV_INFO=6,
    LGR_SEV_DEBUG=7
};

enum logger_facility {
    LGR_FAC_KERN=0,
    LGR_FAC_USER=1,
    LGR_FAC_MAIL=2,
    LGR_FAC_DAEMON=3,
    LGR_FAC_AUTH=4,
    LGR_FAC_SYSLOG=5,
    LGR_FAC_LPR=6,
    LGR_FAC_NEWS=7,
    LGR_FAC_UUCP=8,
    LGR_FAC_CRON=9,
    LGR_FAC_AUTHPRIV=10,
    LGR_FAC_FTP=11,
    LGR_FAC_LOCAL0=16,
    LGR_FAC_LOCAL1=17,
    LGR_FAC_LOCAL2=18,
    LGR_FAC_LOCAL3=19,
    LGR_FAC_LOCAL4=20,
    LGR_FAC_LOCAL5=21,
    LGR_FAC_LOCAL6=22,
    LGR_FAC_LOCAL7=23
};

struct logger_config {
    enum logger_facility facility;
    enum logger_severity severity;
    enum logger_protocol protocol;
    enum logger_framing framing;
    char *address;
    char *port;
    char **fields;
};

struct logger_tl {
    char buf[BUFFER_SIZE];
    char *msg_start;
    char *timestamp;
    int max_timestamp;
    char *meta;
    int max_meta;
    char *message;
    int max_message;
    time_t last_clock;
};

struct logger {
    int running;
    int pri;
    int fd;
    char meta[64];
    struct logger_config config;
    struct logger_tl *tl;
};


struct flb_out_syslog {
    /* Output format */
    int out_format;

    char *host;
    int port;

    /* Timestamp format */
    int       json_date_format;
    flb_sds_t json_date_key;

    /* Upstream connection to the backend server */
    struct flb_upstream *u;
	
	/*syslog specific parameters*/
	struct logger *l;
	char *prcName;
	char *pid;
	char *rMessage;
};

#endif
