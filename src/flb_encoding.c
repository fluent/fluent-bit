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

#include <stdio.h>

#include <string.h>
#include <time.h>
#include <ctype.h>

#include <fluent-bit/flb_macros.h>
#include <fluent-bit/flb_config.h>
#include <fluent-bit/flb_error.h>
#include <fluent-bit/flb_mem.h>
#include <fluent-bit/flb_str.h>
#include <fluent-bit/flb_encoding.h>


#include <tutf8e.h>

/*
 *
 *  flb_encoding_open(encoding):
 *  iso-8859-1,...
 *  windows-1251 windows-1252, ..
 * 
 *  <charset>                     - fail if bad chars
 *  <charset>//IGNORE             - ignore bad chars
 *  <charset>//REPLACEMENT //R    - use unicode replacement chars for bad chars
 *  <charset>//QUESTION  //Q      - use '?' for bad chars
 *  <charset>///<str>             - use <str> for bad chars
 */


static  unsigned char replacement_utf8[] = { 0xEF, 0xBF, 0xBD , 0 };

struct flb_encoding *flb_encoding_open(const char *encoding) {
    struct flb_encoding *ec;
    TUTF8encoder encoder;
    const char *invalid;
    char *opt;

    if ((opt = strstr(encoding,"//")) != NULL) {
        *opt = 0;
        opt += 2;
        if (*opt == '/') {
            invalid = opt + 1;
        }
        else if (!strcmp(opt,"I") || !strcmp(opt,"IGNORE")) {
            invalid = "";
        }
        else if (!strcmp(opt,"R") || !strcmp(opt,"REPLACEMENT")) {
            invalid = (const char *) replacement_utf8;
        }
        else if (!strcmp(opt,"Q") || !strcmp(opt,"QUESTION")) {
            invalid = "?";
        }
        else {
            flb_error("[flb_encoding] unknown encodig option: %s", opt);
            return NULL;
        }
    }
    else {
        invalid = NULL;
    }
    
    if ((encoder = tutf8e_encoder(encoding)) == NULL) {
        flb_error("[flb_encoding] unknown encoding: %s", encoding);
        return NULL;
    }
    
    ec = flb_calloc(sizeof(struct flb_encoding),1);

    if (!ec) {
        flb_errno();
        return NULL;
    }

    if (invalid) {
        invalid = flb_strdup(invalid);
        if (!invalid) {
            flb_errno();
            flb_free(ec);
            return NULL;
        }
    }
        
    ec->encoder = encoder;
    ec->invalid = invalid;
    return ec;
}


int flb_encoding_decode(struct flb_encoding *ec,
                        char *str, size_t slen,
                        char **result, size_t *result_len) 
{
    size_t outlen = 0;
    char *outbuf;
    int ret;

    *result = NULL;
    *result_len = 0;

    if (slen == 0) {
        *result = flb_strdup("");
        *result_len = 0;
        return FLB_ENCODING_SUCCESS;
    }
    
    ret = tutf8e_encoder_buffer_length(ec->encoder, str, ec->invalid,  slen, &outlen);
    
    if (ret != TUTF8E_OK) {
        return FLB_ENCODING_FAILURE;
    }

    outbuf = flb_malloc(outlen + 1);
    if(outbuf == NULL) {
        flb_error("[flb_encoding] out of memory (%zu)", (int) outlen  + 1);
        return FLB_ENCODING_FAILURE;
    }

    ret = tutf8e_encoder_buffer_encode(ec->encoder, str, slen, ec->invalid, outbuf, &outlen);
    
    if (ret != TUTF8E_OK) {
        flb_free(outbuf);
        return FLB_ENCODING_FAILURE;
    }
    
    outbuf[outlen] = 0;
    *result = outbuf;
    *result_len = outlen;
    
    return FLB_ENCODING_SUCCESS;
}
    
void flb_encoding_close(struct flb_encoding *ec) {
    if (ec) {
        if (ec->invalid) {
            flb_free((char*)ec->invalid);
        }
    }
}

